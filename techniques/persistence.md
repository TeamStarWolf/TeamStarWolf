# Persistence — Technique Detail

> Full detail pages for the **64 ATT&CK techniques** whose primary tactic is [Persistence](https://attack.mitre.org/tactics/TA0003/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1037 — Boot or Logon Initialization Scripts
<a id="t1037"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Windows, Linux, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037)  

Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely. Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. An adversary may also be able to escalate their privileges since some boot or logon initialization scripts run with higher privileges.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (9):** `AC-17`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Boot or Logon Initialization Scripts Detection Strategy  
**Used by 4 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 2 software:** [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217)  

---

### T1037.001 — Logon Script (Windows)
<a id="t1037001"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/001)  

Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key. Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

**ATT&CK mitigations (1):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (2):** `AC-17`, `CM-7`  
**ATT&CK detection strategy:** Detect Logon Script Modifications and Execution  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080)  
**Implemented by 4 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526)  

---

### T1037.002 — Login Hook
<a id="t1037002"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/002)  

Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the <code>/Library/Preferences/com.apple.loginwindow.plist</code> file and can be modified using the <code>defaults</code> command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks. Adversaries can add or insert a path to a malicious script in the <code>com.apple.loginwindow.plist</code> file, using the <code>LoginHook</code> or <code>LogoutHook</code> key-value pair. The malicious script is executed upon the next user login. If a login hook already exists, adversaries can add additional commands to an existing login hook. There can be only one login and logout hook on a system at a time. **Note:** Login hooks were deprecated in 10.11 version of macOS in favor of [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001)

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Login Hook Persistence on macOS  

---

### T1037.003 — Network Logon Script
<a id="t1037003"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/003)  

Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems. Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Network Logon Script Abuse via Multi-Event Correlation on Windows  

---

### T1037.004 — RC Scripts
<a id="t1037004"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Linux, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/004)  

Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify. Adversaries may establish persistence by adding a malicious binary path or shell commands to <code>rc.local</code>, <code>rc.common</code>, and other RC scripts specific to the Unix-like distribution. Upon reboot, the system executes the script's contents as root, resulting in persistence. Adversary abuse of RC scripts is especially effective for lightweight Unix-like distributions using the root user as default, such as ESXi hypervisors, IoT, or embedded systems. As ESXi servers store most system files in memory and therefore discard changes on shutdown, leveraging `/etc/rc.local.d/local.sh` is one of the few mechanisms for enabling persistence across reboots. Several Unix-like systems have moved to Systemd and deprecated the use of RC scripts. This is now a deprecated mechanism in macOS in favor of Launchd. This technique can be used on Mac OS X Panther v10.3 and earlier versions which still execute the RC scripts. To maintain backwards compatibility some systems, such as Ubuntu, will execute the RC scripts if they exist with the correct file permissions.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Boot or Logon Initialization Scripts: RC Scripts  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 4 software:** [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S0690 Green Lambert](https://attack.mitre.org/software/S0690)  

---

### T1037.005 — Startup Items
<a id="t1037005"></a>

sub-technique of [T1037](/techniques/persistence.md#t1037) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1037/005)  

Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism. Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (7):** `AC-3`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Modification of macOS Startup Items  
**Implemented by 1 software:** [S0283 jRAT](https://attack.mitre.org/software/S0283)  

---

### T1098 — Account Manipulation
<a id="t1098"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098)  

Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain. However, account manipulation may also lead to privilege escalation where modifications grant access to additional roles, permissions, or higher-privileged [Valid Accounts](https://attack.mitre.org/techniques/T1078).

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Account Manipulation Behavior Chain Detection  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 2 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0274 Calisto](https://attack.mitre.org/software/S0274)  

---

### T1098.001 — Additional Cloud Credentials
<a id="t1098001"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** IaaS, Identity Provider, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/001)  

Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment. For example, adversaries may add credentials for Service Principals and Applications in addition to existing legitimate credentials in Azure / Entra ID. These credentials include both x509 keys and passwords. With sufficient permissions, there are a variety of ways to add credentials including the Azure Portal, Azure command line interface, and Azure or Az PowerShell modules. In infrastructure-as-a-service (IaaS) environments, after gaining access through [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004), adversaries may generate or import their own SSH keys using either the <code>CreateKeyPair</code> or <code>ImportKeyPair</code> API in AWS or the <code>gcloud compute os-login ssh-keys add</code> command in GCP. This allows persistent access to instances within the cloud environment without further usage of the compromised cloud accounts. Adversaries may also use the <code>CreateAccessKey</code> API in AWS or the <code>gcloud iam service-accounts keys create</code> command in GCP to add access keys to an account. Alternatively, they may use the <code>CreateLoginProfile</code> API in AWS to add a password that can be used to log into the AWS Management Console for [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538). If the target account has different permissions from the requesting account, the adversary may also be able to escalate their privileges in the environment (i.e. [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)). For example, in Entra ID environments, an adversary with the Application Administrator role can add a new set of credentials to their application's service principal. In doing so the adversary would be able to access the service principal’s roles and permissions, which may be different from those of the Application Administrator. In AWS environments, adversaries with the appropriate permissions may also use the `sts:GetFederationToken` API call to create a temporary set of credentials to [Forge Web Credentials](https://attack.mitre.org/techniques/T1606) tied to the permissions of the original user account. These temporary credentials may remain valid for the duration of their lifetime even if the original account’s API credentials are deactivated. In Entra ID environments with the app password feature enabled, adversaries may be able to add an app password to a user account. As app passwords are intended to be used with legacy devices that do not support multi-factor authentication (MFA), adding an app password can allow an adversary to bypass MFA requirements. Additionally, app passwords may remain valid even if the user’s primary password is reset.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Additional Cloud Credentials in IaaS/IdP/SaaS  
**Used by 1 threat groups:** [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1098.002 — Additional Email Delegate Permissions
<a id="t1098002"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/002)  

Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account. For example, the <code>Add-MailboxPermission</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlet, available in on-premises Exchange and in the cloud-based service Office 365, adds permissions to a mailbox. In Google Workspace, delegation can be enabled via the Google Admin console and users can delegate accounts via their Gmail settings. Adversaries may also assign mailbox folder permissions through individual folder permissions or roles. In Office 365 environments, adversaries may assign the Default or Anonymous user permissions or roles to the Top of Information Store (root), Inbox, or other mailbox folders. By assigning one or both user permissions to a folder, the adversary can utilize any other account in the tenant to maintain persistence to the target user’s mail folders. This may be used in persistent threat incidents as well as BEC (Business Email Compromise) incidents where an adversary can add [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) to the accounts they wish to compromise. This may further enable use of additional techniques for gaining access to systems. For example, compromised business accounts are often used to send messages to other accounts in the network of the target business while creating inbox rules (ex: [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)), so the messages evade spam/phishing detection mechanisms.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Addition of Email Delegate Permissions  
**Used by 3 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  

---

### T1098.003 — Additional Cloud Roles
<a id="t1098003"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/003)  

An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments. With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins). This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised. This could lead to privilege escalation, particularly if the roles added allow for lateral movement to additional accounts. For example, in AWS environments, an adversary with appropriate permissions may be able to use the <code>CreatePolicyVersion</code> API to define a new version of an IAM policy or the <code>AttachUserPolicy</code> API to attach an IAM policy with additional or distinct permissions to a compromised user account. In some cases, adversaries may add roles to adversary-controlled accounts outside the victim cloud tenant. This allows these external accounts to perform actions inside the victim tenant without requiring the adversary to [Create Account](https://attack.mitre.org/techniques/T1136) or modify a victim-owned account.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Role Addition to Cloud Accounts  
**Used by 3 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1098.004 — SSH Authorized Keys
<a id="t1098004"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, IaaS, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/004)  

Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions, macOS, and ESXi hypervisors commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code> (or, on ESXi, `/etc/ssh/keys-<username>/authorized_keys`). Users may edit the system’s SSH config file to modify the directives `PubkeyAuthentication` and `RSAAuthentication` to the value `yes` to ensure public key and RSA authentication are enabled, as well as modify the directive `PermitRootLogin` to the value `yes` to enable root authentication via SSH. The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>. Adversaries may modify SSH <code>authorized_keys</code> files directly with scripts or shell commands to add their own adversary-supplied public keys. In cloud environments, adversaries may be able to modify the SSH authorized_keys file of a particular virtual machine via the command line interface or rest API. For example, by using the Google Cloud CLI’s “add-metadata” command an adversary may add SSH keys to a user account. Similarly, in Azure, an adversary may update the authorized_keys file of a virtual machine via a PATCH request to the API. This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH. It may also lead to privilege escalation where the virtual machine or instance has distinct permissions from the requesting user. Where authorized_keys files are modified via cloud APIs or command line interfaces, an adversary may achieve privilege escalation on the target virtual machine if they add a key to a higher-privileged user. SSH keys can also be added to accounts on network devices, such as with the `ip ssh pubkey-chain` [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) command.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SC-12`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for SSH Key Injection in Authorized Keys  
**Used by 3 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 3 software:** [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0658 XCSSET](https://attack.mitre.org/software/S0658)  

---

### T1098.005 — Device Registration
<a id="t1098005"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/005)  

Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance. MFA systems, such as Duo or Okta, allow users to associate devices with their accounts in order to complete MFA requirements. An adversary that compromises a user’s credentials may enroll a new device in order to bypass initial MFA requirements and gain persistent access to a network. In some cases, the MFA self-enrollment process may require only a username and password to enroll the account's first device or to enroll a device to an inactive account. Similarly, an adversary with existing access to a network may register a device or a virtual machine to Entra ID and/or its device management system, Microsoft Intune, in order to access sensitive data or resources while bypassing conditional access policies. Devices registered in Entra ID may be able to conduct [Internal Spearphishing](https://attack.mitre.org/techniques/T1534) campaigns via intra-organizational emails, which are less likely to be treated as suspicious by the email client. Additionally, an adversary may be able to perform a [Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002) on an Entra ID tenant by registering a large number of devices.

**ATT&CK mitigations (1):** [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`  
**ATT&CK detection strategy:** Suspicious Device Registration via Entra ID or MFA Platform  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1098.006 — Additional Container Cluster Roles
<a id="t1098006"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/006)  

An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account. Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions. This account modification may immediately follow [Create Account](https://attack.mitre.org/techniques/T1136) or other malicious account activity. Adversaries may also modify existing [Valid Accounts](https://attack.mitre.org/techniques/T1078) that they have compromised. Note that where container orchestration systems are deployed in cloud environments, as with Google Kubernetes Engine, Amazon Elastic Kubernetes Service, and Azure Kubernetes Service, cloud-based role-based access control (RBAC) assignments or ABAC policies can often be used in place of or in addition to local permission assignments. In these cases, this technique may be used in conjunction with [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `IA-5`  
**ATT&CK detection strategy:** Suspicious RoleBinding or ClusterRoleBinding Assignment in Kubernetes  

---

### T1098.007 — Additional Local or Domain Groups
<a id="t1098007"></a>

sub-technique of [T1098](/techniques/persistence.md#t1098) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1098/007)  

An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain. On Windows, accounts may use the `net localgroup` and `net group` commands to add existing users to local and domain groups. On Linux, adversaries may use the `usermod` command for the same purpose. For example, accounts may be added to the local administrators group on Windows devices to maintain elevated privileges. They may also be added to the Remote Desktop Users group, which allows them to leverage [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) to log into the endpoints in the future. Adversaries may also add accounts to VPN user groups to gain future persistence on the network. On Linux, accounts may be added to the sudoers group, allowing them to persistently leverage [Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) for elevated privileges. In Windows environments, machine accounts may also be added to domain groups. This allows the local SYSTEM account to gain privileges on the domain.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `SI-4`  
**ATT&CK detection strategy:** Suspicious Addition to Local or Domain Groups  
**Used by 7 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023)  
**Implemented by 4 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1133 — External Remote Services
<a id="t1133"></a>

**Tactics:** Persistence, Initial Access · **Platforms:** Containers, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1133)  

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally. Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation. Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard. Adversaries may also establish persistence on network by configuring a Tor hidden service on a compromised system. Adversaries may utilize the tool `ShadowLink` to facilitate the installation and configuration of the Tor hidden service. Tor hidden service is then accessible via the Tor network because `ShadowLink` sets up a.onion address on the compromised system. `ShadowLink` may be used to forward any inbound connections to RDP, allowing the adversaries to have remote access. Adversaries may get `ShadowLink` to persist on a system by masquerading it as an MS Defender application.

**ATT&CK mitigations (5):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (17):** `AC-17`, `AC-20`, `AC-3`, `AC-4`, `AC-6`, `AC-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-chain detection for T1133 External Remote Services across Windows, Linux, macOS, Containers  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 5 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S1060 Mafalda](https://attack.mitre.org/software/S1060)  

---

### T1136 — Create Account
<a id="t1136"></a>

**Tactics:** Persistence · **Platforms:** Windows, IaaS, Linux, macOS, Network Devices, Containers, SaaS, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136)  

Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system. Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services, which can reduce the chance of detection.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1136 - Create Account across platforms  
**Used by 3 threat groups:** [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 1 software:** [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199)  

---

### T1136.001 — Local Account
<a id="t1136001"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows, Network Devices, Containers, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/001)  

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. For example, with a sufficient level of access, the Windows <code>net user /add</code> command can be used to create a local account. In Linux, the `useradd` command can be used, while on macOS systems, the <code>dscl -create</code> command can be used. Local accounts may also be added to network devices, often via common [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as <code>username</code>, to ESXi servers via `esxcli system account add`, or to Kubernetes clusters using the `kubectl` utility. Adversaries may also create new local accounts on network firewall management consoles – for example, by exploiting a vulnerable firewall management system, threat actors may be able to establish super-admin accounts that could be used to modify firewall rules and gain further access to the network. Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** T1136.001 Detection Strategy - Local Account Creation Across Platforms  
**Used by 14 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  
**Implemented by 15 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0039 Net](https://attack.mitre.org/software/S0039), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1136.002 — Domain Account
<a id="t1136002"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/002)  

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command can be used to create a domain account. Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-46`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** T1136.002 Detection Strategy - Domain Account Creation Across Platforms  
**Used by 5 threat groups:** [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 4 software:** [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0039 Net](https://attack.mitre.org/software/S0039), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1136.003 — Cloud Account
<a id="t1136003"></a>

sub-technique of [T1136](/techniques/persistence.md#t1136) · **Tactics:** Persistence · **Platforms:** IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1136/003)  

Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system. In addition to user accounts, cloud accounts may be associated with services. Cloud providers handle the concept of service accounts in different ways. In Azure, service accounts include service principals and managed identities, which can be linked to various resources such as OAuth applications, serverless functions, and virtual machines in order to grant those resources permissions to perform various activities in the environment. In GCP, service accounts can also be linked to specific resources, as well as be impersonated by other accounts for [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005). While AWS has no specific concept of service accounts, resources can be directly granted permission to assume roles. Adversaries may create accounts that only have access to specific cloud services, which can reduce the chance of detection. Once an adversary has created a cloud account, they can then manipulate that account to ensure persistence and allow access to additional resources - for example, by adding [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) or assigning [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003).

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1136.003 - Cloud Account Creation across IaaS, IdP, SaaS, Office  
**Used by 2 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1137 — Office Application Startup
<a id="t1137"></a>

**Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137)  

Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins. A variety of features have been discovered in Outlook that can be abused to obtain persistence, such as Outlook rules, forms, and Home Page. These persistence mechanisms can work within Outlook or be used through Office 365.

**ATT&CK mitigations (4):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (13):** `AC-10`, `AC-17`, `AC-6`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SC-18`, `SC-44`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detect Office Startup-Based Persistence via Macros, Forms, and Registry Hooks  
**Used by 2 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050)  

---

### T1137.001 — Office Template Macros
<a id="t1137001"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/001)  

Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts. Office Visual Basic for Applications (VBA) macros can be inserted into the base template and used to execute code when the respective Office application starts in order to obtain persistence. Examples for both Word and Excel have been discovered and published. By default, Word has a Normal.dotm template created that can be modified to include a malicious macro. Excel does not have a template file created by default, but one can be added that will automatically be loaded. Shared templates may also be stored and pulled from remote locations. Word Normal.dotm location:<br> <code>C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Templates\Normal.dotm</code> Excel Personal.xlsb location:<br> <code>C:\Users\&lt;username&gt;\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB</code> Adversaries may also change the location of the base template to point to their own by hijacking the application's search order, e.g. Word 2016 will first look for Normal.dotm under <code>C:\Program Files (x86)\Microsoft Office\root\Office16\</code>, or by modifying the GlobalDotName registry key. By modifying the GlobalDotName registry key an adversary can specify an arbitrary location, file name, and file extension to use for the template that will be loaded on application startup. To abuse GlobalDotName, adversaries may first need to register the template as a trusted document or place it in a trusted location. An adversary may need to enable macros to execute unrestricted depending on the system or enterprise security policy on use of macros.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (10):** `AC-6`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SC-18`, `SC-44`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Office Template Macro Injection or Registry Hijack  
**Used by 1 threat groups:** [G0069 MuddyWater](https://attack.mitre.org/groups/G0069)  
**Implemented by 2 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0475 BackConfig](https://attack.mitre.org/software/S0475)  

---

### T1137.002 — Office Test
<a id="t1137002"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/002)  

Adversaries may abuse the Microsoft Office "Office Test" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation. There exist user and global Registry keys for the Office Test feature, such as: * <code>HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf</code> Adversaries may add this Registry key and specify a malicious DLL that will be executed whenever an Office application, such as Word or Excel, is started.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-10`, `AC-14`, `AC-17`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `SC-18`, `SC-44`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Office Test Registry DLL Injection  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  

---

### T1137.003 — Outlook Forms
<a id="t1137003"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/003)  

Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form. Once malicious forms have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious forms will execute when an adversary sends a specifically crafted email to the user.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Outlook Custom Forms Triggered by Malicious Email  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.004 — Outlook Home Page
<a id="t1137004"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/004)  

Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page. Once malicious home pages have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious Home Pages will execute when the right Outlook folder is loaded/reloaded.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Outlook Home Page Exploitation  
**Used by 1 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049)  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.005 — Outlook Rules
<a id="t1137005"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/005)  

Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user. Once malicious rules have been added to the user’s mailbox, they will be loaded when Outlook is started. Malicious rules will execute when an adversary sends a specifically crafted email to the user.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-2`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Malicious Outlook Rules  
**Implemented by 1 software:** [S0358 Ruler](https://attack.mitre.org/software/S0358)  

---

### T1137.006 — Add-ins
<a id="t1137006"></a>

sub-technique of [T1137](/techniques/persistence.md#t1137) · **Tactics:** Persistence · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1137/006)  

Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. Add-ins can be used to obtain persistence because they can be set to execute code when an Office application starts.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `CM-2`, `CM-6`, `SC-18`, `SC-44`, `SI-8`  
**ATT&CK detection strategy:** Detect Persistence via Malicious Office Add-ins  
**Used by 1 threat groups:** [G0019 Naikon](https://attack.mitre.org/groups/G0019)  
**Implemented by 3 software:** [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1143 LunarLoader](https://attack.mitre.org/software/S1143)  

---

### T1176 — Software Extensions
<a id="t1176"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176)  

Adversaries may abuse software extensions to establish persistent access to victim systems. Software extensions are modular components that enhance or customize the functionality of software applications, including web browsers, Integrated Development Environments (IDEs), and other platforms. Extensions are typically installed via official marketplaces, app stores, or manually loaded by users, and they often inherit the permissions and access levels of the host application. Malicious extensions can be introduced through various methods, including social engineering, compromised marketplaces, or direct installation by users or by adversaries who have already gained access to a system. Malicious extensions can be named similarly or identically to benign extensions in marketplaces. Security mechanisms in extension marketplaces may be insufficient to detect malicious components, allowing adversaries to bypass automated scanners or exploit trust established during the installation process. Adversaries may also abuse benign extensions to achieve their objectives, such as using legitimate functionality to tunnel data or bypass security controls. The modular nature of extensions and their integration with host applications make them an attractive target for adversaries seeking to exploit trusted software ecosystems. Detection can be challenging due to the inherent trust placed in extensions during installation and their ability to blend into normal application workflows.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (14):** `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `RA-5`, `SC-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malicious or Unauthorized Software Extensions  

---

### T1176.001 — Browser Extensions
<a id="t1176001"></a>

sub-technique of [T1176](/techniques/persistence.md#t1176) · **Tactics:** Persistence · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176/001)  

Adversaries may abuse internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality to and customize aspects of internet browsers. They can be installed directly via a local file or custom URL or through a browser's app store - an official online platform where users can browse, install, and manage extensions for a specific web browser. Extensions generally inherit the web browser's permissions previously granted. Malicious extensions can be installed into a browser through malicious app store downloads masquerading as legitimate extensions, through social engineering, or by an adversary that has already compromised a system. Security can be limited on browser app stores, so it may not be difficult for malicious extensions to defeat automated scanners. Depending on the browser, adversaries may also manipulate an extension's update url to install updates from an adversary-controlled server or manipulate the mobile configuration file to silently install additional extensions. Adversaries may abuse how chromium-based browsers load extensions by modifying or replacing the Preferences and/or Secure Preferences files to silently install malicious extensions. When the browser is not running, adversaries can alter these files, ensuring the extension is loaded, granted desired permissions, and will persist in browser sessions. This method does not require user consent and extensions are silently loaded in the background from disk or from the browser's trusted store. Previous to macOS 11, adversaries could silently install browser extensions via the command line using the <code>profiles</code> tool to install malicious <code>.mobileconfig</code> files. In macOS 11+, the use of the <code>profiles</code> tool can no longer install configuration profiles; however, <code>.mobileconfig</code> files can be planted and installed with user interaction. Once the extension is installed, it can browse to websites in the background, steal all information that a user enters into a browser (including credentials), and be used as an installer for a RAT for persistence. There have also been instances of botnets using a persistent backdoor through malicious Chrome extensions for [Command and Control](https://attack.mitre.org/tactics/TA0011). Adversaries may also use browser extensions to modify browser permissions and components, privacy settings, and other security controls for [Stealth](https://attack.mitre.org/tactics/TA0005).

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detecting Malicious Browser Extensions Across Platforms  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 6 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1176.002 — IDE Extensions
<a id="t1176002"></a>

sub-technique of [T1176](/techniques/persistence.md#t1176) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1176/002)  

Adversaries may abuse an integrated development environment (IDE) extension to establish persistent access to victim systems. IDEs such as Visual Studio Code, IntelliJ IDEA, and Eclipse support extensions - software components that add features like code linting, auto-completion, task automation, or integration with tools like Git and Docker. A malicious extension can be installed through an extension marketplace (i.e., [Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001)) or side-loaded directly into the IDE. In addition to installing malicious extensions, adversaries may also leverage benign ones. For example, adversaries may establish persistent SSH tunnels via the use of the VSCode Remote SSH extension (i.e., [IDE Tunneling](https://attack.mitre.org/techniques/T1219/001)). Trust is typically established through the installation process; once installed, the malicious extension is run every time that the IDE is launched. The extension can then be used to execute arbitrary code, establish a backdoor, mine cryptocurrency, or exfiltrate data.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect malicious IDE extension install/usage and IDE tunneling  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1505 — Server Software Component
<a id="t1505"></a>

**Tactics:** Persistence · **Platforms:** Windows, Linux, macOS, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505)  

Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-16`, `SI-14`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505 - Server Software Component  

---

### T1505.001 — SQL Stored Procedures
<a id="t1505001"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/001)  

Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted). Adversaries may craft malicious stored procedures that can provide a persistence mechanism in SQL database servers. To execute operating system commands through SQL syntax the adversary may have to enable additional functionality, such as xp_cmdshell for MSSQL Server. Microsoft SQL Server can enable common language runtime (CLR) integration. With CLR integration enabled, application developers can write stored procedures using any.NET framework language (e.g. VB.NET, C#, etc.). Adversaries may craft or modify CLR assemblies that are linked to stored procedures since these CLR assemblies can be made to execute arbitrary commands.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (12):** `CM-11`, `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SA-10`, `SA-11`, `SI-14`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for SQL Stored Procedures Abuse via T1505.001  
**Implemented by 1 software:** [S0603 Stuxnet](https://attack.mitre.org/software/S0603)  

---

### T1505.002 — Transport Agent
<a id="t1505002"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Linux, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/002)  

Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails. Transport agents can be written by application developers and then compiled to.NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks. Adversaries may register a malicious transport agent to provide a persistence mechanism in Exchange Server that can be triggered by adversary-specified email events. Though a malicious transport agent may be invoked for all emails passing through the Exchange transport pipeline, the agent can be configured to only carry out specific tasks in response to adversary defined criteria. For example, the transport agent may only carry out an action like copying in-transit attachments and saving them for later exfiltration if the recipient email address matches an entry on a list provided by the adversary.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-16`, `SI-14`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505.002 - Transport Agent Abuse (Windows/Linux)  
**Implemented by 1 software:** [S0395 LightNeuron](https://attack.mitre.org/software/S0395)  

---

### T1505.003 — Web Shell
<a id="t1505003"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/003)  

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (e.g. [China Chopper](https://attack.mitre.org/software/S0020) Web shell client).

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Web Shell Detection via Server Behavior and File Execution Chains  
**Used by 31 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 19 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0073 ASPXSpy](https://attack.mitre.org/software/S0073), [S0185 SEASHARPEE](https://attack.mitre.org/software/S0185), [S0578 SUPERNOVA](https://attack.mitre.org/software/S0578), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S1108 PULSECHECK](https://attack.mitre.org/software/S1108), [S1110 SLIGHTPULSE](https://attack.mitre.org/software/S1110), [S1112 STEADYPULSE](https://attack.mitre.org/software/S1112), [S1113 RAPIDPULSE](https://attack.mitre.org/software/S1113), [S1115 WIREFIRE](https://attack.mitre.org/software/S1115), [S1117 GLASSTOKEN](https://attack.mitre.org/software/S1117), [S1118 BUSHWALK](https://attack.mitre.org/software/S1118), [S1119 LIGHTWIRE](https://attack.mitre.org/software/S1119), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1163 SnappyTCP](https://attack.mitre.org/software/S1163), [S1187 reGeorg](https://attack.mitre.org/software/S1187), [S1188 Line Runner](https://attack.mitre.org/software/S1188), [S1189 Neo-reGeorg](https://attack.mitre.org/software/S1189)  

---

### T1505.004 — IIS Components
<a id="t1505004"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/004)  

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: <code>Get{Extension/Filter}Version</code>, <code>Http{Extension/Filter}Proc</code>, and (optionally) <code>Terminate{Extension/Filter}</code>. IIS modules may also be installed to extend IIS web servers. Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic. ISAPI extensions and filters may have access to all IIS web requests and responses. For example, an adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts. Adversaries may also install malicious IIS modules to observe and/or modify traffic. IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters. IIS modules can be written as a DLL that exports <code>RegisterModule</code>, or as a.NET application that interfaces with ASP.NET APIs to access IIS HTTP requests.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (22):** `AC-17`, `AC-3`, `AC-4`, `AC-6`, `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SA-10`, `SA-11`, `SC-7`, `SI-14`, `SI-16`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for T1505.004 - Malicious IIS Components  
**Implemented by 3 software:** [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0258 RGDoor](https://attack.mitre.org/software/S0258), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1505.005 — Terminal Services DLL
<a id="t1505005"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/005)  

Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP. [Windows Service](https://attack.mitre.org/techniques/T1543/003)s that are run as a "generic" process (ex: <code>svchost.exe</code>) load the service's DLL file, the location of which is stored in a Registry entry named <code>ServiceDll</code>. The <code>termsrv.dll</code> file, typically stored in `%SystemRoot%\System32\`, is the default <code>ServiceDll</code> value for Terminal Services in `HKLM\System\CurrentControlSet\services\TermService\Parameters\`. Adversaries may modify and/or replace the Terminal Services DLL to enable persistent access to victimized hosts. Modifications to this DLL could be done to execute arbitrary payloads (while also potentially preserving normal <code>termsrv.dll</code> functionality) as well as to simply enable abusable features of Terminal Services. For example, an adversary may enable features such as concurrent [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) sessions by either patching the <code>termsrv.dll</code> file or modifying the <code>ServiceDll</code> value to point to a DLL that provides increased RDP functionality. On a non-server Windows OS this increased functionality may also enable an adversary to avoid Terminal Services prompts that warn/log out users of a system when a new RDP session is created.

**ATT&CK mitigations (2):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-12`, `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1505.005 – Terminal Services DLL Modification (Windows)  

---

### T1505.006 — vSphere Installation Bundles
<a id="t1505006"></a>

sub-technique of [T1505](/techniques/persistence.md#t1505) · **Tactics:** Persistence · **Platforms:** ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1505/006)  

Adversaries may abuse vSphere Installation Bundles (VIBs) to establish persistent access to ESXi hypervisors. VIBs are collections of files used for software distribution and virtual system management in VMware environments. Since ESXi uses an in-memory filesystem where changes made to most files are stored in RAM rather than in persistent storage, these modifications are lost after a reboot. However, VIBs can be used to create startup tasks, apply custom firewall rules, or deploy binaries that persist across reboots. Typically, administrators use VIBs for updates and system maintenance. VIBs can be broken down into three components: * VIB payload: a `.vgz` archive containing the directories and files to be created and executed on boot when the VIBs are loaded. * Signature file: verifies the host acceptance level of a VIB, indicating what testing and validation has been done by VMware or its partners before publication of a VIB. By default, ESXi hosts require a minimum acceptance level of PartnerSupported for VIB installation, meaning the VIB is published by a trusted VMware partner. However, privileged users can change the default acceptance level using the `esxcli` command line interface. Additionally, VIBs are able to be installed regardless of acceptance level by using the <code> esxcli software vib install --force</code> command. * XML descriptor file: a configuration file containing associated VIB metadata, such as the name of the VIB and its dependencies. Adversaries may leverage malicious VIB packages to maintain persistent access to ESXi hypervisors, allowing system changes to be executed upon each bootup of ESXi – such as using `esxcli` to enable firewall rules for backdoor traffic, creating listeners on hard coded ports, and executing backdoors. Adversaries may also masquerade their malicious VIB files as PartnerSupported by modifying the XML descriptor file.

**ATT&CK mitigations (3):** [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Abuse of vSphere Installation Bundles (VIBs) for Persistent Access  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S1218 VIRTUALPIE](https://attack.mitre.org/software/S1218)  

---

### T1525 — Implant Internal Image
<a id="t1525"></a>

**Tactics:** Persistence · **Platforms:** IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1525)  

Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike [Upload Malware](https://attack.mitre.org/techniques/T1608/001), this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image. A tool has been developed to facilitate planting backdoors in cloud container images. If an adversary has access to a compromised AWS instance, and permissions to list the available container images, they may implant a backdoor such as a [Web Shell](https://attack.mitre.org/techniques/T1505/003).

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-9`, `RA-5`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1525 – Implant Internal Image  

---

### T1543 — Create or Modify System Process
<a id="t1543"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows, macOS, Linux, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543)  

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters. Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect. Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.

**ATT&CK mitigations (9):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (20):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `RA-5`, `SA-22`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of System Process Creation or Modification Across Platforms  
**Implemented by 6 software:** [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S1121 LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1152 IMAPLoader](https://attack.mitre.org/software/S1152), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1194 Akira _v2](https://attack.mitre.org/software/S1194)  

---

### T1543.001 — Launch Agent
<a id="t1543001"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/001)  

Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>~/Library/LaunchAgents</code>. Property list files use the <code>Label</code>, <code>ProgramArguments </code>, and <code>RunAtLoad</code> keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks. Launch Agents can also be executed using the [Launchctl](https://attack.mitre.org/techniques/T1569/001) command. Adversaries may install a new Launch Agent that executes at login by placing a.plist file into the appropriate folders with the <code>RunAtLoad</code> or <code>KeepAlive</code> keys set to <code>true</code>. The Launch Agent name may be disguised by using a name from the related operating system or benign software. Launch Agents are created with user level privileges and execute with user level permissions.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection of Launch Agent Creation or Modification on macOS  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 20 software:** [S0162 Komplex](https://attack.mitre.org/software/S0162), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0235 CrossRAT](https://attack.mitre.org/software/S0235), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0277 FruitFly](https://attack.mitre.org/software/S0277), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0497 Dacls](https://attack.mitre.org/software/S0497), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1543.002 — Systemd Service
<a id="t1543002"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/002)  

Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other system resources. Systemd is the default initialization (init) system on many Linux distributions replacing legacy init systems, including SysVinit and Upstart, while remaining backwards compatible. Systemd utilizes unit configuration files with the `.service` file extension to encode information about a service's process. By default, system level unit files are stored in the `/systemd/system` directory of the root owned directories (`/`). User level unit files are stored in the `/systemd/user` directories of the user owned directories (`$HOME`). Inside the `.service` unit files, the following directives are used to execute commands: * `ExecStart`, `ExecStartPre`, and `ExecStartPost` directives execute when a service is started manually by `systemctl` or on system start if the service is set to automatically start. * `ExecReload` directive executes when a service restarts. * `ExecStop`, `ExecStopPre`, and `ExecStopPost` directives execute when a service is stopped. Adversaries have created new service files, altered the commands a `.service` file’s directive executes, and modified the user directive a `.service` file executes as, which could result in privilege escalation. Adversaries may also place symbolic links in these directories, enabling systemd to find these payloads regardless of where they reside on the filesystem. The `.service` file’s User directive can be used to run service as a specific user, which could result in privilege escalation based on specific user/group permissions. Systemd services can be created via systemd generators, which support the dynamic generation of unit files. Systemd generators are small executables that run during boot or configuration reloads to dynamically create or modify systemd unit files by converting non-native configurations into services, symlinks, or drop-ins (i.e., [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037)).

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `IA-2`, `SA-22`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Systemd Service Creation or Modification on Linux  
**Used by 3 threat groups:** [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 8 software:** [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1198 Gomir](https://attack.mitre.org/software/S1198), [S1222 RIFLESPINE](https://attack.mitre.org/software/S1222)  

---

### T1543.003 — Windows Service
<a id="t1543003"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/003)  

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry. Adversaries may install a new service or modify an existing service to execute at startup in order to persist on a system. Service configurations can be set or modified using system utilities (such as sc.exe), by directly modifying the Registry, or by interacting directly with the Windows API. Adversaries may also use services to install and execute malicious drivers. For example, after dropping a driver file (ex: `.sys`) to disk, the payload can be loaded and registered via [Native API](https://attack.mitre.org/techniques/T1106) functions such as `CreateServiceW()` (or manually via functions such as `ZwLoadDriver()` and `ZwSetValueKey()`), by creating the required service Registry values (i.e. [Modify Registry](https://attack.mitre.org/techniques/T1112)), or by using command-line utilities such as `PnPUtil.exe`. Adversaries may leverage these drivers as [Rootkit](https://attack.mitre.org/techniques/T1014)s to hide the presence of malicious activity on a system. Adversaries may also load a signed yet vulnerable driver onto a compromised machine (known as "Bring Your Own Vulnerable Driver" (BYOVD)) as part of [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068). Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002). To make detection analysis more challenging, malicious services may also incorporate [Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) (ex: using a service and/or payload name related to a legitimate OS or benign software component). Adversaries may also create ‘hidden’ services (i.e., [Hide Artifacts](https://attack.mitre.org/techniques/T1564)), for example by using the `sc sdset` command to set service permissions via the Service Descriptor Definition Language (SDDL). This may hide a Windows service from the view of standard service enumeration methods such as `Get-Service`, `sc query`, and `services.exe`.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection of Windows Service Creation or Modification  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 108 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0071 hcdLoader](https://attack.mitre.org/software/S0071), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0118 Nidiran](https://attack.mitre.org/software/S0118), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0164 TDTESS](https://attack.mitre.org/software/S0164), [S0169 RawPOS](https://attack.mitre.org/software/S0169), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0181 FALLCHILL](https://attack.mitre.org/software/S0181), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0204 Briba](https://attack.mitre.org/software/S0204), [S0205 Naid](https://attack.mitre.org/software/S0205), [S0206 Wiarp](https://attack.mitre.org/software/S0206), [S0210 Nerex](https://attack.mitre.org/software/S0210), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0261 Catchamas](https://attack.mitre.org/software/S0261), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0345 Seasalt](https://attack.mitre.org/software/S0345), [S0347 AuditCred](https://attack.mitre.org/software/S0347), [S0350 zwShell](https://attack.mitre.org/software/S0350), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0560 TEARDROP](https://attack.mitre.org/software/S0560), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0629 RainyDay](https://attack.mitre.org/software/S0629), [S0630 Nebulae](https://attack.mitre.org/software/S0630), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1031 PingPull](https://attack.mitre.org/software/S1031), [S1033 DCSrv](https://attack.mitre.org/software/S1033), [S1037 STARWHALE](https://attack.mitre.org/software/S1037), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1049 SUGARUSH](https://attack.mitre.org/software/S1049), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1090 NightClub](https://attack.mitre.org/software/S1090), [S1099 Samurai](https://attack.mitre.org/software/S1099), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1158 DUSTPAN](https://attack.mitre.org/software/S1158), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1211 Hannotog](https://attack.mitre.org/software/S1211), [S1226 BOOKWORM](https://attack.mitre.org/software/S1226), [S1232 SplatDropper](https://attack.mitre.org/software/S1232), [S1235 CorKLOG](https://attack.mitre.org/software/S1235), [S1239 TONESHELL](https://attack.mitre.org/software/S1239), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1543.004 — Launch Daemon
<a id="t1543004"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/004)  

Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in <code>/System/Library/LaunchDaemons/</code> and <code>/Library/LaunchDaemons/</code>. Required Launch Daemons parameters include a <code>Label</code> to identify the task, <code>Program</code> to provide a path to the executable, and <code>RunAtLoad</code> to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks. Adversaries may install a Launch Daemon configured to execute at startup by using the <code>RunAtLoad</code> parameter set to <code>true</code> and the <code>Program</code> parameter set to the malicious executable path. The daemon name may be disguised by using a name from a related operating system or benign software (i.e. [Masquerading](https://attack.mitre.org/techniques/T1036)). When the Launch Daemon is executed, the program inherits administrative permissions. Additionally, system configuration changes (such as the installation of third party package managing software) may cause folders such as <code>usr/local/bin</code> to become globally writeable. So, it is possible for poor configurations to allow an adversary to modify executables referenced by current Launch Daemon's plist files.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-2`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Launch Daemon Creation or Modification (macOS)  
**Implemented by 10 software:** [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0497 Dacls](https://attack.mitre.org/software/S0497), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1543.005 — Container Service
<a id="t1543005"></a>

sub-technique of [T1543](/techniques/persistence.md#t1543) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1543/005)  

Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet. By modifying these services, an adversary may be able to achieve persistence or escalate their privileges on a host. For example, by using the `docker run` or `podman run` command with the `restart=always` directive, a container can be configured to persistently restart on the host. A user with access to the (rootful) docker command may also be able to escalate their privileges on the host. In Kubernetes environments, DaemonSets allow an adversary to persistently [Deploy Container](https://attack.mitre.org/techniques/T1610)s on all nodes, including ones added later to the cluster. Pods can also be deployed to specific nodes using the `nodeSelector` or `nodeName` fields in the pod spec. Note that containers can also be configured to run as [Systemd Service](https://attack.mitre.org/techniques/T1543/002)s.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (5):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-2`  
**ATT&CK detection strategy:** Detect persistent or elevated container services via container runtime or cluster manipulation  

---

### T1546.017 — Udev Rules
<a id="t1546017"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/017)  

Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename. Adversaries may abuse the udev subsystem by adding or modifying rules in udev rule files to execute malicious content. For example, an adversary may configure a rule to execute their binary each time the pseudo-device file, such as `/dev/random`, is accessed by an application. Although udev is limited to running short tasks and is restricted by systemd-udevd's sandbox (blocking network and filesystem access), attackers may use scripting commands under the action key `RUN+=` to detach and run the malicious content’s process in the background to bypass these controls.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1546.017 - Udev Rules (Linux)  
**Implemented by 1 software:** [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1546.018 — Python Startup Hooks
<a id="t1546018"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/018)  

Adversaries may achieve persistence by leveraging Python’s startup mechanisms, including path configuration (`.pth`) files and the `sitecustomize.py` or `usercustomize.py` modules. These files are automatically processed during the initialization of the Python interpreter, allowing for the execution of arbitrary code whenever Python is invoked. Path configuration files are designed to extend Python’s module search paths through the use of import statements. If a `.pth` file is placed in Python's `site-packages` or `dist-packages` directories, any lines beginning with `import` will be executed automatically on Python invocation. Similarly, if `sitecustomize.py` or `usercustomize.py` is present in the Python path, these files will be imported during interpreter startup, and any code they contain will be executed. Adversaries may abuse these mechanisms to establish persistence on systems where Python is widely used (e.g., for automation or scripting in production environments).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Linux Python Startup Hook Persistence via .pth and Customize Files (T1546.018)  

---

### T1547 — Boot or Logon Autostart Execution
<a id="t1547"></a>

**Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547)  

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel. Since some boot or logon autostart programs run with higher privileges, an adversary may leverage these to elevate privileges.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Boot or Logon Autostart Execution Detection Strategy  
**Used by 1 threat groups:** [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 5 software:** [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0651 BoxCaon](https://attack.mitre.org/software/S0651), [S0653 xCaon](https://attack.mitre.org/software/S0653)  

---

### T1547.001 — Registry Run Keys / Startup Folder
<a id="t1547001"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/001)  

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level. The following run keys are created by default on Windows systems: * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code> Run keys may exist under multiple hives. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>. The following Registry keys can be used to set startup folder items for persistence: * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code> * <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code> The following Registry keys can control automatic startup of services during boot: * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code> * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code> Using policy settings to specify startup programs creates corresponding values in either of two Registry keys: * <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code> * <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code> Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run automatically for the currently logged-on user. By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot. Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Registry and Startup Folder Persistence (Windows)  
**Used by 55 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 194 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0080 Mivast](https://attack.mitre.org/software/S0080), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0087 Hi-Zor](https://attack.mitre.org/software/S0087), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0124 Pisloader](https://attack.mitre.org/software/S0124), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0131 TINYTYPHON](https://attack.mitre.org/software/S0131), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0152 EvilGrab](https://attack.mitre.org/software/S0152), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0159 SNUGRIDE](https://attack.mitre.org/software/S0159), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0178 Truvasys](https://attack.mitre.org/software/S0178), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0186 DownPaper](https://attack.mitre.org/software/S0186), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0199 TURNEDUP](https://attack.mitre.org/software/S0199), [S0204 Briba](https://attack.mitre.org/software/S0204), [S0207 Vasport](https://attack.mitre.org/software/S0207), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0235 CrossRAT](https://attack.mitre.org/software/S0235), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0247 NavRAT](https://attack.mitre.org/software/S0247), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0254 PLAINTEE](https://attack.mitre.org/software/S0254), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0337 BadPatch](https://attack.mitre.org/software/S0337), [S0338 Cobian RAT](https://attack.mitre.org/software/S0338), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0345 Seasalt](https://attack.mitre.org/software/S0345), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0353 NOKKI](https://attack.mitre.org/software/S0353), [S0355 Final1stspy](https://attack.mitre.org/software/S0355), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0371 POWERTON](https://attack.mitre.org/software/S0371), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0396 EvilBunny](https://attack.mitre.org/software/S0396), [S0397 LoJax](https://attack.mitre.org/software/S0397), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0414 BabyShark](https://attack.mitre.org/software/S0414), [S0417 GRIFFON](https://attack.mitre.org/software/S0417), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0433 Rifdoor](https://attack.mitre.org/software/S0433), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0441 PowerShower](https://attack.mitre.org/software/S0441), [S0442 VBShower](https://attack.mitre.org/software/S0442), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0471 build_downer](https://attack.mitre.org/software/S0471), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0500 MCMD](https://attack.mitre.org/software/S0500), [S0512 FatDuke](https://attack.mitre.org/software/S0512), [S0513 LiteDuke](https://attack.mitre.org/software/S0513), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0546 SharpStage](https://attack.mitre.org/software/S0546), [S0553 MoleNet](https://attack.mitre.org/software/S0553), [S0561 GuLoader](https://attack.mitre.org/software/S0561), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0582 LookBack](https://attack.mitre.org/software/S0582), [S0586 TAINTEDSCRIBE](https://attack.mitre.org/software/S0586), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0630 Nebulae](https://attack.mitre.org/software/S0630), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644), [S0647 Turian](https://attack.mitre.org/software/S0647), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1021 DnsSystem](https://attack.mitre.org/software/S1021), [S1025 Amadey](https://attack.mitre.org/software/S1025), [S1026 Mongall](https://attack.mitre.org/software/S1026), [S1027 Heyoka Backdoor](https://attack.mitre.org/software/S1027), [S1029 AuTo Stealer](https://attack.mitre.org/software/S1029), [S1035 Small Sieve](https://attack.mitre.org/software/S1035), [S1037 STARWHALE](https://attack.mitre.org/software/S1037), [S1041 Chinoxy](https://attack.mitre.org/software/S1041), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1074 ANDROMEDA](https://attack.mitre.org/software/S1074), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1138 Gootloader](https://attack.mitre.org/software/S1138), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1182 MagicRAT](https://attack.mitre.org/software/S1182), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1230 HIUPAN](https://attack.mitre.org/software/S1230), [S1236 CLAIMLOADER](https://attack.mitre.org/software/S1236), [S1239 TONESHELL](https://attack.mitre.org/software/S1239), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1547.002 — Authentication Package
<a id="t1547002"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/002)  

Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\</code> with the key value of <code>"Authentication Packages"=&lt;target binary&gt;</code>. The binary will then be executed by the system when the authentication packages are loaded.

**ATT&CK mitigations (1):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025)  
**NIST 800-53 R5 controls (5):** `CM-6`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect LSA Authentication Package Persistence via Registry and LSASS DLL Load  
**Implemented by 1 software:** [S0143 Flame](https://attack.mitre.org/software/S0143)  

---

### T1547.003 — Time Providers
<a id="t1547003"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/003)  

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\`. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. Adversaries may abuse this architecture to establish persistence, specifically by creating a new arbitrarily named subkey pointing to a malicious DLL in the `DllName` value. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (10):** `AC-17`, `AC-3`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Abuse of Windows Time Providers for Persistence  

---

### T1547.004 — Winlogon Helper DLL
<a id="t1547004"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/004)  

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\Software[\\Wow6432Node\\]\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> and <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\</code> are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: * Winlogon\Notify - points to notification package DLLs that handle Winlogon events * Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on * Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (13):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-7`, `IA-2`, `SI-10`, `SI-14`, `SI-16`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Winlogon Helper DLL Abuse via Registry and Process Artifacts on Windows  
**Used by 3 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 10 software:** [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0200 Dipsind](https://attack.mitre.org/software/S0200), [S0351 Cannon](https://attack.mitre.org/software/S0351), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1547.005 — Security Support Provider
<a id="t1547005"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/005)  

Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.

**ATT&CK mitigations (1):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025)  
**NIST 800-53 R5 controls (5):** `CM-6`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Registry and LSASS Monitoring for Security Support Provider Abuse  
**Implemented by 3 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1547.006 — Kernel Modules and Extensions
<a id="t1547006"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/006)  

Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0). Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors, and enabling root access to non-privileged users. Kernel extensions, also called kext, are used in macOS to load functionality onto a system similar to LKMs for Linux. Since the kernel is responsible for enforcing security and the kernel extensions run as apart of the kernel, kexts are not governed by macOS security policies. Kexts are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands. Kexts need to be signed with a developer ID that is granted privileges by Apple allowing it to sign Kernel extensions. Developers without these privileges may still sign kexts but they will not load unless SIP is disabled. If SIP is enabled, the kext signature is verified before being added to the AuxKC. Since macOS Catalina 10.15, kernel extensions have been deprecated in favor of System Extensions. However, kexts are still allowed as "Legacy System Extensions" since there is no System Extension for Kernel Programming Interfaces. Adversaries can use LKMs and kexts to conduct [Persistence](https://attack.mitre.org/tactics/TA0003) and/or [Privilege Escalation](https://attack.mitre.org/tactics/TA0004) on a system. Examples have been found in the wild, and there are some relevant open source projects as well.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SI-10`, `SI-14`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Kernel Modules and Extensions Autostart Execution  
**Implemented by 3 software:** [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1547.007 — Re-opened Applications
<a id="t1547007"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/007)  

Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to "Reopen windows when logging back in". When selected, all applications currently open are added to a property list file named <code>com.apple.loginwindow.[UUID].plist</code> within the <code>~/Library/Preferences/ByHost</code> directory. Applications listed in this file are automatically reopened upon the user’s next logon. Adversaries can establish [Persistence](https://attack.mitre.org/tactics/TA0003) by adding a malicious application path to the <code>com.apple.loginwindow.[UUID].plist</code> file to execute payloads when a user logs in.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-16`, `AC-3`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect persistence via reopened application plist modification (macOS)  

---

### T1547.008 — LSASS Driver
<a id="t1547008"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/008)  

Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.

**ATT&CK mitigations (3):** [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1044 Restrict Library Loading](../ATTACK_MITIGATIONS_REFERENCE.md#m1044)  
**NIST 800-53 R5 controls (7):** `CM-2`, `CM-6`, `RA-5`, `SC-39`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect unauthorized LSASS driver persistence via LSA plugin abuse (Windows)  
**Implemented by 2 software:** [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0208 Pasam](https://attack.mitre.org/software/S0208)  

---

### T1547.009 — Shortcut Modification
<a id="t1547009"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/009)  

Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries may abuse shortcuts in the startup folder to execute their tools and achieve persistence. Although often used as payloads in an infection chain (e.g. [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001)), adversaries may also create a new shortcut as a means of indirection, while also abusing [Masquerading](https://attack.mitre.org/techniques/T1036) to make the malicious shortcut appear as a legitimate program. Adversaries can also edit the target path or entirely replace an existing shortcut so their malware will be executed instead of the intended legitimate program. Shortcuts can also be abused to establish persistence by implementing other methods. For example, LNK browser extensions may be modified (e.g. [Browser Extensions](https://attack.mitre.org/techniques/T1176/001)) to persistently launch malware.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1547.009 – Shortcut Modification (Windows)  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 25 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652)  

---

### T1547.010 — Port Monitors
<a id="t1547010"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/010)  

Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup. This DLL can be located in <code>C:\Windows\System32</code> and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to the `Driver` value of an existing or new arbitrarily named subkey of <code>HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</code>. The Registry key contains entries for the following: * Local Port * Standard TCP/IP Port * USB Monitor * WSD Port

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1547.010 – Port Monitor DLL Persistence via spoolsv.exe (Windows)  

---

### T1547.012 — Print Processors
<a id="t1547012"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/012)  

Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot. Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup. A print processor can be installed through the <code>AddPrintProcessor</code> API call with an account that has <code>SeLoadDriverPrivilege</code> enabled. Alternatively, a print processor can be registered to the print spooler service by adding the <code>HKLM\SYSTEM\\[CurrentControlSet or ControlSet001]\Control\Print\Environments\\[Windows architecture: e.g., Windows x64]\Print Processors\\[user defined]\Driver</code> Registry key that points to the DLL. For the malicious print processor to be correctly installed, the payload must be located in the dedicated system print-processor directory, that can be found with the <code>GetPrintProcessorDirectory</code> API call, or referenced via a relative path from this directory. After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run. The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (8):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Windows Detection Strategy for T1547.012 - Print Processor DLL Persistence  
**Used by 1 threat groups:** [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006)  
**Implemented by 2 software:** [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0666 Gelsemium](https://attack.mitre.org/software/S0666)  

---

### T1547.013 — XDG Autostart Entries
<a id="t1547013"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/013)  

Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user’s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user’s desktop environment upon user login. These configuration files determine what applications launch upon user login, define associated applications to open specific file types, and define applications used to open removable media. Adversaries may abuse this feature to establish persistence by adding a path to a malicious binary or command to the `Exec` directive in the `.desktop` configuration file. When the user’s desktop environment is loaded at user login, the `.desktop` files located in the XDG Autostart directories are automatically executed. System-wide Autostart entries are located in the `/etc/xdg/autostart` directory while the user entries are located in the `~/.config/autostart` directory. Adversaries may combine this technique with [Masquerading](https://attack.mitre.org/techniques/T1036) to blend malicious Autostart entries with legitimate programs.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Linux Detection Strategy for T1547.013 - XDG Autostart Entries  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 6 software:** [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0235 CrossRAT](https://attack.mitre.org/software/S0235), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1547.014 — Active Setup
<a id="t1547014"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/014)  

Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level. Adversaries may abuse Active Setup by creating a key under <code> HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\</code> and setting a malicious value for <code>StubPath</code>. This value will serve as the program that will be executed when a user logs into the computer. Adversaries can abuse these components to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Active Setup Persistence via StubPath Execution  
**Implemented by 1 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012)  

---

### T1547.015 — Login Items
<a id="t1547015"></a>

sub-technique of [T1547](/techniques/persistence.md#t1547) · **Tactics:** Persistence, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1547/015)  

Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be added via a shared file list or Service Management Framework. Shared file list login items can be set using scripting languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002), whereas the Service Management Framework uses the API call <code>SMLoginItemSetEnabled</code>. Login items installed using the Service Management Framework leverage <code>launchd</code>, are not visible in the System Preferences, and can only be removed by the application that created them. Login items created using a shared file list are visible in System Preferences, can hide the application when it launches, and are executed through LaunchServices, not launchd, to open applications, documents, or URLs without using Finder. Users and applications use login items to configure their user environment to launch commonly used services or applications, such as email, chat, and music applications. Adversaries can utilize [AppleScript](https://attack.mitre.org/techniques/T1059/002) and [Native API](https://attack.mitre.org/techniques/T1106) calls to create a login item to spawn malicious executables. Prior to version 10.5 on macOS, adversaries can add login items by using [AppleScript](https://attack.mitre.org/techniques/T1059/002) to send an Apple events to the “System Events” process, which has an AppleScript dictionary for manipulating login items. Adversaries can use a command such as <code>tell application “System Events” to make login item at end with properties /path/to/executable</code>. This command adds the path of the malicious executable to the login item file list located in <code>~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm</code>. Adversaries can also use login items to launch executables that can be used to control the victim system remotely or as a means to gain privilege escalation by prompting for user credentials.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1547.015 – Login Items on macOS  
**Implemented by 3 software:** [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0690 Green Lambert](https://attack.mitre.org/software/S0690)  

---

### T1554 — Compromise Host Software Binary
<a id="t1554"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1554)  

Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications. Adversaries may establish persistence though modifications to host software binaries. For example, an adversary may replace or otherwise infect a legitimate application binary (or support files) with a backdoor. Since these binaries may be routinely executed by applications or the user, the adversary can leverage this for persistent access to the host. An adversary may also modify a software binary such as an SSH client in order to persistently collect credentials during logins (i.e., [Modify Authentication Process](https://attack.mitre.org/techniques/T1556)). An adversary may also modify an existing binary by patching in malicious functionality (e.g., IAT Hooking/Entry point patching) prior to the binary’s legitimate execution. For example, an adversary may modify the entry point of a binary to point to malicious code patched in by the adversary before resuming normal execution flow. After modifying a binary, an adversary may attempt to impair defenses by preventing it from updating (e.g., via the `yum-versionlock` command or `versionlock.list` file in Linux systems that use the yum package manager).

**ATT&CK mitigations (1):** [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (9):** `CM-2`, `CM-5`, `CM-6`, `IA-9`, `SI-3`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detect Compromise of Host Software Binaries  
**Used by 2 threat groups:** [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 16 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0486 Bonadan](https://attack.mitre.org/software/S0486), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104), [S1115 WIREFIRE](https://attack.mitre.org/software/S1115), [S1116 WARPWIRE](https://attack.mitre.org/software/S1116), [S1118 BUSHWALK](https://attack.mitre.org/software/S1118), [S1119 LIGHTWIRE](https://attack.mitre.org/software/S1119), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1121 LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184)  

---

### T1653 — Power Settings
<a id="t1653"></a>

**Tactics:** Persistence · **Platforms:** Windows, Linux, macOS, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1653)  

Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity. Adversaries may abuse system utilities and configuration settings to maintain access by preventing machines from entering a state, such as standby, that can terminate malicious activity. For example, `powercfg` controls all configurable power system settings on a Windows system and can be abused to prevent an infected host from locking or shutting down. Adversaries may also extend system lock screen timeout settings. Other relevant settings, such as disk and hibernate timeout, can be similarly abused to keep the infected machine running even if no user is active. Aware that some malware cannot survive system reboots, adversaries may entirely delete files used to invoke system shut down or reboot.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (4):** `CM-2`, `CM-3`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Power Settings Abuse  
**Implemented by 2 software:** [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1188 Line Runner](https://attack.mitre.org/software/S1188)  

---

### T1668 — Exclusive Control
<a id="t1668"></a>

**Tactics:** Persistence · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1668)  

Adversaries who successfully compromise a system may attempt to maintain persistence by “closing the door” behind them – in other words, by preventing other threat actors from initially accessing or maintaining a foothold on the same system. For example, adversaries may patch a vulnerable, compromised system to prevent other threat actors from leveraging that vulnerability in the future. They may “close the door” in other ways, such as disabling vulnerable services, stripping privileges from accounts, or removing other malware already on the compromised device. Hindering other threat actors may allow an adversary to maintain sole access to a compromised system or network. This prevents the threat actor from needing to compete with or even being removed themselves by other threat actors. It also reduces the “noise” in the environment, lowering the possibility of being caught and evicted by defenders. Finally, in the case of [Resource Hijacking](https://attack.mitre.org/techniques/T1496), leveraging a compromised device’s full power allows the threat actor to maximize profit.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Exclusive Control  

---

### T1671 — Cloud Application Integration
<a id="t1671"></a>

**Tactics:** Persistence · **Platforms:** Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1671)  

Adversaries may achieve persistence by leveraging OAuth application integrations in a software-as-a-service environment. Adversaries may create a custom application, add a legitimate application into the environment, or even co-opt an existing integration to achieve malicious ends. OAuth is an open standard that allows users to authorize applications to access their information on their behalf. In a SaaS environment such as Microsoft 365 or Google Workspace, users may integrate applications to improve their workflow and achieve tasks. Leveraging application integrations may allow adversaries to persist in an environment – for example, by granting consent to an application from a high-privileged adversary-controlled account in order to maintain access to its data, even in the event of losing access to the account. In some cases, integrations may remain valid even after the original consenting user account is disabled. Application integrations may also allow adversaries to bypass multi-factor authentication requirements through the use of [Application Access Token](https://attack.mitre.org/techniques/T1550/001)s. Finally, they may enable persistent [Automated Exfiltration](https://attack.mitre.org/techniques/T1020) over time. Creating or adding a new application may require the adversary to create a dedicated [Cloud Account](https://attack.mitre.org/techniques/T1136/003) for the application and assign it [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) – for example, in Microsoft 365 environments, an application can only access resources via an associated service principal.

**ATT&CK mitigations (2):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Cloud Application Integration  

---
