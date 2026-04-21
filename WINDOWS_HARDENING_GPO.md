# Windows Hardening and GPO Reference

> Comprehensive guide to Windows Group Policy hardening, attack surface reduction, service management, and enterprise mitigation strategies.

## Table of Contents
1. [GPO Hardening Fundamentals](#1-gpo-hardening-fundamentals)
2. [Disabling Dangerous Services via GPO](#2-disabling-dangerous-services-via-gpo)
3. [Credential Hardening via GPO](#3-credential-hardening-via-gpo)
4. [Network Hardening via GPO](#4-network-hardening-via-gpo)
5. [PowerShell and Script Execution Controls](#5-powershell-and-script-execution-controls)
6. [Audit Policy Configuration](#6-audit-policy-configuration)
7. [Common Attack Techniques Enabled by GPO Misconfigurations](#7-common-attack-techniques-enabled-by-gpo-misconfigurations)
8. [CIS Benchmark Key Controls](#8-cis-benchmark-key-controls-level-1--windows-1011-enterprise)
9. [Mitigation Strategy Reference](#9-mitigation-strategy-reference)

---

## 1. GPO Hardening Fundamentals

### GPO Processing Order (LSDOU)
Local → Site → Domain → OU (last writer wins for conflicts)
- **Computer Configuration:** Applied at boot regardless of who logs in
- **User Configuration:** Applied at logon for the user object
- **Loopback processing:** Force computer policies to apply to user settings (use for kiosk/RDS/VDI environments)
- `gpupdate /force` — Apply GPO changes immediately
- `gpresult /r` — Show resultant set of policy for current user/computer
- `gpresult /h report.html` — Full HTML RSoP report

### GPO Security Filtering
- Default: Applies to Authenticated Users
- Best practice: Use security group filtering — `Remove Authenticated Users`, add specific target group
- WMI filtering: Target by OS version, hardware, domain join status — powerful but slows processing

### GPO Hierarchy for Security
```
Domain Root GPO          (global defaults — baseline)
└── Servers OU
    ├── Domain Controllers GPO   (strictest — no exceptions)
    ├── Web Servers GPO          (IIS-specific hardening)
    └── Database Servers GPO     (SQL-specific hardening)
└── Workstations OU
    ├── Standard Users GPO       (user hardening)
    └── Admin Workstations GPO   (PAW — privileged access)
└── Service Accounts OU          (restricted logon rights)
```

---

## 2. Disabling Dangerous Services via GPO

Navigate to: `Computer Configuration > Windows Settings > Security Settings > System Services`

### Services to Disable (Attack Surface Reduction)

| Service | Service Name | Why Disable | Registry Path |
|---|---|---|---|
| Print Spooler (on non-print servers) | Spooler | PrintNightmare (CVE-2021-1675), SpoolFool; exploited by Lazarus, APT29 | `HKLM\SYSTEM\CurrentControlSet\Services\Spooler` |
| Remote Registry | RemoteRegistry | Enables remote reading/writing of registry; used by attackers for lateral movement | `HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry` |
| Server (SMB Server) on workstations | LanmanServer | Removes SMB attack surface if file sharing not needed; eliminates WannaCry/EternalBlue entry | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer` |
| Netlogon (only on non-domain members) | Netlogon | Zerologon (CVE-2020-1472); critical — only disable if not domain-joined | `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon` |
| WinRM on non-admin workstations | WinRM | Lateral movement via PowerShell Remoting; evil-winrm | `HKLM\SYSTEM\CurrentControlSet\Services\WinRM` |
| Telnet Client | TlntSvr | Cleartext credential transmission; obsolete | `HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr` |
| TFTP Client | TFTP | Used to transfer malicious payloads; LOTL technique | N/A (feature, not service) |
| Simple TCP/IP Services | simptcp | No security value; attack surface (echo, chargen) | `HKLM\SYSTEM\CurrentControlSet\Services\simptcp` |
| Routing and Remote Access | RemoteAccess | Unnecessary on most machines; attack surface | `HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess` |
| Secondary Logon | seclogon | Used by runas; some credential theft techniques exploit it | `HKLM\SYSTEM\CurrentControlSet\Services\seclogon` |
| LLMNR (via GPO, not service) | N/A | LLMNR poisoning (Responder); disable via GPO not services | Group Policy > Computer > Admin Templates > Network > DNS Client |

### Disabling Services via GPO (Step by Step)
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      System Services >
        [Find service] >
          Properties >
            Select "Define this policy setting" >
              Startup: Disabled
```

### Disabling LLMNR and NetBIOS (Critical)

**LLMNR Disable via GPO:**
```
Computer Configuration >
  Administrative Templates >
    Network >
      DNS Client >
        Turn off multicast name resolution = Enabled
```

**NetBIOS Disable (DHCP option or registry):**
```
Computer Configuration >
  Preferences >
    Windows Settings >
      Registry >
        New Registry Item:
          Hive: HKEY_LOCAL_MACHINE
          Key: SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
          Value name: NetbiosOptions
          Value type: REG_DWORD
          Value data: 2 (Disable NetBIOS)
```

---

## 3. Credential Hardening via GPO

### Password Policy
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Account Policies >
        Password Policy
```

| Setting | Recommended Value | Why |
|---|---|---|
| Minimum password length | 14+ characters | NIST 800-63B; brute force resistance |
| Password complexity | Disabled (if using length ≥14) | Complexity rules lead to predictable patterns (Password1!); length matters more |
| Maximum password age | 0 (never expire) or 365 days | NIST 800-63B recommends not forcing changes unless compromise suspected |
| Minimum password age | 1 day | Prevent immediate cycling back to old password |
| Password history | 24 | Prevent reuse |

### Account Lockout Policy
```
Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy
```

| Setting | Recommended Value |
|---|---|
| Account lockout threshold | 10 invalid attempts (NIST recommends ≥10 before lockout) |
| Account lockout duration | 15 minutes (or admin reset only for service accounts) |
| Reset account lockout counter | 15 minutes |

### LSASS Protection

**Credential Guard (virtualization-based)**
```
Computer Configuration >
  Administrative Templates >
    System >
      Device Guard >
        Turn on Virtualization Based Security = Enabled
        Credential Guard Configuration = Enabled with UEFI lock
```
Effect: Isolates LSASS secrets in hypervisor-protected region; Mimikatz cannot extract them

**LSA Protection (PPL — Protected Process Light)**
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Local Policies >
        Security Options >
          Configure LSASS to run as a protected process = Enabled with UEFI lock
```
Registry equivalent:
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL = 1
```

**WDigest Disable (prevent cleartext password storage)**
```
Computer Configuration >
  Preferences >
    Windows Settings >
      Registry:
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
        UseLogonCredential = 0
```
> Note: Default disabled since Windows 8.1/2012 R2; verify explicitly on older or patched systems

### Cached Credentials Limit
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Local Policies >
        Security Options >
          Interactive logon: Number of previous logons to cache = 0 (or 1 for laptops that go offline)
```

### Kerberos Policy
```
Computer Configuration > Windows Settings > Security Settings > Account Policies > Kerberos Policy
```
- Maximum lifetime for service ticket: 600 minutes (default; Golden Ticket detection: flag tickets >10 hours)
- Maximum lifetime for user ticket: 10 hours
- Maximum lifetime for user ticket renewal: 7 days
- Enforce user logon restrictions: Enabled

---

## 4. Network Hardening via GPO

### Windows Firewall via GPO
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Windows Defender Firewall with Advanced Security
```

**Baseline Rules to Create:**
```
Inbound Block Rules (add to Domain, Private, Public profiles):
- Block SMB from internet (445, 139): Source = Any, Destination = Local, Action = Block (for internet-facing)
- Block RDP except from management network: TCP 3389, Source = Management VLAN only
- Block WinRM except from management: TCP 5985, 5986, Source = Management VLAN only

Outbound Block Rules (high-value):
- Block direct outbound SMB (443, 445) except to known servers — C2 uses SMB
- Block Tor port ranges: 9001, 9030, 9050, 9051
```

**Firewall Default Actions:**
```
Domain Profile:  Inbound = Block, Outbound = Allow
Private Profile: Inbound = Block, Outbound = Allow
Public Profile:  Inbound = Block, Outbound = Block (locked-down; explicit allows only)
```

### SMB Hardening

**Disable SMBv1 (critical — WannaCry/EternalBlue uses SMBv1):**
```
Computer Configuration >
  Administrative Templates >
    Network >
      Lanman Workstation >
        Enable insecure guest logons = Disabled

# Also via PowerShell (for immediate effect):
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force
```

**SMB Signing (required — prevents relay attacks):**
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Local Policies >
        Security Options:
          Microsoft network server: Digitally sign communications (always) = Enabled
          Microsoft network client: Digitally sign communications (always) = Enabled
```

### Remote Desktop Hardening
```
Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services
```
- **Require NLA (Network Level Authentication):** Enabled — prevents unauthenticated RDP access, reduces attack surface
- **Set encryption level:** High (128-bit)
- **Limit RDP to specific security layer:** SSL/TLS only (not Classic RDP)
- **Session timeout:** 15 minutes idle disconnect

---

## 5. PowerShell and Script Execution Controls

### PowerShell Constrained Language Mode
Via AppLocker or WDAC (Windows Defender Application Control):
```
# AppLocker approach — prevent PowerShell from loading untrusted scripts
# Forces Constrained Language Mode for non-administrators
```

**PowerShell Execution Policy via GPO (insufficient alone — not a security boundary):**
```
Computer Configuration >
  Administrative Templates >
    Windows Components >
      Windows PowerShell >
        Turn on Script Execution = Enabled
        Execution Policy: RemoteSigned or AllSigned
```
> **Warning:** Execution policy can be bypassed with `-ExecutionPolicy Bypass` flag; use AppLocker/WDAC for real enforcement

### PowerShell Logging (Critical for Detection)

**Module Logging (logs all PowerShell activity):**
```
Computer Configuration >
  Administrative Templates >
    Windows Components >
      Windows PowerShell >
        Turn on Module Logging = Enabled
        Module Names = * (all modules)
```
Event ID **4103** in `Microsoft-Windows-PowerShell/Operational`

**Script Block Logging (logs full script content including decoded blocks — critical for AMSI bypass detection):**
```
Computer Configuration >
  Administrative Templates >
    Windows Components >
      Windows PowerShell >
        Turn on PowerShell Script Block Logging = Enabled
        Log script block invocation start/stop events = Enabled
```
Event ID **4104** in `Microsoft-Windows-PowerShell/Operational`

**PowerShell Transcription:**
```
Computer Configuration >
  Administrative Templates >
    Windows Components >
      Windows PowerShell >
        Turn on PowerShell Transcription = Enabled
        Transcript output directory = \\SIEM-SHARE\PSTranscripts\
        Include invocation headers = Enabled
```

### AppLocker / WDAC

**AppLocker Basic Rules:**
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Application Control Policies >
        AppLocker
```
- Default allow rules: Windows, Program Files (signed executables from standard paths)
- Block rules: `C:\Temp\`, `C:\Users\*\Downloads\`, `C:\Users\*\AppData\`
- Script rules: Block `.ps1`, `.vbs`, `.js` except from Program Files

**WDAC (Windows Defender Application Control) — stronger than AppLocker:**
- Kernel-level enforcement; cannot be bypassed by admin (AppLocker can)
- WDAC Wizard: `https://aka.ms/wdacwizard` — GUI for policy creation
- Policy modes: Audit → Enforce
- Supplement policies for Line of Business apps

---

## 6. Audit Policy Configuration

### Advanced Audit Policy (via GPO)
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Advanced Audit Policy Configuration
```

**Critical Subcategories to Enable:**

| Category | Subcategory | Setting | Key Event IDs |
|---|---|---|---|
| Account Logon | Credential Validation | Success, Failure | 4776 (NTLM auth) |
| Account Logon | Kerberos Authentication Service | Success, Failure | 4768 (TGT request) |
| Account Logon | Kerberos Service Ticket Operations | Success, Failure | 4769 (service ticket) |
| Account Management | User Account Management | Success, Failure | 4720 (create), 4722 (enable), 4725 (disable), 4726 (delete), 4738 (change) |
| Account Management | Security Group Management | Success | 4728, 4732 (add to group) |
| Account Management | Computer Account Management | Success | 4741, 4742 (computer account changes) |
| DS Access | Directory Service Changes | Success | 5136 (AD object modified — DCSync detection) |
| Logon/Logoff | Logon | Success, Failure | 4624, 4625 |
| Logon/Logoff | Logoff | Success | 4634, 4647 |
| Logon/Logoff | Special Logon | Success | 4672 (admin logon — sensitive privilege use) |
| Object Access | File System | Success, Failure | 4663 (file access — enable for sensitive paths only) |
| Object Access | Registry | Success, Failure | 4657 (registry modification) |
| Object Access | Handle Manipulation | Failure | 4658 |
| Policy Change | Audit Policy Change | Success | 4719 (audit policy changed — tamper detection) |
| Privilege Use | Sensitive Privilege Use | Success, Failure | 4673 (SeDebugPrivilege — Mimikatz indicator) |
| Process Creation | Process Creation | Success | 4688 — enable command line logging! |
| System | Security State Change | Success | 4608, 4609 |
| System | Security System Extension | Success | 7045 (new service — persistence) |
| System | System Integrity | Success, Failure | 4612, 4615 |

**Enable Process Command Line in 4688:**
```
Computer Configuration >
  Administrative Templates >
    System >
      Audit Process Creation >
        Include command line in process creation events = Enabled
```

### Log Size and Retention
```
Computer Configuration >
  Windows Settings >
    Security Settings >
      Event Log:
        Security log maximum size = 1,048,576 KB (1 GB)
        Security log retention method = Overwrite events as needed
        Application log maximum size = 102,400 KB
        System log maximum size = 102,400 KB
```

---

## 7. Common Attack Techniques Enabled by GPO Misconfigurations

| Misconfiguration | ATT&CK Technique | Attacker Exploitation Method | GPO Fix |
|---|---|---|---|
| SMBv1 enabled | T1210 | EternalBlue/WannaCry lateral movement | Disable via Computer Config > Admin Templates > Network > Lanman Workstation |
| LLMNR/NBT-NS enabled | T1557.001 | Responder captures NTLMv2 hashes | Turn off multicast name resolution GPO |
| WDigest enabled | T1003.001 | Cleartext passwords in LSASS | Set WDigest `UseLogonCredential = 0` via GPO Preferences |
| Print Spooler running on DCs | T1547/T1068 | SpoolSample/Printerbug for unconstrained delegation abuse | Disable Spooler service on DCs |
| No LSA Protection | T1003.001 | Mimikatz `sekurlsa::logonpasswords` | Enable `RunAsPPL` via GPO |
| No Credential Guard | T1003.001 | Hash/ticket extraction from LSASS | Enable Device Guard/Credential Guard GPO |
| PowerShell v2 available | T1059.001 | PowerShell v2 bypasses AMSI/logging | Disable PowerShell v2: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` |
| No AppLocker/WDAC | T1059 | Run arbitrary scripts from user-writable locations | Deploy AppLocker blocking scripts in user dirs |
| AlwaysInstallElevated = 1 | T1548.002 | Install malicious MSI with SYSTEM privileges | Never enable; GPO: Computer+User both must be 1 — set both to Disabled |
| Unconstrained delegation | T1558 | SpoolSample + TGT capture → impersonate any user | Enable Protected Users group; set delegation to None on sensitive accounts |
| Guest account enabled | T1078.001 | Anonymous access to shares | Disable via Computer > Security Settings > Local Policies > Security Options |
| AutoRun enabled | T1091 | USB autorun malware | Disable via Computer > Admin Templates > Windows Components > AutoPlay Policies |

---

## 8. CIS Benchmark Key Controls (Level 1 — Windows 10/11 Enterprise)

**Section 1 — Account Policies**
- 1.1.1: Enforce password history = 24 passwords
- 1.1.2: Maximum password age = 365 days or less
- 1.1.4: Minimum password length = 14 characters
- 1.2.1: Account lockout duration = 15+ minutes
- 1.2.2: Account lockout threshold = 5–10 invalid attempts

**Section 2 — Local Policies**
- 2.2.1: Access this computer from the network = Administrators, Authenticated Users only
- 2.2.4: Allow log on through Remote Desktop = Administrators only (not generic RDP group)
- 2.2.11: Deny log on locally for service accounts = service accounts should NOT be in this list (they should not have interactive logon)
- 2.3.1.1: Accounts: Administrator account status = Disabled (use named admin account)
- 2.3.7.1: Interactive logon: Don't display last user name = Enabled
- 2.3.11.2: Network security: Allow anonymous SID enumeration = Disabled
- 2.3.15.1: System objects: Strengthen default permissions = Enabled

**Section 18 — Administrative Templates**
- 18.3.5: MSS: Disable NetBIOS = Enabled
- 18.4.3: Enable Font Providers = Disabled (prevents remote font loading C2 technique)
- 18.5.11.3: Network connections: Prohibit use of Internet Connection Sharing = Enabled
- 18.9.31.2: Configure Windows SmartScreen = Enabled: Warn and prevent bypass
- 18.9.47.5.1: Allow Telemetry = 1 (Security only for Enterprise)

---

## 9. Mitigation Strategy Reference

### Microsoft Security Baseline
- Download: `https://www.microsoft.com/en-us/download/details.aspx?id=55319`
- Includes pre-configured GPOs for Windows 10/11, Server 2019/2022, Microsoft 365 Apps
- Import into Group Policy Management: `LGPO.exe /g <path_to_GPO_backup>`

### Defense-in-Depth GPO Layers

**Layer 1 — Prevent Initial Compromise:**
- SmartScreen enabled
- AppLocker blocking untrusted script locations
- Attack Surface Reduction rules in Block mode
- Email filtering (Proofpoint TAP, EOP)

**Layer 2 — Prevent Lateral Movement:**
- SMB signing required
- LLMNR/NetBIOS disabled
- Local admin account disabled or unique per machine (LAPS)
- Tiered AD model (Tier 0/1/2 separation)

**Layer 3 — Prevent Credential Theft:**
- Credential Guard enabled
- LSA Protection (PPL) enabled
- WDigest disabled
- No unconstrained delegation
- Protected Users group for all privileged accounts

**Layer 4 — Contain Blast Radius:**
- Windows Firewall blocking unnecessary inbound/outbound
- No lateral movement from workstation to workstation (deny TCP 445/139 between workstations)
- Service account lockdown (deny interactive logon, restrict to specific computers)
- LAPS: Unique local admin passwords per machine

### LAPS (Local Administrator Password Solution)
```
# Deploy via GPO (legacy LAPS or Windows LAPS built into Windows 11 2022H2+)
Computer Configuration >
  Administrative Templates >
    LAPS >
      Enable local admin password management = Enabled
      Password complexity = Large letters + small letters + numbers + special
      Password length = 15
      Password age = 30 days

# Windows LAPS (built-in, 2022+) via Intune:
# Backup directory: Azure AD or Active Directory
# Password age: 30 days
# Password length: 15+
```

### Protected Users Security Group
- Members cannot use NTLM (Kerberos only)
- DES/RC4 encryption for Kerberos not allowed (AES only)
- Cannot be delegated (unconstrained or constrained)
- TGT lifetime: 4 hours (cannot be renewed)
- **Recommendation:** Add all Tier 0 accounts (Domain Admins, Enterprise Admins, Schema Admins) to Protected Users

### Tiered Administration Model
- **Tier 0:** Domain Controllers, AD Connect, PKI infrastructure — accounts ONLY log into Tier 0 assets
- **Tier 1:** Member servers (apps, file servers, SQL) — accounts ONLY log into Tier 1 or Tier 0 assets via PAW
- **Tier 2:** Workstations and user devices — standard user accounts

GPO enforcement:
```
Tier 0 servers — GPO Deny Logon:
  Deny log on locally: Domain Admins (they use Tier 0 PAW instead, never interactive on servers)

Tier 1 servers — GPO Deny Logon:
  Deny log on locally: Workstation Admins, standard users

Workstations — GPO Deny Logon:
  Deny log on locally: Domain Admins, Server Admins
  Deny log on through Remote Desktop: All admin accounts (admins use PAW or jump box)
```

---

## Related Resources
- [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) — WAF, ASR, CrowdStrike, Tanium, Proofpoint, Zscaler
- [Active Directory Security](disciplines/active-directory.md) — AD attack paths and defense
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — Sigma and SIEM rules for Windows events
- [Malware Families](MALWARE_FAMILIES.md) — malware that GPO hardening prevents
- [Vulnerability Management](disciplines/vulnerability-management.md) — patch and configuration management
