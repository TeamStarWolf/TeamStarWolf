# Windows Hardening Reference

> **Scope:** Windows 10/11 endpoints and Windows Server 2019/2022 — from architecture foundations through monitoring pipelines.
> **Last updated:** 2026-04-26

---

## Table of Contents
1. [Windows Security Architecture](#1-windows-security-architecture)
2. [Account and Authentication Hardening](#2-account-and-authentication-hardening)
3. [Group Policy Hardening](#3-group-policy-hardening)
4. [Sysmon Deployment and Configuration](#4-sysmon-deployment-and-configuration)
5. [Windows Event Forwarding (WEF)](#5-windows-event-forwarding-wef)
6. [PowerShell Security](#6-powershell-security)
7. [Windows Defender and Endpoint Protection](#7-windows-defender-and-endpoint-protection)
8. [Application Control](#8-application-control)
9. [Network Hardening and SMB Security](#9-network-hardening-and-smb-security)
10. [Audit Policy and Monitoring](#10-audit-policy-and-monitoring)

---

## 1. Windows Security Architecture

### 1.1 Core Security Model

Windows implements a mandatory access-control model built on four primitives:

| Primitive | Description |
|-----------|-------------|
| **SID** (Security Identifier) | Unique binary identifier for every security principal (user, group, computer). Format: `S-1-5-21-<domain>-<RID>`. Well-known SIDs: `S-1-5-18` (SYSTEM), `S-1-1-0` (Everyone), `S-1-5-32-544` (Administrators). |
| **ACL** (Access Control List) | Attached to every securable object. A **DACL** lists ACEs granting/denying access; a **SACL** triggers audit events. |
| **Access Token** | Created at logon by LSASS; contains user SID, group SIDs, privileges, integrity level, session ID, and impersonation level. Copied into every process the user spawns. |
| **Privilege** | Named rights independent of object DACLs (e.g., `SeDebugPrivilege`, `SeTcbPrivilege`, `SeImpersonatePrivilege`). Privileges must be **enabled** in the token before use; holding them is not sufficient. |

**Object access flow:**
`Thread requests access` → `SRM compares token SIDs against DACL ACEs` → `Granted/Denied` → `If SACL present, audit event generated`

**Integrity Levels (Mandatory Integrity Control):**
`Untrusted (0)` < `Low (0x1000)` < `Medium (0x2000)` < `High (0x3000)` < `System (0x4000)` < `Protected Process (0x5000)`

UAC elevation transitions a token from Medium to High. Protected Processes (e.g., Antimalware) run at a level that blocks even Administrator access.

### 1.2 Authentication Stores

**SAM (Security Account Manager)**
- Stores local account credentials in `HKLM\SAM` (ACL-protected, inaccessible at runtime without SYSTEM or debug privilege).
- Credential format: NT hash (MD4 of Unicode password). LM hashes disabled by default since Vista.
- Registry hive file: `%SystemRoot%\System32\config\SAM` — always locked by the OS; requires VSS shadow copy or offline access.
- Syskey (Boot Key) encrypts the SAM; stored in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` boot key material across four registry values.

**LSA (Local Security Authority)**
- `lsass.exe` — the authentication broker. Hosts SSP/AP packages: `msv1_0.dll` (NTLM), `kerberos.dll`, `wdigest.dll`, `tspkg.dll`, `livessp.dll`.
- LSA Secrets stored in `HKLM\SECURITY\Policy\Secrets` — service account credentials, domain machine account hash, cached domain credentials (DCC2).
- **Cached Domain Credentials:** Up to 10 by default (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount`). Uses PBKDF2-based DCC2 hash. Set to `0` on non-mobile domain workstations.

**NTDS.dit (Active Directory Database)**
- Located at `%SystemRoot%\NTDS\NTDS.dit` on domain controllers.
- Jet Blue database containing all AD objects including `unicodePwd` attribute (NT hash, encrypted with PEK — Password Encryption Key).
- PEK itself encrypted with the BOOTKEY (same derivation as SAM Syskey).
- Extraction requires: DC replication rights (DCSync), VSS shadow copy, or physical access + offline tools.
- **DCSync attack mitigations:** Remove `Replicating Directory Changes All` from non-DC accounts; alert on Event ID 4662 with GUID `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`.

### 1.3 Security Subsystem Components

```
User mode:
  winlogon.exe  ──►  LogonUI.exe (credential providers)
       │
       ▼
  lsass.exe  (LSA server, token creation, audit dispatch)
    ├── msv1_0.dll    (NTLM authentication package)
    ├── kerberos.dll  (Kerberos v5)
    ├── wdigest.dll   (HTTP Digest — disable with UseLogonCredential=0)
    └── SSP/AP chain (TSSSP, LiveSSP, CloudAP)

Kernel mode:
  nt!SeAccessCheck()   (object access validation)
  nt!SepTokenPrivileges (privilege checks)
  CI.dll / HVCI        (code integrity)
  KPP (Kernel Patch Protection / PatchGuard)
```

**Key hardening:** Protect LSASS as a PPL (Protected Process Light):
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD)`
Requires UEFI Secure Boot to prevent pre-boot bypass.

### 1.4 Windows Security Features Timeline

| Version | Feature | Description |
|---------|---------|-------------|
| Windows XP SP2 | DEP (NX) | Hardware no-execute for stack/heap |
| Vista | UAC + IL | User Account Control + Mandatory Integrity Control |
| Vista | BitLocker | Full-volume encryption, TPM-bound |
| 7 | AppLocker | Application allowlisting via GPO rules |
| 8 | Secure Boot | UEFI firmware validates bootloader chain |
| 8.1 | Measured Boot | TPM logs firmware/boot measurements |
| 10 1507 | Device Guard | Hardware-backed code integrity (precursor to WDAC) |
| 10 1507 | Credential Guard | VBS-isolated LSASS secret storage |
| 10 1511 | VBS | Virtualization-Based Security (hypervisor isolation layer) |
| 10 1607 | WDAC | Windows Defender Application Control (replaces Device Guard policy) |
| 10 1703 | HVCI | Hypervisor-Protected Code Integrity (kernel code integrity in VTL1) |
| 10 1709 | ASR Rules | Attack Surface Reduction rules in Defender |
| 10 1809 | Tamper Protection | Prevents local Defender configuration changes |
| 11 21H2 | Smart App Control | Cloud-based app trust on fresh installs |
| 11 22H2 | Enhanced Phishing Protection | Warns on password reuse in browsers/apps |
| Server 2022 | Secured-core Server | Combines HVCI + Secure Boot + DRTM + SMM protection |

### 1.5 Credential Guard (VBS-Based LSASS Isolation)

Credential Guard moves NTLM hashes and Kerberos TGTs into **VSM (Virtual Secure Mode)**, a separate VTL1 virtual machine managed by the hypervisor. Even a kernel-mode attacker cannot extract these secrets.

**Architecture:**
```
VTL1 (Isolated User Mode — Secure World):
  LsaIso.exe  ──  stores NT hashes, Kerberos keys, DPAPI keys

VTL0 (Normal World — Kernel + User):
  lsass.exe  ──  communicates via RPC to LsaIso.exe
               ──  only receives derived credentials, never raw secrets
```

**Requirements:** UEFI 2.3.1+, Secure Boot, 64-bit CPU with virtualization (VT-x/AMD-V), IOMMU (VT-d/AMD-Vi), TPM 2.0 recommended.

**Enable via GPO:**
`Computer Configuration > Administrative Templates > System > Device Guard`
→ "Turn On Virtualization Based Security": **Enabled**
→ "Credential Guard Configuration": **Enabled with UEFI lock**

**Enable via Registry:**
```registry
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
  EnableVirtualizationBasedSecurity = 1 (DWORD)
  RequirePlatformSecurityFeatures   = 3 (DWORD)  ; Secure Boot + DMA

HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  LsaCfgFlags = 1 (DWORD)  ; 1=enabled, 2=enabled+UEFI lock
```

**Verify:** `msinfo32.exe` → "Virtualization-based security Services Running" shows "Credential Guard".
PowerShell: `(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning`
Returns `2` when Credential Guard active.

**Limitations:** Breaks NTLMv1, RC4 Kerberos, unconstrained delegation, explicit credential storage by some legacy apps. DCs cannot run Credential Guard (they need direct NTDS access).

### 1.6 TPM 2.0 in Windows 11

Windows 11 mandates TPM 2.0 as a baseline requirement. The TPM provides:

| Function | Mechanism |
|----------|-----------|
| **Measured Boot** | PCR banks (0–23) log SHA-256 hashes of each boot component; attestable remotely |
| **BitLocker key sealing** | SRK seals VMK to PCR values; unseals only if measurements match expected values |
| **Credential Guard** | VBS requires TPM for UEFI lock binding |
| **Windows Hello for Business** | Asymmetric key pair generated and stored in TPM; private key never leaves TPM |
| **Device Health Attestation** | MDM servers can verify PCR values via attestation service |
| **Virtual Smart Card** | Software smart card backed by TPM keys |

**Verify TPM status:** `tpm.msc` or `Get-Tpm`
**Check PCR values:** `certutil -v -scinfo` or third-party tools
**TPM reset risk:** Clearing TPM destroys BitLocker VMK — ensure recovery key is backed up.

---

## 2. Account and Authentication Hardening

### 2.1 Local Administrator Password Solution (LAPS v2)

**Legacy LAPS vs. LAPS v2:**
- Legacy (2015): Stores plaintext password in `ms-Mcs-AdmPwd` AD attribute.
- LAPS v2 (Windows LAPS, built into Win 11 22H2 / Server 2022 Oct 2023 CU): Encrypted storage in `msLAPS-EncryptedPassword`, supports Azure AD, passphrase option, history.

**Schema Extension (on-prem AD):**
```powershell
# Extend AD schema for Windows LAPS
Update-LapsADSchema -Verbose

# Grant computer objects permission to update their own password attribute
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"

# Grant helpdesk read access
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\HelpDesk"

# Verify schema
Get-LapsADSchema
```

**GPO Settings (Computer Configuration > Admin Templates > System > LAPS):**

| Setting | Recommended Value |
|---------|------------------|
| Enable password backup directory | Active Directory (or Azure AD) |
| Administrator account name | Custom account name (not built-in) |
| Password Settings – Complexity | Large letters + small letters + numbers + specials |
| Password Settings – Length | 20 |
| Password Settings – Age (days) | 30 |
| Enable password encryption | Enabled |
| Authorized decryptors | LAPS Admins group |
| Post-authentication actions | Reset password + logoff managed account |
| Post-authentication reset delay (hours) | 8 |

**Retrieve password (authorized users):**
```powershell
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText
# Azure AD:
Get-LapsAADPassword -DeviceId "device-guid" -AsPlainText
```

**Event IDs for LAPS monitoring:** 10018 (password updated), 10020 (password read), 10022 (policy applied) — source: `Microsoft-Windows-LAPS`.

### 2.2 Built-in Administrator Account (SID 500)

The built-in Administrator (RID 500) cannot be locked out by account lockout policy — a significant brute-force risk.

```powershell
# Rename the account (GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options)
# "Accounts: Rename administrator account" -> set to unpredictable name

# Disable via PowerShell
Disable-LocalUser -Name "Administrator"

# Verify
Get-LocalUser -Name "Administrator" | Select-Object Name, Enabled, SID

# Enable a separate named local admin (managed by LAPS)
New-LocalUser -Name "CorpAdmin" -NoPassword
Add-LocalGroupMember -Group "Administrators" -Member "CorpAdmin"
```

**GPO path:** `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`
- "Accounts: Administrator account status" → **Disabled**
- "Accounts: Rename administrator account" → `<random-name>`

**Note:** Even when disabled, SID 500 can be enabled via WinPE/offline tools. Complement with BitLocker + Secure Boot + TPM PIN.

### 2.3 Protected Users Security Group

Members of `Protected Users` (added in Windows Server 2012 R2 / Windows 8.1) receive automatic restrictions:

| Restriction | Detail |
|-------------|--------|
| No NTLM authentication | Forces Kerberos; fails gracefully if Kerberos unavailable |
| No RC4 Kerberos | Requires AES 128/256 only |
| No unconstrained delegation | Cannot be granted unconstrained Kerberos delegation |
| No CredSSP credential caching | WDigest/CredSSP will not cache credentials |
| TGT lifetime limited to 4 hours | Non-renewable; user must re-authenticate |
| No password stored in reversible encryption | Automatic enforcement |

```powershell
# Add user to Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "jsmith","svc-admin"

# View current members
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName

# Verify Kerberos-only (look for absence of NTLM in netlogon.log after enabling)
# Check: nltest /query
```

**Caution:** Do NOT add service accounts that need NTLM or accounts used on pre-2012R2 DCs. Test in pilot OU first. Local accounts are unaffected (Protected Users only applies to domain accounts).

### 2.4 Windows Hello for Business (WHfB)

WHfB replaces password-based authentication with asymmetric key pairs tied to the TPM.

**Deployment Models:**

| Model | Description | Requirements |
|-------|-------------|--------------|
| Key-based (Hybrid AAD) | Keys backed by TPM; Azure AD validates | Azure AD + ADFS or PHS/PTA, Intune or GPO |
| Certificate-based | WHfB enrolls a certificate; supports Kerberos | PKI (CA), AD CS, NDES/CES |
| Cloud Kerberos Trust | New hybrid model using AzureAD Kerberos | Azure AD + DCs running 2016+ |

**Key Trust GPO (Hybrid AAD):**
`Computer Configuration > Admin Templates > Windows Components > Windows Hello for Business`
- Use Windows Hello for Business: **Enabled**
- Use certificate for on-premises authentication: **Disabled** (key trust)
- Use a hardware security device: **Enabled** (require TPM)
- Enable PIN Recovery: **Enabled** (if using Microsoft PIN Reset Service)

**Registry verification:**
```registry
HKLM\SOFTWARE\Policies\Microsoft\PassportForWork
  Enabled = 1
  RequireSecurityDevice = 1
```

**Verify enrollment:**
`certutil -scinfo` (certificate trust)
`dsregcmd /status` — look for `AzureAdJoined: YES` and `NgcSet: YES`

### 2.5 NTLM Restrictions

NTLM is a legacy authentication protocol vulnerable to pass-the-hash, relay attacks, and brute-force offline cracking.

**Disable NTLMv1, require NTLMv2:**
`Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`
- "Network security: LAN Manager authentication level" → **Send NTLMv2 response only. Refuse LM & NTLM** (value 5)

Registry:
```registry
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  LmCompatibilityLevel = 5 (DWORD)
```

**NTLM Auditing (before blocking):**
```registry
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
  AuditReceivingNTLMTraffic = 2   ; Audit all NTLM
  AuditNTLMInDomain           = 7   ; Audit all domain NTLM
  RestrictReceivingNTLMTraffic = 0  ; Audit only initially
```

Event IDs generated: **8001** (NTLM authentication to remote server), **8002** (NTLM pass-through), **8003** (NTLM blocked) — source: `Microsoft-Windows-NTLM`.

**Restrict NTLM to specific servers (phased approach):**
```registry
; Phase 1: Audit incoming NTLM
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
  AuditNTLMInDomain = 7

; Phase 2: Allow list exceptions
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
  ClientAllowedNTLMServers = (REG_MULTI_SZ list of allowed servers)

; Phase 3: Block all incoming NTLM
  RestrictReceivingNTLMTraffic = 2
  RestrictSendingNTLMTraffic   = 2
```

---

## 3. Group Policy Hardening

### 3.1 CIS Benchmark v3.0 — Windows Server 2022 Key Settings

Critical registry-backed settings with full paths:

**Account Policies:**
```
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
  MaximumPasswordAge         = 60  (days)
  MinimumPasswordLength      = 14

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  CachedLogonsCount          = 0  (non-mobile domain members)
```

**Interactive Logon:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  DontDisplayLastUserName    = 1
  InactivityTimeoutSecs      = 900
  LegalNoticeCaption         = "Authorized Use Only"
  LegalNoticeText            = "<org warning banner>"
  ScForceOption              = 0  ; don't force smart card (unless required)
```

**Network Access:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  LmCompatibilityLevel       = 5
  RestrictAnonymous          = 1
  RestrictAnonymousSAM       = 1
  EveryoneIncludesAnonymous  = 0
  NoLMHash                   = 1
  RunAsPPL                   = 1

HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg
  (restrict remote registry access via ACL on this key)
```

**SMB / Network:**
```
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
  RequireSecuritySignature   = 1  ; SMB server signing required
  EnableSecuritySignature    = 1
  SMB1                       = 0  ; SMBv1 disabled

HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
  RequireSecuritySignature   = 1  ; SMB client signing required
  EnableSecuritySignature    = 1
```

**Audit Settings:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  AuditBaseObjects           = 1
  FullPrivilegeAuditing      = 1 (BINARY: 01)
  CrashOnAuditFail           = 0  ; keep 0 — CrashOnAuditFail=1 is DoS risk
```

**Remote Desktop:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
  fAllowToGetHelp            = 0   ; disable Remote Assistance
  fEncryptionLevel           = 3   ; High encryption
  SecurityLayer              = 2   ; TLS required
  UserAuthentication         = 1   ; NLA required
  fDenyTSConnections         = 1   ; disable RDP if not needed
  MinEncryptionLevel         = 3
```

**Windows Defender Firewall:**
```
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile
  EnableFirewall             = 1
  DefaultInboundAction       = 1   ; block
  DefaultOutboundAction      = 0   ; allow

HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile
  EnableFirewall             = 1
  DefaultInboundAction       = 1

HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile
  EnableFirewall             = 1
  DefaultInboundAction       = 1
  DefaultOutboundAction      = 1   ; block outbound on public
```

### 3.2 Microsoft Security Baseline Settings

Download via: Microsoft Security Compliance Toolkit (SCT) — `https://www.microsoft.com/en-us/download/details.aspx?id=55319`

Key baselines available: Windows 11, Windows Server 2022, Microsoft 365 Apps, Edge.

**Import baseline GPO:**
```powershell
# Extract SCT, then:
.\LGPO.exe /g ".\GPOs\{GUID-of-baseline}"  # apply locally
# Or import into GPMC via Backup/Restore
```

**Notable Microsoft Security Baseline additions over CIS:**
- Disables Xbox Game Bar, GameDVR
- Enables "Virtualization Based Security" with UEFI lock
- Configures WDAC audit mode baseline
- Sets PowerShell ScriptBlock logging
- Configures Windows Update for automatic install
- Disables AutoPlay/AutoRun fully
- Enables "Early Launch Antimalware" driver enforcement

### 3.3 STIG Controls Reference Table

| STIG ID | Title | Setting |
|---------|-------|---------|
| V-253264 | Account lockout threshold | ≤ 3 invalid attempts |
| V-253265 | Account lockout duration | ≥ 15 minutes |
| V-253266 | Reset lockout counter | 15 minutes |
| V-253282 | LAN Manager auth level | 5 (NTLMv2 only) |
| V-253285 | Unsigned driver installation | Warn or Block |
| V-253290 | Windows Firewall Domain | On |
| V-253291 | Windows Firewall Private | On |
| V-253292 | Windows Firewall Public | On |
| V-253296 | Audit account logon | Success, Failure |
| V-253297 | Audit logon events | Success, Failure |
| V-253317 | Smart card removal behavior | Lock workstation |
| V-253344 | WDigest authentication | Disabled |
| V-253350 | LSASS PPL | Enabled |
| V-253360 | SMBv1 | Disabled |

### 3.4 Account Lockout Policy (GPO)

```
Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy

Account lockout threshold:  5 invalid attempts
Account lockout duration:   15 minutes
Reset account lockout counter after: 15 minutes
```

Registry (applied by GPO engine to SAM):
```
HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
  MaximumPasswordAge = 42  ; force GPO application

; Actual lockout stored in SAM, visible via:
net accounts
```

**Fine-Grained Password Policies (PSO) for privileged accounts:**
```powershell
New-ADFineGrainedPasswordPolicy -Name "PrivilegedAccounts-PSO" `
    -Precedence 10 `
    -LockoutObservationWindow "0.00:15:00" `
    -LockoutDuration "0.00:30:00" `
    -LockoutThreshold 3 `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false

Add-ADFineGrainedPasswordPolicySubject -Identity "PrivilegedAccounts-PSO" `
    -Subjects "Domain Admins","Tier0-Accounts"
```

### 3.5 Audit Policy via auditpol.exe

```cmd
REM Enable comprehensive audit policy via auditpol
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /failure:enable
auditpol /set /subcategory:"SAM" /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable

REM Verify settings
auditpol /get /category:*
```

### 3.6 WinRM over HTTPS Only

```powershell
# Create self-signed cert (use CA cert in production)
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME `
    -CertStoreLocation "cert:\LocalMachine\My"

# Create HTTPS listener
winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
    "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"

# Delete HTTP listener
winrm delete winrm/config/Listener?Address=*+Transport=HTTP

# Set authentication to Kerberos only (no Basic/Digest)
winrm set winrm/config/service/auth '@{Basic="false";Kerberos="true";Negotiate="true";Certificate="false";CredSSP="false"}'

# Enable firewall rule for 5986 (HTTPS), block 5985 (HTTP)
New-NetFirewallRule -Name "WinRM-HTTPS" -DisplayName "WinRM HTTPS" `
    -Protocol TCP -LocalPort 5986 -Action Allow -Profile Domain

# GPO: Computer Config > Admin Templates > Windows Components > Windows Remote Management
# Allow remote server management through WinRM -> Enabled (IPv4/IPv6 filter to management IPs only)
```

---

## 4. Sysmon Deployment and Configuration

### 4.1 Sysmon Architecture

Sysmon (System Monitor) is a Windows system service and kernel driver that logs detailed process and network activity to the Windows Event Log.

**Components:**
- `Sysmon64.exe` — userspace service
- `SysmonDrv.sys` — kernel filter driver (operates at PASSIVE_LEVEL, IRQL 0)
- Events written to: `Microsoft-Windows-Sysmon/Operational` (Channel)
- Default log path: `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

**Driver behavior:** The kernel driver hooks via ETW (Event Tracing for Windows) and kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, object callbacks). It cannot be bypassed by userspace code alone when properly protected.

**Protect Sysmon driver from tampering:**
```powershell
# Protect the service via ACL
sc sdset sysmon D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)
# Or use WDAC to prevent driver removal
```

### 4.2 Complete Sysmon Event ID Reference

| Event ID | Name | Description |
|----------|------|-------------|
| 1 | ProcessCreate | Process creation with full command line, hashes, parent |
| 2 | FileCreationTimeChanged | File creation time modification (timestomping) |
| 3 | NetworkConnect | TCP/UDP network connections (outbound) |
| 4 | SysmonServiceStateChanged | Sysmon service state changes |
| 5 | ProcessTerminated | Process exits |
| 6 | DriverLoaded | Kernel driver loaded with signature info |
| 7 | ImageLoaded | DLL/module loaded into process |
| 8 | CreateRemoteThread | Thread created in another process (injection indicator) |
| 9 | RawAccessRead | Raw disk read bypassing file system |
| 10 | ProcessAccess | Process opened with access rights (credential dumping) |
| 11 | FileCreate | File creation or overwrite |
| 12 | RegistryEvent (Object create/delete) | Registry key/value created or deleted |
| 13 | RegistryEvent (Value Set) | Registry value modifications |
| 14 | RegistryEvent (Key/Value Rename) | Registry rename operations |
| 15 | FileCreateStreamHash | Alternate data stream creation |
| 16 | SysmonConfigStateChanged | Sysmon configuration changes |
| 17 | PipeEvent (Pipe Created) | Named pipe creation |
| 18 | PipeEvent (Pipe Connected) | Named pipe connection |
| 19 | WmiEvent (WmiEventFilter) | WMI filter activity |
| 20 | WmiEvent (WmiEventConsumer) | WMI consumer activity |
| 21 | WmiEvent (WmiEventConsumerToFilter) | WMI binding |
| 22 | DNSEvent | DNS query and response |
| 23 | FileDelete (Archived) | File deleted and saved to archive |
| 24 | ClipboardChange | Clipboard content change |
| 25 | ProcessTampering | Process image tampering (hollowing/herpaderping) |
| 26 | FileDeleteDetected | File deletion detected (no archive) |
| 27 | FileBlockExecutable | Executable file creation blocked |
| 28 | FileBlockShredding | File shredding blocked |
| 29 | FileExecutableDetected | Executable file created/modified |

### 4.3 SwiftOnSecurity Config Deployment

```powershell
# Download SwiftOnSecurity sysmon-config
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest -Uri $configUrl -OutFile "C:\Tools\sysmonconfig.xml"

# Install Sysmon with config
.\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml

# Verify installation
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# Update config without restart
.\Sysmon64.exe -c C:\Tools\sysmonconfig.xml

# Check current config
.\Sysmon64.exe -s
```

### 4.4 olafhartong/sysmon-modular

sysmon-modular provides individual XML modules per technique that can be merged into a single config.

```powershell
# Clone repository
git clone https://github.com/olafhartong/sysmon-modular.git
cd sysmon-modular

# Install PowerShell module dependency
Install-Module -Name PSYaml -Force

# Merge all modules into single config
.\Merge-SysmonXml.ps1 -AsString | Out-File sysmonconfig.xml

# Selective merge — only include specific event types
.\Merge-SysmonXml.ps1 -IncludeList @(
    ".\1_process_creation\",
    ".\3_network_connection_initiated\",
    ".\7_image_load\",
    ".\8_create_remote_thread\",
    ".\10_process_access\",
    ".\11_file_create\",
    ".\12_14_registry_event\",
    ".\22_dns_query\"
) | Out-File sysmonconfig-custom.xml

# Deploy merged config
.\Sysmon64.exe -c sysmonconfig-custom.xml
```

**Module directory structure:**
```
sysmon-modular/
├── 1_process_creation/       # EID 1 filters
├── 3_network_connection_*/   # EID 3 filters
├── 7_image_load/             # EID 7 — high volume, selective
├── 8_create_remote_thread/   # EID 8 — injection detection
├── 10_process_access/        # EID 10 — LSASS access detection
├── 11_file_create/           # EID 11 — file monitoring
├── 12_14_registry_event/     # EID 12-14 — registry monitoring
└── merge.ps1                 # merge script
```

### 4.5 Key Detection-Focused Event IDs

**EID 10 — ProcessAccess (LSASS Credential Dumping):**
```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```
Alert when: `GrantedAccess` contains `0x1010`, `0x1038`, `0x1fffff` targeting lsass.exe.

**EID 8 — CreateRemoteThread (Process Injection):**
```xml
<CreateRemoteThread onmatch="exclude">
  <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
</CreateRemoteThread>
```

**EID 3 — NetworkConnect (C2 Beaconing):**
Alert on: `svchost.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe` initiating outbound connections on non-standard ports.

**EID 25 — ProcessTampering:**
Detects process hollowing, process herpaderping, process doppelganging. No filter needed — all are suspicious.

**EID 15 — FileCreateStreamHash (ADS):**
Alerts on creation of Alternate Data Streams — common malware persistence technique.

### 4.6 Updating Sysmon Config Without Service Restart

```powershell
# Update config — does not drop events or restart service
& "C:\Tools\Sysmon64.exe" -c "C:\Tools\sysmonconfig-new.xml"

# Automate via scheduled task
$action = New-ScheduledTaskAction -Execute "C:\Tools\Sysmon64.exe" `
    -Argument "-c C:\Tools\sysmonconfig.xml"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "SysmonConfigRefresh" `
    -Action $action -Trigger $trigger -RunLevel Highest

# Enterprise deployment via GPO startup script or SCCM/Intune
# Use Sysmon MSI wrapper: https://github.com/nsacyber/Event-Forwarding-Guidance
```

---

## 5. Windows Event Forwarding (WEF)

### 5.1 WEF Architecture

WEF enables centralized collection of Windows Event Logs from source computers to one or more collector servers without third-party agents.

```
Source Computers (1..N)
    └── WinRM Service (source)
            │  WS-Management protocol
            ▼
    Collector Server
        └── Windows Event Collector (wecsvc)
                │
                ▼
        Forwarded Events Log
        (%SystemRoot%\System32\winevt\Logs\ForwardedEvents.evtx)
                │
                ▼
        SIEM / Log Aggregator (Splunk, Elastic, Sentinel)
```

**Transport:** WS-Management over HTTP (5985) or HTTPS (5986).
**Authentication:** Kerberos (domain) or Certificate (workgroup).
**Scalability:** Single collector can handle ~100,000 source endpoints (Microsoft guidance); use multiple collectors with load distribution for larger environments.

### 5.2 Collector Configuration

```powershell
# On collector server — configure and start WEC service
winrm quickconfig -force
wecutil qc -quiet

# Verify collector is running
Get-Service wecsvc
wecutil es  # enumerate subscriptions

# Set ForwardedEvents log size
wevtutil sl ForwardedEvents /ms:4294967296  # 4GB max size
wevtutil sl ForwardedEvents /rt:true         # retain old events
```

### 5.3 GPO Configuration for WEF

**On source computers (via GPO):**

```
Computer Configuration > Administrative Templates > Windows Components > Event Forwarding
  "Configure the server address, refresh interval, and issuer CA..."
  → Enabled
  → Server URL: http://collector.corp.local:5985/wsman/SubscriptionManager/WEC
  → Refresh interval: 60 seconds

Computer Configuration > Administrative Templates > Windows Components > Windows Remote Management > WinRM Service
  "Allow remote server management through WinRM" → Enabled (filter to collector IPs)
  "Allow Basic authentication" → Disabled
  "Allow unencrypted traffic" → Disabled

Computer Configuration > Windows Settings > Security Settings > System Services
  "Windows Remote Management (WS-Management)" → Automatic
```

### 5.4 Subscription XML (Palantir WEF)

The palantir/windows-event-forwarding project provides ready-made subscription XMLs organized by channel.

```powershell
# Clone subscription XMLs
git clone https://github.com/palantir/windows-event-forwarding.git

# Create subscription from XML
wecutil cs ".\subscriptions\Microsoft-Windows-Sysmon-Operational.xml"
wecutil cs ".\subscriptions\Security.xml"
wecutil cs ".\subscriptions\PowerShell.xml"

# List all subscriptions
wecutil es

# Check subscription status and runtime
wecutil gr "Microsoft-Windows-Sysmon-Operational"
```

**Recommended subscription channels:**

| Channel | Events | Priority |
|---------|--------|----------|
| Security | 4624,4625,4648,4672,4688,4697,4698,4720-4726,4776 | Critical |
| System | 7045,7034,7036 (service installs/crashes) | High |
| Microsoft-Windows-Sysmon/Operational | All Sysmon EIDs | Critical |
| Microsoft-Windows-PowerShell/Operational | 4103,4104 (script block) | High |
| Windows PowerShell | 400,403,600,800 | Medium |
| Microsoft-Windows-WMI-Activity/Operational | 5857-5861 (WMI activity) | High |
| Microsoft-Windows-TaskScheduler/Operational | 106,140,141,200,201 | Medium |
| Microsoft-Windows-AppLocker/EXE and DLL | 8003,8004 | High |
| Microsoft-Windows-DNS-Client/Operational | All | Medium |
| Microsoft-Windows-Bits-Client/Operational | 3,59,60 | Medium |

### 5.5 Source-Initiated vs. Collector-Initiated Subscriptions

| Type | Direction | Use Case | Scalability |
|------|-----------|----------|-------------|
| **Source-Initiated** | Source pushes to collector | Workgroup, large deployments, DMZ | Very High — sources self-register |
| **Collector-Initiated** | Collector pulls from sources | Small environments, easier debugging | Lower — collector maintains connection list |

**Source-initiated requires:** GPO to configure subscription manager URL; collector must have `Network Service` in local Administrators on each source (or use certificate auth).

**Collector-initiated requires:** Each source listed in subscription XML; WinRM must accept connections from collector computer account.

### 5.6 Network Ports and Firewall Rules

```powershell
# Allow WinRM from collector to sources (source-initiated: sources connect OUT)
New-NetFirewallRule -Name "WEF-WinRM-Out" -DisplayName "WEF WinRM Outbound" `
    -Direction Outbound -Protocol TCP -RemotePort 5985 `
    -RemoteAddress "10.0.0.50"  # collector IP
    -Action Allow -Profile Domain

# On collector — allow inbound from all sources
New-NetFirewallRule -Name "WEF-WinRM-In" -DisplayName "WEF WinRM Inbound" `
    -Direction Inbound -Protocol TCP -LocalPort 5985 `
    -Action Allow -Profile Domain
# Scope to source subnet for security
```

---

## 6. PowerShell Security

### 6.1 Constrained Language Mode (CLM)

CLM restricts PowerShell to a safe subset — prevents access to .NET types, COM objects, and arbitrary code execution patterns used by attackers.

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode
# Returns: FullLanguage, ConstrainedLanguage, RestrictedLanguage, NoLanguage

# CLM is enforced by:
# 1. WDAC policy (most reliable — enforced by kernel)
# 2. AppLocker (user-mode only — bypassable by kernel exploits)
# 3. JEA endpoint (session-level restriction)

# Test if CLM is effective
[System.Environment]::OSVersion  # Blocked in CLM
Add-Type -TypeDefinition "public class T{}"  # Blocked in CLM
```

**CLM bypass mitigations:**
- Use WDAC (not AppLocker) for CLM enforcement — AppLocker CLM can be bypassed via `powershell_ise.exe`, `powershell -version 2`, or loading alternate runspaces.
- Disable PowerShell v2: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`

### 6.2 PowerShell Logging (ScriptBlock, Module, Transcription)

**ScriptBlock Logging** (captures all executed script content including deobfuscated code):
```registry
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging         = 1
  EnableScriptBlockInvocationLogging = 1  ; also log script start/stop (verbose)
```

Events: **4104** (script block contents), **4105** (script block start), **4106** (script block stop)
Log: `Microsoft-Windows-PowerShell/Operational`

**Query ScriptBlock logs:**
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 } |
    Select-Object TimeCreated, @{N='Script';E={$_.Properties[2].Value}} |
    Where-Object { $_.Script -match "Invoke-Mimikatz|AMSI|bypass|EncodedCommand" }
```

**Module Logging** (logs pipeline execution of module members):
```registry
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
  EnableModuleLogging = 1

HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
  * = *  ; log all modules
```

Events: **4103** (module member invocation)

**Transcription Logging** (full session transcript to text file):
```registry
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
  EnableTranscripting       = 1
  EnableInvocationHeader    = 1
  OutputDirectory           = \\logserver\PStranscripts$\%COMPUTERNAME%
```

**Important:** Transcripts are plaintext files — secure the output directory with restricted ACLs.

### 6.3 AMSI (Antimalware Scan Interface)

AMSI hooks into PowerShell, VBScript, JScript, Office macros, and other script engines to submit content to registered antimalware before execution.

**AMSI scan flow:**
```
Script content → AmsiScanBuffer() API → Registered AV engine → Scan result
                                                                    │
                                                            AMSI_RESULT_CLEAN (0)
                                                            AMSI_RESULT_DETECTED (32768)
```

**AMSI providers query:**
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
# Shows registered AMSI providers (Windows Defender = {2781761E-28E0-4109-99FE-B9D127C57AFE})
```

**Detecting AMSI bypass attempts:** Look for EID 4104 containing: `AmsiUtils`, `amsiInitFailed`, `[Ref].Assembly.GetType`, `amsi.dll`, `AmsiScanBuffer`.

**AMSI in PowerShell 7:** Available when running on Windows with a registered AMSI provider. Ensure PS7 is covered by endpoint protection.

### 6.4 Just Enough Administration (JEA)

JEA creates constrained remote PowerShell endpoints that limit what users can do based on their role.

```powershell
# 1. Create Role Capability file (what commands a role can run)
New-PSRoleCapabilityFile -Path "C:\JEA\RoleCapabilities\HelpDesk.psrc"

# Edit the .psrc file:
# VisibleCmdlets = 'Restart-Service', 'Get-Service', 'Get-EventLog'
# VisibleExternalCommands = 'C:\Tools\approved-tool.exe'
# VisibleFunctions = 'Get-ComputerInfo'
# RunAsVirtualAccount = $true

# 2. Create Session Configuration file
New-PSSessionConfigurationFile -Path "C:\JEA\HelpDeskJEA.pssc" `
    -SessionType RestrictedRemoteServer `
    -RunAsVirtualAccount `
    -RoleDefinitions @{
        'CORP\HelpDesk' = @{ RoleCapabilities = 'HelpDesk' }
        'CORP\NetAdmins' = @{ RoleCapabilities = 'NetworkAdmin' }
    } `
    -TranscriptDirectory "\\logserver\JEATranascripts$"

# 3. Register the endpoint
Register-PSSessionConfiguration -Name "HelpDeskEndpoint" `
    -Path "C:\JEA\HelpDeskJEA.pssc" `
    -Force

# 4. Connect as a help desk user
Enter-PSSession -ComputerName "SERVER01" -ConfigurationName "HelpDeskEndpoint"

# 5. Audit JEA usage
Get-PSSessionConfiguration -Name "HelpDeskEndpoint"
```

### 6.5 PowerShell 7 vs. Windows PowerShell 5.1 Security

| Feature | PS 5.1 | PS 7 |
|---------|--------|------|
| AMSI integration | Yes | Yes (Windows) |
| ScriptBlock logging | Yes | Yes |
| CLM support | Yes | Yes |
| SSH remoting | No | Yes |
| Execution policy | Yes (weak) | Yes (weak) |
| `#requires -RunAsAdministrator` | Yes | Yes |
| Parallel `ForEach-Object -Parallel` | No | Yes (new attack surface) |
| Secure string handling | Win32 API | Cross-platform |
| WinRM remoting | Yes | Yes |

**Key recommendation:** Deploy PS7 alongside PS5.1; audit both. Disable PS2 (`MicrosoftWindowsPowerShellV2Root` optional feature).

### 6.6 Execution Policy vs. AppLocker/WDAC

**Execution Policy is NOT a security boundary:**
```powershell
# Trivially bypassed:
powershell -ExecutionPolicy Bypass -File malicious.ps1
powershell -ep bypass
[System.Threading.Thread]::CurrentThread.Name  # runs in any EP
Get-Content script.ps1 | Invoke-Expression    # bypasses EP
```

**Actual script enforcement — WDAC Publisher rules:**
```xml
<!-- In WDAC policy XML -->
<FileRules>
  <Allow ID="ID_ALLOW_PS_SIGNED" FriendlyName="Signed PowerShell scripts"
         MinimumFileVersion="0.0.0.0"
         FilePath="*.ps1">
    <CertificatePublisher CertificateEKUs="1.3.6.1.5.5.7.3.3"
                          CertificateTBSHash="<your-signing-cert-thumbprint>"/>
  </Allow>
</FileRules>
```

**AppLocker for PowerShell:**
```powershell
# Create AppLocker rule to allow only signed scripts
$rule = New-AppLockerPolicy -RuleType Script -Action Allow `
    -User Everyone `
    -XmlPolicy (Get-AppLockerPolicy -Effective -Xml)
# Requires: AppLocker + Publisher rules + code signing CA
```

---

## 7. Windows Defender and Endpoint Protection

### 7.1 Microsoft Defender Antivirus Configuration

**Cloud-Delivered Protection:**
```powershell
# Enable cloud protection and automatic sample submission
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 50  # seconds to block pending cloud verdict

# Verify
Get-MpPreference | Select-Object MAPSReporting, CloudBlockLevel, CloudExtendedTimeout
```

**Tamper Protection:**
Tamper Protection prevents local changes to Defender settings — must be managed via Intune if enrolled.

```powershell
# Check tamper protection status
Get-MpComputerStatus | Select-Object IsTamperProtected, TamperProtectionSource
# TamperProtectionSource: 0=not protected, 1=GP, 4=MDM, 5=MDM+GP, 6=Intune
```

Enable via: Windows Security app > Virus & Threat Protection > Manage Settings > Tamper Protection: **On**
Or via Intune: Device Configuration > Endpoint Security > Microsoft Defender > Tamper Protection: **Enabled**

### 7.2 Attack Surface Reduction (ASR) Rules

ASR rules block specific behaviors commonly used in attacks. Each rule has a GUID.

| Rule Name | GUID | Recommended Mode |
|-----------|------|-----------------|
| Block executable content from email/webmail | BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Block |
| Block Office apps from creating child processes | D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block |
| Block Office apps from creating executable content | 3B576869-A4EC-4529-8536-B80A7769E899 | Block |
| Block Office apps from injecting into processes | 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block |
| Block JavaScript/VBScript from launching executables | D3E037E1-3EB8-44C8-A917-57927947596D | Block |
| Block execution of potentially obfuscated scripts | 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block |
| Block Win32 API calls from Office macro | 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Block |
| Block credential stealing from LSASS | 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0 | Block |
| Block process creations from PSExec/WMI | D1E49AAC-8F56-4280-B9BA-993A6D77406C | Audit first |
| Block untrusted/unsigned USB processes | B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 | Block |
| Block persistence through WMI event subscription | E6DB77E5-3DF2-4CF1-B95A-636979351E5B | Block |
| Block Office comm apps from creating child procs | 26190899-1602-49E8-8B27-EB1D0A1CE869 | Block |
| Block Adobe Reader from creating child processes | 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C | Block |
| Block abuse of exploited vulnerable signed drivers | 56A863A9-875E-4185-98A7-B882C64B5CE5 | Block |
| Use advanced protection against ransomware | C1DB55AB-C21A-4637-BB3F-A12568109D35 | Block |
| Block credential stealing via LSASS | 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0 | Block |

```powershell
# Enable ASR rules via PowerShell
$asrRules = @(
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
    "3B576869-A4EC-4529-8536-B80A7769E899",
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
    "D3E037E1-3EB8-44C8-A917-57927947596D",
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0",
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
    "26190899-1602-49E8-8B27-EB1D0A1CE869",
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
    "56A863A9-875E-4185-98A7-B882C64B5CE5",
    "C1DB55AB-C21A-4637-BB3F-A12568109D35",
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4"
)

# Set all to Block (2) — use Audit (1) initially in production
Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRules `
    -AttackSurfaceReductionRules_Actions (@(2) * $asrRules.Count)

# Verify
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

**ASR audit events:** EID **1121** (Block), **1122** (Audit) — source: `Microsoft-Windows-Windows Defender`

### 7.3 Exploit Guard Settings

Exploit Guard replaces EMET (Enhanced Mitigation Experience Toolkit) with built-in Windows protections.

```powershell
# Configure Exploit Protection system-wide
$exploitSettings = @{
    DEP = @{Enable = $true; EnableXProcessCreation = $false}
    CFG = @{Enable = $true; SuppressExports = $false}
    SEHOP = @{Enable = $true}
}

# Export current settings
Get-ProcessMitigation -System | ConvertTo-Xml | Out-File exploit-settings.xml

# Apply system-level settings
Set-ProcessMitigation -System -Enable DEP, SEHOP, CFG

# Apply per-process settings (example: Word)
Set-ProcessMitigation -Name "WINWORD.EXE" `
    -Enable DEP, SEHOP, CFG, HeapSpray `
    -Disable MicrosoftSignedOnly

# Export settings for GPO deployment
Get-ProcessMitigation -RegistryConfigFilePath "C:\exploit-protection.xml"
# Import via GPO: Computer Config > Admin Templates > Windows Components >
# Windows Defender Exploit Guard > Exploit Protection > Use a common set of exploit protection settings
```

**Key mitigations:**
- **DEP (Data Execution Prevention):** Marks non-code pages as non-executable; hardware NX bit enforcement.
- **CFG (Control Flow Guard):** Validates indirect function call targets; compiler + OS feature.
- **SEHOP (Structured Exception Handler Overwrite Protection):** Validates SEH chain before dispatch.
- **Heap Spray Allocation:** Reserves common heap spray addresses.
- **Import Address Filter (IAF):** Blocks suspicious use of sensitive APIs from shellcode.

### 7.4 Microsoft Defender for Endpoint (MDE)

**Onboarding:**
```powershell
# Deploy onboarding script (from MDE portal > Settings > Endpoints > Onboarding)
# WindowsDefenderATPOnboardingPackage.zip contains:
#   WindowsDefenderATPOnboardingScript.cmd  (local script)
#   WindowsDefenderATPLocalOnboardingTool.cmd (tool)

# GPO deployment: Computer Config > Preferences > Windows Settings > Files
# Deploy onboarding script as a startup script

# Verify onboarding
Get-MpComputerStatus | Select-Object DefenderEnabled, RealTimeProtectionEnabled
# MDE-specific: check sense service
Get-Service -Name "sense"  # Windows Defender Advanced Threat Protection Service
```

**Advanced Hunting KQL — Common Attacks:**

```kql
// Credential Dumping — LSASS Access
DeviceEvents
| where ActionType == "LsassMemoryDump"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine

// Lateral Movement — Pass the Hash indicators
DeviceLogonEvents
| where LogonType == "Network" and IsLocalAdmin == true
| where AccountDomain != DeviceName  // remote logon
| summarize count() by AccountName, DeviceName, RemoteIP
| where count_ > 5

// PowerShell encoded commands
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-ec ")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName

// Suspicious scheduled task creation
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| where InitiatingProcessFileName !in~ ("taskschd.dll","svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, AdditionalFields

// Ransomware — mass file extension changes
DeviceFileEvents
| where ActionType == "FileRenamed"
| summarize renames=count(), extensions=make_set(FileName) by DeviceName, bin(Timestamp, 1m)
| where renames > 100
```

**Live Response commands:**
```
> run GetRunningProcesses.ps1  # execute PS script on endpoint
> getfile C:\path\to\suspicious.exe  # download file for analysis
> remediate-file malware.exe    # remove file
> isolate                        # network isolate endpoint
```

---

## 8. Application Control

### 8.1 AppLocker

AppLocker enforces application execution policy via GPO rules. Operates in user mode.

**Rule Types:**

| Type | Identifies By | Use Case |
|------|--------------|----------|
| **Publisher** | Code signing certificate + filename + version | Commercial software with consistent signing |
| **Path** | File/folder path with wildcards | Location-based control (C:\Windows\*) |
| **Hash** | SHA-256 file hash | Unsigned software, specific versions |

**Default Rules (always create these first):**
- Executable: Allow `%WINDIR%\*`, Allow `%PROGRAMFILES%\*`, Allow Administrators (all)
- Script: Allow `%WINDIR%\*`, Allow `%PROGRAMFILES%\*`
- Windows Installer: Allow digitally signed, Allow `%WINDIR%\Installer\*`
- DLL: (Optional — high impact, test thoroughly)

**Configure AppLocker via PowerShell:**
```powershell
# Get current effective policy
Get-AppLockerPolicy -Effective -Xml | Out-File C:\AppLockerPolicy.xml

# Test a file against policy
Test-AppLockerPolicy -Path "C:\Tools\psexec.exe" -User Everyone

# Create publisher rule for approved software
$policy = New-AppLockerPolicy -RuleType Publisher -FileInformation `
    (Get-AppLockerFileInformation -Path "C:\Program Files\App\app.exe") `
    -User Everyone -Action Allow

# Set enforcement mode
Set-AppLockerPolicy -XmlPolicy $policy -Merge

# Enable AppLocker services
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc
```

**AppLocker Event Log:** `Microsoft-Windows-AppLocker/EXE and DLL`
- EID **8003**: Block (Audit mode — would have blocked)
- EID **8004**: Block (Enforcement mode — blocked)
- EID **8005**: Allow (Audit mode)
- EID **8006**: Allow (Enforcement mode — DLL)
- EID **8007**: Allow (Enforcement mode — EXE)

**Limitations:** AppLocker can be bypassed via alternate execution environments (`msbuild.exe`, `regsvr32.exe`, `InstallUtil.exe`, `rundll32.exe`, `mshta.exe`) — these LOLBins may be whitelisted by default. Supplement with WDAC.

### 8.2 Windows Defender Application Control (WDAC)

WDAC enforces code integrity at the kernel level — superior to AppLocker because bypassing it requires a kernel exploit.

**Policy Types:**

| Type | Description |
|------|-------------|
| **Base policy** | Primary policy; single base per system |
| **Supplemental policy** | Extends base policy (allow additional apps); multiple allowed |
| **Audit mode** | Logs what would be blocked — no enforcement |
| **Enforcement mode** | Blocks unauthorized code execution |

**Create WDAC Policy (WDAC Wizard or PowerShell):**
```powershell
# Create default policy (allow Windows + WHQL signed + MSIT signed)
$policyPath = "C:\WDAC\BasePolicy.xml"
New-CIPolicy -Level Publisher -Fallback Hash -FilePath $policyPath `
    -UserPEs -ScanPath "C:\Windows"

# Convert to binary
ConvertFrom-CIPolicy -XmlFilePath $policyPath `
    -BinaryFilePath "C:\WDAC\BasePolicy.p7b"

# Deploy policy
Copy-Item "C:\WDAC\BasePolicy.p7b" `
    "$env:windir\System32\CodeIntegrity\CIPolicies\Active\{GUID}.cip"

# Refresh policy (no reboot for unsigned policies)
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI `
    -ClassName PS_UpdateAndCompareCIPolicy `
    -MethodName Update `
    -Arguments @{FilePath = "C:\WDAC\BasePolicy.p7b"}
```

**Audit → Enforcement Pipeline:**
```powershell
# Step 1: Deploy in audit mode
Set-RuleOption -FilePath $policyPath -Option 3  # Audit Mode

# Step 2: Collect audit events (EID 3076 = would-have-blocked)
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object { $_.Id -eq 3076 }

# Step 3: Create supplemental policy for legitimate software
New-CIPolicy -Level Publisher -ScanPath "C:\LegitApps" `
    -FilePath "C:\WDAC\SupplementalPolicy.xml" -UserPEs

# Step 4: Remove audit mode, enforce
Remove-RuleOption -FilePath $policyPath -Option 3

# Step 5: Sign policy (recommended for UEFI lock)
# Use signtool.exe with code signing cert
```

**WDAC Event IDs:**
- **3076**: Audit mode — file would have been blocked
- **3077**: Enforcement mode — file blocked
- **3089**: Signer information for blocked file
- **3099**: Policy activated

### 8.3 HVCI (Hypervisor-Protected Code Integrity)

HVCI runs WDAC code integrity checks inside VTL1 (Virtual Secure Mode), preventing even kernel exploits from loading unsigned code.

```powershell
# Enable HVCI
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
  Enabled = 1 (DWORD)
  Locked  = 1 (DWORD)  ; UEFI lock prevents disabling without firmware access

# Check HVCI status
(Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard).CodeIntegrityPolicyEnforcementStatus
# 2 = HVCI enforced
```

**Requirements:** VT-x/AMD-V with SLAT, IOMMU, Secure Boot, no legacy mode drivers.
**Impact:** Incompatible with many legacy/unsigned kernel drivers — audit driver compatibility before enabling.

### 8.4 Smart App Control (Windows 11)

Smart App Control (SAC) blocks apps that lack valid signatures or are not trusted by Microsoft's cloud service.

- **On:** Blocks unsigned/untrusted apps — strictest mode.
- **Evaluation:** Microsoft evaluates each app and determines trust over time.
- **Off:** Disabled (permanent — cannot re-enable without OS reset).

SAC integrates with WDAC; disabling SAC is irreversible without reinstalling Windows. Available only on fresh Windows 11 22H2+ installs (not upgrades).

---

## 9. Network Hardening and SMB Security

### 9.1 SMB Hardening

**Disable SMBv1:**
```powershell
# Server-side
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Client-side
Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force

# Also disable the Windows feature
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart

# Verify
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
```

**Require SMB Signing:**
```powershell
# Server: require signing (clients must sign)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force

# Client: require signing (servers must sign)
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# GPO paths:
# Computer Config > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network server: Digitally sign communications (always)" -> Enabled
# "Microsoft network client: Digitally sign communications (always)" -> Enabled
```

**SMB Encryption (SMBv3):**
```powershell
# Require encryption for all SMB connections
Set-SmbServerConfiguration -EncryptData $true -Force

# Per-share encryption
Set-SmbShare -Name "SensitiveData" -EncryptData $true

# Verify encryption
Get-SmbSession | Select-Object ClientComputerName, Encrypted
```

**Disable NetBIOS over TCP/IP:**
```powershell
# Via registry (all adapters)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 0=default, 1=enable, 2=disable
}

# Registry path:
# HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
# NetbiosOptions = 2 (Disable NetBIOS over TCP/IP)
```

### 9.2 LLMNR, mDNS, WPAD Disable

These protocols are abused for credential capture (Responder attacks).

**Disable LLMNR (Link-Local Multicast Name Resolution):**
```registry
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
  EnableMulticast = 0 (DWORD)
```
GPO: `Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution` → **Enabled**

**Disable mDNS:**
```registry
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
  EnableMDNS = 0 (DWORD)
```

**Disable WPAD (Web Proxy Auto-Discovery):**
```powershell
# Via registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" `
    -Name DisableWpad -Value 1 -Type DWord

# Also set WinHttpSettings
netsh winhttp reset autoproxy

# Block WPAD DNS resolution at DNS server level (add WPAD A record pointing to 0.0.0.0)
```

### 9.3 Windows Firewall Configuration

```powershell
# Enable all profiles
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Set default inbound deny, outbound allow (standard posture)
Set-NetFirewallProfile -Profile Domain,Private -DefaultInboundAction Block `
    -DefaultOutboundAction Allow -NotifyOnListen True

# Public profile — also block outbound from non-browser apps
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block `
    -DefaultOutboundAction Block

# Enable logging
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 32767 `
    -LogBlocked True `
    -LogAllowed True

# Server inbound rules (example: allow RDP from management subnet only)
New-NetFirewallRule -Name "RDP-In-Mgmt" -DisplayName "RDP from Management" `
    -Protocol TCP -LocalPort 3389 -Action Allow `
    -RemoteAddress "10.0.100.0/24" -Direction Inbound

# Allow WinRM HTTPS from management only
New-NetFirewallRule -Name "WinRM-HTTPS-In" -DisplayName "WinRM HTTPS" `
    -Protocol TCP -LocalPort 5986 -Action Allow `
    -RemoteAddress "10.0.100.0/24" -Direction Inbound

# Block inbound SMB except from specific servers
New-NetFirewallRule -Name "SMB-Block-Inbound" -DisplayName "Block SMB Inbound" `
    -Protocol TCP -LocalPort 445 -Action Block -Direction Inbound -Priority 1000
New-NetFirewallRule -Name "SMB-Allow-FileServer" -DisplayName "Allow SMB from FileServer" `
    -Protocol TCP -LocalPort 445 -Action Allow `
    -RemoteAddress "10.0.0.10" -Direction Inbound -Priority 100
```

### 9.4 IPSec for Lateral Movement Restriction

IPSec connection security rules can enforce encryption and authentication between systems without a full PKI.

```powershell
# Require IPSec for workstation-to-workstation SMB (prevent lateral movement)
New-NetIPsecRule -DisplayName "Require IPSec for SMB" `
    -InboundSecurity Require -OutboundSecurity Request `
    -Protocol TCP -LocalPort 445

# Create authentication rule using Kerberos (domain-joined systems)
New-NetIPsecAuthProposal -Machine -Kerberos
New-NetIPsecPhase1AuthSet -DisplayName "Kerberos Phase1" `
    -Proposal (New-NetIPsecAuthProposal -Machine -Kerberos) | Out-Null

# GPO: Computer Config > Windows Settings > Security Settings >
# Windows Firewall > Connection Security Rules
```

### 9.5 Disabling Legacy Protocols

```powershell
# Disable Telnet client
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart

# Disable TFTP client
Disable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart

# Disable FTP Publishing Service (if IIS installed)
Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer -NoRestart

# Disable older TLS versions (enforce TLS 1.2+)
# Via Schannel registry:
$tlsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
# Disable SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1
foreach ($version in @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")) {
    foreach ($role in @("Client", "Server")) {
        $path = "$tlsPath\$version\$role"
        New-Item -Path $path -Force | Out-Null
        Set-ItemProperty -Path $path -Name Enabled -Value 0 -Type DWord
        Set-ItemProperty -Path $path -Name DisabledByDefault -Value 1 -Type DWord
    }
}
# Enable TLS 1.2, 1.3
foreach ($version in @("TLS 1.2", "TLS 1.3")) {
    foreach ($role in @("Client", "Server")) {
        $path = "$tlsPath\$version\$role"
        New-Item -Path $path -Force | Out-Null
        Set-ItemProperty -Path $path -Name Enabled -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name DisabledByDefault -Value 0 -Type DWord
    }
}
```

---

## 10. Audit Policy and Monitoring

### 10.1 Complete auditpol.exe Category Reference

```cmd
REM ─── Account Logon ───
auditpol /set /subcategory:"Credential Validation"               /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service"     /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"  /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events"          /success:enable /failure:enable

REM ─── Account Management ───
auditpol /set /subcategory:"Computer Account Management"         /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management"       /success:enable
auditpol /set /subcategory:"Other Account Management Events"     /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"           /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"             /success:enable /failure:enable

REM ─── Detailed Tracking ───
auditpol /set /subcategory:"DPAPI Activity"                      /success:enable /failure:enable
auditpol /set /subcategory:"PNP Activity"                        /success:enable
auditpol /set /subcategory:"Process Creation"                    /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination"                 /success:enable
auditpol /set /subcategory:"RPC Events"                          /success:enable /failure:enable
auditpol /set /subcategory:"Token Right Adjusted Events"         /success:enable

REM ─── DS Access ───
auditpol /set /subcategory:"Detailed Directory Service Replication" /failure:enable
auditpol /set /subcategory:"Directory Service Access"            /failure:enable
auditpol /set /subcategory:"Directory Service Changes"           /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication"       /success:enable /failure:enable

REM ─── Logon/Logoff ───
auditpol /set /subcategory:"Account Lockout"                     /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership"                    /success:enable
auditpol /set /subcategory:"IPsec Extended Mode"                 /failure:enable
auditpol /set /subcategory:"IPsec Main Mode"                     /failure:enable
auditpol /set /subcategory:"IPsec Quick Mode"                    /failure:enable
auditpol /set /subcategory:"Logoff"                              /success:enable
auditpol /set /subcategory:"Logon"                               /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server"               /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events"           /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"                       /success:enable

REM ─── Object Access ───
auditpol /set /subcategory:"Application Generated"               /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services"              /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share"                 /failure:enable
auditpol /set /subcategory:"File Share"                          /success:enable /failure:enable
auditpol /set /subcategory:"File System"                         /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection"       /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop"      /failure:enable
auditpol /set /subcategory:"Handle Manipulation"                 /failure:enable
auditpol /set /subcategory:"Kernel Object"                       /failure:enable
auditpol /set /subcategory:"Other Object Access Events"          /success:enable /failure:enable
auditpol /set /subcategory:"Registry"                            /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage"                   /success:enable /failure:enable
auditpol /set /subcategory:"SAM"                                 /failure:enable

REM ─── Policy Change ───
auditpol /set /subcategory:"Audit Policy Change"                 /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change"        /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change"         /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change"    /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change"     /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events"          /failure:enable

REM ─── Privilege Use ───
auditpol /set /subcategory:"Non Sensitive Privilege Use"         /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events"          /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use"             /success:enable /failure:enable

REM ─── System ───
auditpol /set /subcategory:"IPsec Driver"                        /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events"                 /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change"               /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"           /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity"                    /success:enable /failure:enable
```

### 10.2 SACL Configuration for Sensitive Objects

```powershell
# Audit sensitive registry keys (SAM, LSA Secrets)
$acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$auditRule = New-Object System.Security.AccessControl.RegistryAuditRule(
    "Everyone",
    [System.Security.AccessControl.RegistryRights]::FullControl,
    [System.Security.AccessControl.AuditFlags]::Failure
)
$acl.SetAuditRule($auditRule)
Set-Acl "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" $acl

# Audit sensitive files (NTDS.dit on DCs)
$sacl = Get-Acl "C:\Windows\NTDS\NTDS.dit"
$fileAudit = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    [System.Security.AccessControl.FileSystemRights]::Read,
    [System.Security.AccessControl.AuditFlags]::Success
)
$sacl.SetAuditRule($fileAudit)
Set-Acl "C:\Windows\NTDS\NTDS.dit" $sacl
```

### 10.3 Windows Security Event ID Cheat Sheet

| Event ID | Source | Description | Detection Value |
|----------|--------|-------------|-----------------|
| **4624** | Security | Successful logon | Baseline; correlate LogonType |
| **4625** | Security | Failed logon | Brute force detection |
| **4634** | Security | Logoff | Session tracking |
| **4647** | Security | User-initiated logoff | Session tracking |
| **4648** | Security | Logon with explicit credentials (runas) | Lateral movement |
| **4649** | Security | Replay attack detected | Critical |
| **4657** | Security | Registry value modified | Configuration tampering |
| **4661** | Security | Handle to SAM object requested | Credential access |
| **4662** | Security | Operation on AD object | DCSync (GUID filter) |
| **4663** | Security | File/object access attempt | Data exfil (with SACL) |
| **4670** | Security | Permissions on object changed | Privilege escalation |
| **4672** | Security | Special privileges assigned to new logon | Admin/privileged logon |
| **4673** | Security | Privileged service called | Privilege abuse |
| **4674** | Security | Privileged object operation | Privilege abuse |
| **4688** | Security | Process created (with command line if enabled) | Execution tracking |
| **4697** | Security | Service installed | Persistence |
| **4698** | Security | Scheduled task created | Persistence |
| **4699** | Security | Scheduled task deleted | Tamper detection |
| **4700** | Security | Scheduled task enabled | Persistence |
| **4701** | Security | Scheduled task disabled | Defense evasion |
| **4702** | Security | Scheduled task updated | Persistence |
| **4703** | Security | Token right adjusted | Privilege escalation |
| **4719** | Security | System audit policy changed | Defense evasion |
| **4720** | Security | User account created | Persistence |
| **4722** | Security | User account enabled | Persistence |
| **4723** | Security | Password change attempt | Account control |
| **4724** | Security | Password reset attempt | Account control |
| **4725** | Security | User account disabled | Tamper |
| **4726** | Security | User account deleted | Tamper |
| **4728** | Security | Member added to global security group | Privilege escalation |
| **4732** | Security | Member added to local security group | Privilege escalation |
| **4740** | Security | User account locked out | Brute force |
| **4743** | Security | Computer account deleted | Tamper |
| **4756** | Security | Member added to universal security group | Privilege escalation |
| **4768** | Security | Kerberos TGT requested | Auth tracking |
| **4769** | Security | Kerberos service ticket requested | Auth tracking |
| **4771** | Security | Kerberos pre-auth failed | Brute force / AS-REP roasting |
| **4776** | Security | NTLM auth attempt (local) | Credential validation |
| **4778** | Security | Session reconnected | RDP tracking |
| **4779** | Security | Session disconnected | RDP tracking |
| **4798** | Security | Local group membership enumerated | Discovery |
| **4799** | Security | Security-enabled local group enumerated | Discovery |
| **4964** | Security | Special groups assigned to new logon | Privileged access |
| **5140** | Security | Network share accessed | Data access |
| **5145** | Security | Network share object access check | Data access |
| **5156** | Security | Windows Filtering Platform allowed connection | Network tracking |
| **5158** | Security | WFP allowed bind to local port | Network tracking |
| **5379** | Security | Credential Manager credentials read | Credential access |
| **7034** | System | Service crashed unexpectedly | Process injection / crash |
| **7036** | System | Service state changed | Service manipulation |
| **7045** | System | New service installed | Persistence |
| **1102** | Security | Audit log cleared | Defense evasion — CRITICAL |
| **4616** | Security | System time changed | Timestamp manipulation |
| **4907** | Security | Auditing settings on object changed | SACL tamper |

### 10.4 Event Log Sizing Recommendations

```powershell
# Increase Security log size (default 20MB is insufficient)
wevtutil sl Security /ms:1073741824   # 1GB
wevtutil sl System /ms:536870912     # 512MB
wevtutil sl Application /ms:536870912 # 512MB
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:2147483648  # 2GB
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824  # 1GB
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:536870912 # 512MB

# Set retention: overwrite as needed (not archive)
wevtutil sl Security /rt:false
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /rt:false

# Check current log configuration
wevtutil gl Security
```

### 10.5 MITRE ATT&CK Technique to Event ID Mapping

| ATT&CK Technique | ID | Key Event IDs | Notes |
|------------------|----|---------------|-------|
| Valid Accounts | T1078 | 4624, 4625, 4648 | LogonType 3/10 for remote |
| Pass the Hash | T1550.002 | 4624 (Type 3, NtLm), 4776 | Look for NtLm auth from workstations |
| Kerberoasting | T1558.003 | 4769 (EncryptionType 0x17) | RC4 ticket requests |
| AS-REP Roasting | T1558.004 | 4768 (failure, 0x18), 4771 | Pre-auth not required |
| DCSync | T1003.006 | 4662 (GUID 1131f6ad) | Non-DC requesting replication |
| LSASS Dump | T1003.001 | 10 (Sysmon), 4656, 4663 | Handle to lsass.exe |
| Scheduled Task | T1053.005 | 4698, 4702, 106 (Task Scheduler) | Unusual task paths |
| Service Creation | T1543.003 | 7045, 4697 | New services from temp paths |
| Registry Run Keys | T1547.001 | 4657, Sysmon 13 | HKCU/HKLM Run modifications |
| WMI Persistence | T1546.003 | Sysmon 19/20/21, WMI-Activity 5857 | WMI event subscriptions |
| PowerShell | T1059.001 | 4104, 4103, 4688 | Encoded commands, CLM bypass |
| Process Injection | T1055 | Sysmon 8, 10 | Remote thread creation |
| Lateral Movement (RDP) | T1021.001 | 4624 (Type 10), 4778, 4779 | Interactive remote logon |
| Lateral Movement (SMB) | T1021.002 | 5140, 5145, 4624 (Type 3) | Admin share access |
| Pass the Ticket | T1550.003 | 4768, 4769, 4770 | Unusual TGT/TGS patterns |
| Token Impersonation | T1134 | 4672, 4674, 4703 | SeImpersonatePrivilege use |
| Defense Evasion (Log Clear) | T1070.001 | 1102, 104 | Audit log cleared |
| Account Discovery | T1087 | 4798, 4799 | Local group enumeration |
| Network Scanning | T1046 | 5156, 5157 (WFP) | Port sweep patterns |

### 10.6 Windows Security Event Log — Microsoft Benchmark Audit Policy Summary

The following represents the Microsoft-recommended advanced audit policy baseline (matches MSSecurityBaseline):

```
Account Logon:
  Credential Validation:              Success, Failure
  Kerberos Authentication Service:    Success, Failure
  Kerberos Service Ticket Operations: Success, Failure
  Other Account Logon Events:         Success, Failure

Account Management:
  Computer Account Management:        Success, Failure
  Security Group Management:          Success, Failure
  User Account Management:            Success, Failure

Detailed Tracking:
  Process Creation:                   Success
  DPAPI Activity:                     Success, Failure

Logon/Logoff:
  Logon:                              Success, Failure
  Logoff:                             Success
  Account Lockout:                    Success, Failure
  Special Logon:                      Success
  Other Logon/Logoff Events:          Success, Failure

Object Access:
  File System:                        Failure (+ SACL for targeted Success)
  Registry:                           Failure (+ SACL for targeted Success)
  Certification Services:             Success, Failure

Policy Change:
  Audit Policy Change:                Success, Failure
  Authentication Policy Change:       Success

Privilege Use:
  Sensitive Privilege Use:            Success, Failure

System:
  Security State Change:              Success, Failure
  Security System Extension:          Success, Failure
  System Integrity:                   Success, Failure
```

---

## References and Further Reading

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) — Windows 10/11, Server 2022
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [DISA STIG Viewer](https://public.cyber.mil/stigs/srg-stig-tools/)
- [NSA Cybersecurity Guidance — Windows 10](https://media.defense.gov/2021/Sep/07/2002840795/-1/-1/0/CSI_WINDOWS-10-TLSSECURITY-SETTINGS_UOO12173421.PDF)
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/windows/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [palantir/windows-event-forwarding](https://github.com/palantir/windows-event-forwarding)
- [Microsoft Defender for Endpoint docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Windows LAPS Overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [WDAC Policy Wizard](https://webapp-wdac-wizard.azurewebsites.net/)
- [NSA Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)

---

*TeamStarWolf Cybersecurity Reference Library — Windows Hardening Reference v1.0*
