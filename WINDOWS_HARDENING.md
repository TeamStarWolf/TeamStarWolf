# Windows Hardening Reference

Hardening guidance for Windows endpoints and servers based on CIS Benchmarks, Microsoft Security Baselines, and DISA STIGs.

## Contents
- [CIS Windows Server 2022 Benchmark (Level 1 & 2)](#cis-windows-server-2022-benchmark)
- [Windows 10/11 Endpoint Hardening](#windows-1011-endpoint-hardening)
- [Group Policy Object (GPO) Configuration](#group-policy-object-gpo-configuration)
- [Windows Defender / Microsoft Defender for Endpoint](#windows-defender--microsoft-defender-for-endpoint)
- [Attack Surface Reduction (ASR) Rules](#attack-surface-reduction-asr-rules)
- [AppLocker / WDAC Application Control](#applocker--wdac-application-control)
- [Credential Guard & LSA Protection](#credential-guard--lsa-protection)
- [BitLocker Drive Encryption](#bitlocker-drive-encryption)
- [Windows Firewall Configuration](#windows-firewall-configuration)
- [Advanced Audit Policy](#advanced-audit-policy)
- [PowerShell Security](#powershell-security)
- [RDP Hardening](#rdp-hardening)
- [SMB Hardening](#smb-hardening)
- [LAPS (Local Administrator Password Solution)](#laps-local-administrator-password-solution)
- [Compliance Scanning Tools](#compliance-scanning-tools)
- [Quick Hardening Checklist](#quick-hardening-checklist)

---

## CIS Windows Server 2022 Benchmark

The CIS Benchmark for Windows Server 2022 is organized into Level 1 (basic hygiene, minimal impact) and Level 2 (defense-in-depth, may affect functionality). Below are the most impactful controls with registry paths and PowerShell commands.

### Account Policies — Password Policy

**CIS 1.1 — Password Policy**

| Setting | Recommended Value | GPO Path |
|---|---|---|
| Enforce password history | 24 or more passwords | Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy |
| Maximum password age | 365 days or fewer (NIST recommends no max unless breach) | Same |
| Minimum password age | 1 or more days | Same |
| Minimum password length | 14 or more characters | Same |
| Password must meet complexity | Enabled | Same |
| Store passwords using reversible encryption | Disabled | Same |

PowerShell (via `secedit` export/import):

```powershell
# Export current security policy
secedit /export /cfg C:\Windows\Temp\secpol.cfg

# Or set via net accounts
net accounts /minpwlen:14 /maxpwage:365 /minpwage:1 /uniquepw:24

# Verify
net accounts
```

Registry for password complexity is managed through SAM — use GPO or secedit, not direct registry edits.

### Account Policies — Account Lockout

**CIS 1.2 — Account Lockout Policy**

| Setting | Recommended Value | CIS Ref |
|---|---|---|
| Account lockout duration | 15 or more minutes | CIS 1.2.1 |
| Account lockout threshold | 5 or fewer invalid attempts | CIS 1.2.2 |
| Reset account lockout counter after | 15 or more minutes | CIS 1.2.3 |
| Administrator account lockout | Enabled (Windows Server 2019+) | CIS 1.2.4 |

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15

# Fine-Grained Password Policies (AD DS) via PowerShell
New-ADFineGrainedPasswordPolicy -Name "StrictPolicy" -Precedence 10 `
  -LockoutThreshold 5 -LockoutDuration "00:15:00" `
  -LockoutObservationWindow "00:15:00" `
  -MinPasswordLength 14 -PasswordHistoryCount 24 `
  -ComplexityEnabled $true -ReversibleEncryptionEnabled $false
```

### Local Policies — User Rights Assignment

**CIS 2.2 — User Rights Assignment**

| Right | Recommended | GPO Path |
|---|---|---|
| Access this computer from the network | Administrators, Authenticated Users | Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment |
| Act as part of the operating system | No one | Same |
| Allow log on locally | Administrators | Same (servers) |
| Allow log on through RDP | Administrators, Remote Desktop Users | Same |
| Back up files and directories | Administrators | Same |
| Change the system time | Administrators, LOCAL SERVICE | Same |
| Create symbolic links | Administrators | Same |
| Debug programs | Administrators | Same |
| Deny access from network | Guests, Local account | Same |
| Deny log on as a service | (CIS L2) Guests | Same |
| Force shutdown from remote system | Administrators | Same |
| Load and unload device drivers | Administrators | Same |
| Manage auditing and security log | Administrators | Same |
| Shut down the system | Administrators | Same |
| Take ownership of files | Administrators | Same |

```powershell
# View current user rights with secedit
secedit /export /cfg C:\Temp\userrights.cfg /areas USER_RIGHTS
Get-Content C:\Temp\userrights.cfg | Select-String "Se"
```

### Security Options

**CIS 2.3 — Security Options**

Key registry values under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` and related hives:

```powershell
# Accounts: Guest account status - Disabled
Set-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\000001F5" -Name "V" -Value ... # Use GPO

# Interactive logon: Machine inactivity limit (900 seconds = 15 min)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "InactivityTimeoutSecs" -Value 900 -Type DWord

# Interactive logon: Do not display last user name
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "DontDisplayLastUserName" -Value 1 -Type DWord

# Interactive logon: Do not require CTRL+ALT+DEL - Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "DisableCAD" -Value 0 -Type DWord

# Network access: Do not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RestrictAnonymousSAM" -Value 1 -Type DWord

# Network access: Do not allow anonymous enumeration of SAM accounts and shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RestrictAnonymous" -Value 1 -Type DWord

# Network security: LAN Manager authentication level — NTLMv2 only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LmCompatibilityLevel" -Value 5 -Type DWord

# Network security: LDAP client signing requirements — Negotiate signing (2)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" `
  -Name "LDAPClientIntegrity" -Value 2 -Type DWord

# Network security: Minimum session security for NTLM SSP — require NTLMv2 + 128-bit
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "NTLMMinClientSec" -Value 537395200 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "NTLMMinServerSec" -Value 537395200 -Type DWord

# System: Audit: Force audit policy subcategory settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

# UAC settings — CIS Level 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord  # Prompt for credentials on secure desktop
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord   # Deny elevation requests
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "EnableVirtualization" -Value 1 -Type DWord
```

**ATT&CK relevance**: T1078 (Valid Accounts), T1110 (Brute Force), T1021 (Remote Services)

---

## Windows 10/11 Endpoint Hardening

### Microsoft Security Baseline

Microsoft publishes Security Baselines via the Security Compliance Toolkit (SCT). Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319

```powershell
# Apply baseline with LGPO.exe (from SCT)
LGPO.exe /g ".\GPOs\{GUID-of-baseline}"

# Or import via Group Policy Management
# Copy GPO folder to SYSVOL and link via GPMC
```

### Endpoint-Specific Hardening Controls

```powershell
# Disable autorun/autoplay
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# Disable Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
  -Name "Enabled" -Value 0 -Type DWord

# Disable LLMNR (used in relay attacks)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -Value 0 -Type DWord

# Disable NetBIOS over TCP/IP via registry (also configure per-adapter)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
foreach ($a in $adapters) { $a.SetTcpipNetbios(2) }  # 2 = Disable

# Disable WPAD (Web Proxy Auto-Discovery)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" `
  -Name "Start" -Value 4 -Type DWord

# Enable Structured Exception Handler Overwrite Protection (SEHOP)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
  -Name "DisableExceptionChainValidation" -Value 0 -Type DWord

# Enable Data Execution Prevention (DEP)
bcdedit /set nx AlwaysOn

# Enable Address Space Layout Randomization (ASLR)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
  -Name "MoveImages" -Value 0xFFFFFFFF -Type DWord
```

**ATT&CK relevance**: T1187 (Forced Authentication/LLMNR Poisoning), T1566 (Phishing), T1204 (User Execution)

---

## Group Policy Object (GPO) Configuration

### Recommended GPO Structure

```
Default Domain Policy           → Account policies only (password, lockout, Kerberos)
Computers – Baseline Security  → OS hardening, firewall, audit, LSA, UAC
Computers – Defender           → MDE/Defender settings, ASR rules
Computers – AppLocker/WDAC     → Application control policies
Computers – BitLocker          → Encryption requirements
Servers – RDP Restriction       → NLA, session limits, cipher suites
Domain Controllers – Hardening  → DC-specific settings, LDAP signing
```

### Kerberos Policy (Domain Controllers)

```
GPO Path: Computer Configuration > Windows Settings > Security Settings > Account Policies > Kerberos Policy

Enforce user logon restrictions: Enabled
Maximum lifetime for service ticket: 600 minutes
Maximum lifetime for user ticket: 10 hours
Maximum lifetime for user ticket renewal: 7 days
Maximum tolerance for computer clock synchronization: 5 minutes
```

```powershell
# Verify Kerberos policy
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object *
Get-ADDefaultDomainPasswordPolicy
```

### MS Security Guide GPO Settings

Import the MS Security Guide ADMX templates from SCT for additional settings:

```
Computer Configuration > Administrative Templates > MS Security Guide

- Apply UAC restrictions to local accounts on network logons: Enabled
  (Prevents pass-the-hash lateral movement with local admin accounts)
  Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  Value: LocalAccountTokenFilterPolicy = 0

- WDigest Authentication: Disabled
  Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
  Value: UseLogonCredential = 0
  (Prevents cleartext credential caching in LSASS)

- NetBT NodeType configuration: P-node (2)
  (Eliminates NetBIOS broadcast resolution)
```

```powershell
# Disable WDigest - prevents cleartext creds in LSASS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -Name "UseLogonCredential" -Value 0 -Type DWord

# Prevent local admin token filter bypass (PtH mitigation)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
```

**NIST 800-53**: AC-2, AC-3, CM-6, CM-7  
**ATT&CK**: T1550.002 (Pass the Hash), T1003.001 (LSASS Memory)

---

## Windows Defender / Microsoft Defender for Endpoint

### Core Protection Settings

```powershell
# Enable Real-Time Protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Cloud-Delivered Protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable Potentially Unwanted Application (PUA) protection
Set-MpPreference -PUAProtection Enabled

# Enable Network Protection (requires MDE)
Set-MpPreference -EnableNetworkProtection Enabled

# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Configure scan settings
Set-MpPreference -ScanAvgCPULoadFactor 50
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
Set-MpPreference -ScanScheduleDay Everyday
Set-MpPreference -RemediationScheduleDay Everyday

# Update signatures
Update-MpSignature
Get-MpComputerStatus | Select-Object AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated
```

### Tamper Protection

Tamper Protection prevents unauthorized changes to Defender settings. It must be configured through the MDE portal or Intune; it cannot be disabled via PowerShell when enabled.

```powershell
# Verify tamper protection status
Get-MpComputerStatus | Select-Object IsTamperProtected

# Registry path (read-only when tamper protection is active)
# HKLM:\SOFTWARE\Microsoft\Windows Defender\Features
# TamperProtection = 5 (enabled), 4 (disabled)
```

**GPO Path** (for non-MDE managed): `Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus`

```powershell
# Registry equivalents for GPO settings
# Cloud protection level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" `
  -Name "SpynetReporting" -Value 2 -Type DWord

# Controlled Folder Access via registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" `
  -Name "EnableControlledFolderAccess" -Value 1 -Type DWord
```

### Defender for Endpoint — Exclusions Best Practice

- Never exclude entire drives or `C:\Windows\Temp` globally
- Scope exclusions to specific process + path combinations
- Document all exclusions with business justification
- Review exclusions quarterly

```powershell
# View current exclusions
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# Add process exclusion (example: backup agent)
Add-MpPreference -ExclusionProcess "C:\Program Files\BackupAgent\agent.exe"
```

**ATT&CK**: T1562.001 (Disable or Modify Tools)

---

## Attack Surface Reduction (ASR) Rules

ASR rules are enforced by Windows Defender and require Microsoft Defender Antivirus in active mode. They are supported on Windows 10 1709+ and Windows Server 2019+.

### Modes
- **0** = Disabled  
- **1** = Block  
- **2** = Audit  
- **6** = Warn (user can bypass)

### Full ASR Rule Table

| GUID | Rule Name | Recommended Mode |
|---|---|---|
| BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 | Block executable content from email client and webmail | Block (1) |
| D4F940AB-401B-4EFC-AADC-AD5F3C50688A | Block all Office applications from creating child processes | Block (1) |
| 3B576869-A4EC-4529-8536-B80A7769E899 | Block Office applications from creating executable content | Block (1) |
| 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 | Block Office applications from injecting code into other processes | Block (1) |
| D3E037E1-3EB8-44C8-A917-57927947596D | Block JavaScript or VBScript from launching downloaded executable content | Block (1) |
| 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC | Block execution of potentially obfuscated scripts | Block (1) |
| 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B | Block Win32 API calls from Office macros | Block (1) |
| 01443614-CD74-433A-B99E-2ECDC07BFC25 | Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Audit (2) |
| C1DB55AB-C21A-4637-BB3F-A12568109D35 | Use advanced protection against ransomware | Block (1) |
| 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 | Block credential stealing from the Windows LSASS process | Block (1) |
| D1E49AAC-8F56-4280-B9BA-993A6D77406C | Block process creations originating from PSExec and WMI commands | Audit (2) |
| B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 | Block untrusted and unsigned processes that run from USB | Block (1) |
| 26190899-1602-49E8-8B27-EB1D0A1CE869 | Block Office communication application from creating child processes | Block (1) |
| 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C | Block Adobe Reader from creating child processes | Block (1) |
| E6DB77E5-3DF2-4CF1-B95A-636979351E5B | Block persistence through WMI event subscription | Block (1) |

### Enable ASR via PowerShell (MDE)

```powershell
# Enable all recommended Block rules
$blockRules = @(
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Email executable content
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Office child processes
    "3B576869-A4EC-4529-8536-B80A7769E899",  # Office executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Office code injection
    "D3E037E1-3EB8-44C8-A917-57927947596D",  # JS/VBS downloaded executables
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Obfuscated scripts
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Office Win32 API calls
    "C1DB55AB-C21A-4637-BB3F-A12568109D35",  # Advanced ransomware protection
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",  # LSASS credential theft
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",  # Unsigned USB processes
    "26190899-1602-49E8-8B27-EB1D0A1CE869",  # Office comm child processes
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",  # Adobe Reader child processes
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"   # WMI persistence
)

$auditRules = @(
    "01443614-CD74-433A-B99E-2ECDC07BFC25",  # Prevalence-based executable block
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C"   # PSExec/WMI process creation
)

foreach ($rule in $blockRules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled
}
foreach ($rule in $auditRules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions AuditMode
}

# Verify
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

### Enable ASR via GPO

```
GPO Path: Computer Configuration > Administrative Templates > Windows Components >
          Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction

Setting: Configure Attack Surface Reduction rules
Value: Enabled, then add each GUID with value 1 (Block) or 2 (Audit)
```

### ASR Exclusions

```powershell
# Exclude a specific path from all ASR rules
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\SpecificApp\trusted.exe"

# View exclusions
Get-MpPreference | Select-Object AttackSurfaceReductionOnlyExclusions
```

**ATT&CK coverage**: T1059 (Command and Scripting Interpreter), T1566 (Phishing), T1003 (Credential Dumping), T1547 (Boot/Logon Autostart), T1021 (Remote Services)

---

## AppLocker / WDAC Application Control

### AppLocker

AppLocker controls which applications users can run. It supports four rule types: **Executable**, **Windows Installer**, **Script**, and **Packaged App**.

**Rule Types by Priority**:
1. Publisher rules (certificate-based — most maintainable)
2. Hash rules (file-specific — break on updates)
3. Path rules (location-based — easiest to bypass)

**Default Rule Sets** (always create these to avoid lockout):

```powershell
# Generate default rules for all rule collections
Get-AppLockerPolicy -Effective | Set-AppLockerPolicy -Merge

# Create default rules via GUI: 
# Local Security Policy > Application Control Policies > AppLocker > right-click > Create Default Rules
```

**PowerShell Deployment**:

```powershell
# Export current policy to XML
Get-AppLockerPolicy -Effective -Xml | Out-File C:\AppLockerPolicy.xml

# Import and apply policy
Set-AppLockerPolicy -XmlPolicy C:\AppLockerPolicy.xml

# Test a policy without enforcing
Test-AppLockerPolicy -Path C:\AppLockerPolicy.xml -User Everyone

# Enable AppLocker Application Identity service (required)
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
```

**Sample AppLocker XML Policy (Executable Rules)**:

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <!-- Allow Administrators to run everything -->
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
                  Name="(Default Rule) All files" Description=""
                  UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow Everyone to run from Program Files -->
    <FilePathRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                  Name="(Default Rule) All files in %PROGRAMFILES%"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*"/>
      </Conditions>
    </FilePathRule>
    <!-- Allow Everyone to run from Windows -->
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="(Default Rule) All files in %WINDIR%"
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

### Windows Defender Application Control (WDAC)

WDAC (formerly Device Guard Code Integrity) is the preferred application control solution for modern Windows. Unlike AppLocker, WDAC is enforced at the kernel level and cannot be bypassed by local administrators.

**WDAC Policy Creation**:

```powershell
# Create a base policy from an existing "golden" machine
New-CIPolicy -Level Publisher -FilePath C:\BasePolicy.xml `
  -ScanPath C:\Windows -UserPEs -MultiplePolicyFormat

# Create a policy in audit mode first
Set-RuleOption -FilePath C:\BasePolicy.xml -Option 3  # Audit mode

# Remove audit mode option to enforce
Set-RuleOption -FilePath C:\BasePolicy.xml -Option 3 -Delete

# Merge with Microsoft recommended block list
$mergeInputs = @("C:\BasePolicy.xml", "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml")
Merge-CIPolicy -PolicyPaths $mergeInputs -OutputFilePath C:\MergedPolicy.xml

# Convert to binary for deployment
ConvertFrom-CIPolicy -XmlFilePath C:\MergedPolicy.xml -BinaryFilePath C:\SiPolicy.p7b

# Deploy policy (copy to correct location)
Copy-Item -Path C:\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
```

**WDAC Supplemental Policies** (for exceptions without touching base policy):

```powershell
# Create supplemental policy for a specific application
New-CIPolicy -Level Publisher -FilePath C:\SupplementalApp.xml `
  -ScanPath "C:\Program Files\CustomApp" -MultiplePolicyFormat

# Set as supplemental
Set-CIPolicyIdInfo -FilePath C:\SupplementalApp.xml `
  -SupplementsBasePolicyID "{Base-Policy-GUID}"

# Convert and deploy
ConvertFrom-CIPolicy -XmlFilePath C:\SupplementalApp.xml `
  -BinaryFilePath C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{SupplementalGUID}.cip
```

**Audit vs Enforce Mode**:

```powershell
# Check current mode
Get-CimInstance -ClassName Win32_DeviceGuard | Select-Object CodeIntegrityPolicyEnforcementStatus
# 0 = off, 1 = audit, 2 = enforced

# View blocked applications in event log
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
  Where-Object { $_.Id -in @(3076, 3077) } |
  Select-Object TimeCreated, Message
```

**NIST 800-53**: CM-7, CM-14, SI-7  
**ATT&CK**: T1204 (User Execution), T1059 (Command and Scripting Interpreter)

---

## Credential Guard & LSA Protection

### Credential Guard

Credential Guard uses Virtualization Based Security (VBS) to isolate credential secrets from the OS. Domain-joined machines store Kerberos tickets and NTLM hashes in a secure, hypervisor-protected enclave.

**Requirements**:
- 64-bit CPU with virtualization extensions (Intel VT-x / AMD-V)
- UEFI firmware with Secure Boot enabled
- TPM 2.0 (recommended; 1.2 supported)
- Windows 10 Enterprise/Education or Windows Server 2016+
- Not a Hyper-V guest (unless nested virtualization is enabled)

**Enable via GPO**:

```
GPO Path: Computer Configuration > Administrative Templates > System > Device Guard
Setting: Turn On Virtualization Based Security
  Platform Security Level: Secure Boot and DMA Protection
  Credential Guard Configuration: Enabled with UEFI lock
  Secure Launch Configuration: Enabled
```

**Enable via Registry**:

```powershell
# Enable VBS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

# Require Secure Boot + DMA protection (3)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord

# Enable Credential Guard with UEFI lock (1)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LsaCfgFlags" -Value 1 -Type DWord
# Value 2 = enabled without UEFI lock (can be disabled without UEFI config change)
```

**Verify Credential Guard**:

```powershell
# Via PowerShell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning, SecurityServicesConfigured
# SecurityServicesRunning: 1 = Credential Guard running, 2 = HVCI running

# Via msinfo32.exe
# System Summary > Virtualization-based security Services Running
```

**Note**: Credential Guard is on by default on eligible Windows 11 22H2+ domain-joined devices.

### LSA Protection (Protected Process Light)

LSA runs as a Protected Process Light (PPL) when enabled, preventing non-PPL processes (including unsigned tools) from reading LSASS memory.

```powershell
# Enable LSA Protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1 -Type DWord

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL"

# Check in event log after reboot
Get-WinEvent -LogName "System" | Where-Object { $_.Id -eq 12 } | Select-Object -First 5
```

**ATT&CK**: T1003.001 (LSASS Memory), T1550.002 (Pass the Hash)  
**NIST 800-53**: IA-5, SC-28

---

## BitLocker Drive Encryption

### Requirements and Preparation

```powershell
# Check TPM status
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, ManagedAuthLevel

# Check BitLocker prerequisites
Get-BitLockerVolume -MountPoint C: | Select-Object MountPoint, VolumeStatus, EncryptionMethod
```

### Enable BitLocker with AES-256-XTS (Strongest Cipher)

```powershell
# Set cipher strength before enabling (must be done before first encryption)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
  -Name "EncryptionMethodWithXtsFdv" -Value 7 -Type DWord   # XTS-AES-256
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
  -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord    # XTS-AES-256
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" `
  -Name "EncryptionMethodWithXtsRdv" -Value 7 -Type DWord   # XTS-AES-256

# Enable BitLocker with TPM + PIN (most secure for endpoints)
$securePin = ConvertTo-SecureString "YourSecurePIN" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
  -TpmAndPinProtector -Pin $securePin

# Add recovery key protector
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector

# Enable BitLocker with TPM only (servers / no user interaction)
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector
Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
```

### Recovery Key Escrow

**Backup to Active Directory**:

```powershell
# Get the recovery key protector ID
$keyID = (Get-BitLockerVolume -MountPoint C:).KeyProtector |
  Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
  Select-Object -ExpandProperty KeyProtectorId

# Backup to AD DS
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyID

# Backup to Azure AD (via manage-bde on AAD-joined devices)
manage-bde -protectors -adbackup C: -id $keyID
```

**Backup to Azure Active Directory (Intune)**:
Configure via Intune endpoint protection policy: `BitLocker > OS drive settings > Recovery key backup to Azure AD: Required`

### Status and Management

```powershell
# Check all volumes
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus

# manage-bde status
manage-bde -status C:
manage-bde -status -protectors C:

# Suspend BitLocker (for updates, do NOT disable)
Suspend-BitLocker -MountPoint "C:" -RebootCount 1

# Resume BitLocker
Resume-BitLocker -MountPoint "C:"
```

**GPO Path**: `Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption`

**NIST 800-53**: SC-28, MP-5  
**CIS**: CIS Control 3 (Data Protection)

---

## Windows Firewall Configuration

### Enable All Profiles and Set Default Deny Inbound

```powershell
# Enable firewall for all profiles and block inbound by default
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
  -LogBlocked True -LogAllowed True `
  -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
  -LogMaxSizeKilobytes 32767
```

### Allow Rules for Management

```powershell
# Allow RDP from specific management subnet only
New-NetFirewallRule -DisplayName "Allow RDP - Management Only" `
  -Direction Inbound -Protocol TCP -LocalPort 3389 `
  -RemoteAddress "10.10.10.0/24" -Action Allow -Profile Domain

# Allow WinRM (PowerShell Remoting) from specific hosts
New-NetFirewallRule -DisplayName "Allow WinRM - Management" `
  -Direction Inbound -Protocol TCP -LocalPort 5985,5986 `
  -RemoteAddress "10.10.10.0/24" -Action Allow -Profile Domain

# Allow ICMP Echo (ping) from trusted networks only
New-NetFirewallRule -DisplayName "Allow ICMP Echo - Internal" `
  -Direction Inbound -Protocol ICMPv4 -IcmpType 8 `
  -RemoteAddress "10.0.0.0/8" -Action Allow

# Block everything else inbound (already set by DefaultInboundAction Block)
```

### Connection Security Rules (IPsec)

```powershell
# Require IPsec encryption for sensitive server communication
New-NetIPsecRule -DisplayName "Require Encryption - Internal" `
  -InboundSecurity Require -OutboundSecurity Request `
  -Phase1AuthSet "Default" -Phase2AuthSet "Default" `
  -InterfaceType Any

# Create an isolation rule (block non-domain systems)
New-NetFirewallRule -DisplayName "Isolate from Non-Domain Systems" `
  -Direction Inbound -Action Block `
  -Authentication Required
```

### Monitoring with netsh advfirewall

```powershell
# Show all active firewall rules
netsh advfirewall firewall show rule name=all

# Show firewall profile status
netsh advfirewall show allprofiles

# Export rules
netsh advfirewall export "C:\FirewallBackup.wfw"

# Import rules
netsh advfirewall import "C:\FirewallBackup.wfw"
```

**NIST 800-53**: SC-7, CA-9  
**CIS**: CIS Control 12 (Network Infrastructure Management)

---

## Advanced Audit Policy

### Enable Advanced Audit Policy via Registry

```powershell
# Force advanced audit policy subcategory settings to override legacy settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
```

### Recommended Audit Settings Table

| Category | Subcategory | Recommended Setting | CIS Ref |
|---|---|---|---|
| Account Logon | Credential Validation | Success, Failure | CIS 17.1.1 |
| Account Logon | Kerberos Authentication Service | Success, Failure | CIS 17.1.2 |
| Account Logon | Kerberos Service Ticket Operations | Success, Failure | CIS 17.1.3 |
| Account Management | Computer Account Management | Success | CIS 17.2.1 |
| Account Management | Other Account Management Events | Success | CIS 17.2.2 |
| Account Management | Security Group Management | Success | CIS 17.2.3 |
| Account Management | User Account Management | Success, Failure | CIS 17.2.5 |
| DS Access | Directory Service Access | Failure | CIS 17.3.1 |
| DS Access | Directory Service Changes | Success | CIS 17.3.2 |
| Logon/Logoff | Account Lockout | Failure | CIS 17.5.1 |
| Logon/Logoff | Group Membership | Success | CIS 17.5.2 |
| Logon/Logoff | Logoff | Success | CIS 17.5.3 |
| Logon/Logoff | Logon | Success, Failure | CIS 17.5.4 |
| Logon/Logoff | Other Logon/Logoff Events | Success, Failure | CIS 17.5.5 |
| Logon/Logoff | Special Logon | Success | CIS 17.5.6 |
| Object Access | Detailed File Share | Failure | CIS 17.6.1 |
| Object Access | File Share | Success, Failure | CIS 17.6.2 |
| Object Access | Other Object Access Events | Success, Failure | CIS 17.6.3 |
| Object Access | Removable Storage | Success, Failure | CIS 17.6.4 |
| Object Access | SAM | Failure | — |
| Policy Change | Audit Policy Change | Success | CIS 17.7.1 |
| Policy Change | Authentication Policy Change | Success | CIS 17.7.2 |
| Policy Change | Authorization Policy Change | Success | CIS 17.7.3 |
| Policy Change | MPSSVC Rule-Level Policy Change | Success, Failure | CIS 17.7.4 |
| Policy Change | Other Policy Change Events | Failure | CIS 17.7.5 |
| Privilege Use | Sensitive Privilege Use | Success, Failure | CIS 17.8.1 |
| System | IPsec Driver | Success, Failure | CIS 17.9.1 |
| System | Other System Events | Success, Failure | CIS 17.9.2 |
| System | Security State Change | Success | CIS 17.9.3 |
| System | Security System Extension | Success | CIS 17.9.4 |
| System | System Integrity | Success, Failure | CIS 17.9.5 |

### Apply with auditpol

```powershell
# Set audit policies via auditpol
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable  # Critical for EDR
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Export current policy
auditpol /get /category:* /r > C:\AuditPolicy.csv

# Import policy backup
auditpol /restore /file:C:\AuditPolicy.csv
```

### Key Event IDs for SIEM Detection

| Event ID | Description | Detection Use |
|---|---|---|
| 4624 | Successful logon | Baseline/anomaly detection |
| 4625 | Failed logon | Brute force detection |
| 4648 | Explicit credential logon | Pass-the-hash / lateral movement |
| 4657 | Registry value modified | Configuration tampering |
| 4663 | Object access | Data access auditing |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | Process creation | Malware/LOLBin detection |
| 4698 | Scheduled task created | Persistence |
| 4719 | Audit policy changed | Defense evasion |
| 4720 | User account created | Unauthorized account creation |
| 4732 | Member added to local group | Privilege escalation |
| 4768 | Kerberos TGT requested | Kerberoasting baseline |
| 4769 | Kerberos service ticket | Kerberoasting detection |
| 4771 | Kerberos pre-auth failed | Password spraying |
| 4776 | NTLM authentication | PtH / NTLM relay detection |
| 7045 | New service installed | Persistence |

**ATT&CK**: T1562.002 (Disable Windows Event Logging)  
**NIST 800-53**: AU-2, AU-3, AU-8, AU-12

---

## PowerShell Security

### Constrained Language Mode

Constrained Language Mode (CLM) restricts PowerShell to a safe subset of the language, preventing access to .NET types, COM objects, and Win32 APIs that attackers commonly use.

```powershell
# Check current language mode
$ExecutionContext.SessionState.LanguageMode
# FullLanguage = unrestricted, ConstrainedLanguage = CLM active

# CLM is enforced automatically when:
# 1. WDAC policy is active
# 2. AppLocker policy with script enforcement is active

# Force CLM via environment variable (soft enforcement — not recommended alone)
[System.Environment]::SetEnvironmentVariable("__PSLockDownPolicy", "4", "Machine")
```

### Script Block Logging

Records the content of PowerShell commands executed, including obfuscated and decoded scripts. Essential for detection.

```powershell
# Enable via registry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
```

**GPO Path**: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging`

### Module Logging

Logs the complete execution of every PowerShell module (including parameters and output).

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1 -Type DWord

# Log all modules (wildcard)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
  -Name "*" -Value "*" -Type String
```

### Transcription

Creates a text file of all PowerShell input/output in a centralized location.

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableInvocationHeader" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "OutputDirectory" -Value "\\fileserver\PSTranscripts$" -Type String
```

### Execution Policy via GPO

```
GPO Path: Computer Configuration > Administrative Templates > Windows Components >
          Windows PowerShell > Turn on Script Execution
Value: AllSigned (or RemoteSigned for servers)
```

```powershell
# Set execution policy (GPO overrides this)
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Verify
Get-ExecutionPolicy -List
```

### Remove PowerShell 2.0

PowerShell 2.0 bypasses Script Block Logging and runs without AMSI. Remove it:

```powershell
# Check if PS 2.0 is installed
Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root"

# Remove PS 2.0
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root"
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2"
```

### AMSI (Antimalware Scan Interface)

AMSI allows security products to scan PowerShell scripts, VBA macros, JScript, and other script-based content before execution.

```powershell
# Verify AMSI is active (from within PowerShell — should trigger AMSI)
# Test with EICAR-style string (AMSI test token):
# [Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils')

# Check if AMSI bypass is in use (detection)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Id -eq 4104 -and $_.Message -match "AmsiUtils" } |
  Select-Object TimeCreated, Message
```

**ATT&CK**: T1059.001 (PowerShell), T1562.001 (Disable Security Tools)  
**NIST 800-53**: AU-2, CM-7, SI-3

---

## RDP Hardening

### Network Level Authentication (NLA)

NLA requires users to authenticate before establishing a full RDP session, reducing the attack surface against unauthenticated exploits (e.g., BlueKeep).

```powershell
# Enable NLA via registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
  -Name "UserAuthentication" -Value 1 -Type DWord

# Disable RDP if not needed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections" -Value 1 -Type DWord
```

**GPO Path**: `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using NLA`

### Cipher Suite Restriction

```powershell
# Disable weak ciphers for RDP
# TLS 1.0 and 1.1 should be disabled
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
  -Name "SecurityLayer" -Value 2 -Type DWord  # TLS only (2 = SSL/TLS)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
  -Name "MinEncryptionLevel" -Value 3 -Type DWord  # High (128-bit minimum)

# Disable TLS 1.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
  -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" `
  -Name "DisabledByDefault" -Value 1 -Type DWord
```

### Session and Timeout Settings

```powershell
# Idle session timeout (15 minutes = 900000 ms)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -Name "MaxIdleTime" -Value 900000 -Type DWord

# Active session limit (8 hours = 480 minutes)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -Name "MaxConnectionTime" -Value 28800000 -Type DWord

# Disconnect on limit (don't end session — allow reconnect)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -Name "fResetBroken" -Value 1 -Type DWord

# Limit to 2 concurrent sessions per user
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
  -Name "MaxInstanceCount" -Value 2 -Type DWord
```

### Restricted Admin Mode

Restricted Admin Mode prevents credentials from being stored on the remote server during RDP sessions (pass-the-hash mitigation).

```powershell
# Enable Restricted Admin Mode on RDP server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "DisableRestrictedAdmin" -Value 0 -Type DWord

# Use from client side
mstsc /restrictedAdmin /v:server.domain.com
```

### Firewall Rule — Restrict RDP to Management Network

```powershell
# Remove default allow-any RDP rule
Remove-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -ErrorAction SilentlyContinue

# Create restricted rule (management subnet only)
New-NetFirewallRule -DisplayName "RDP - Management Network Only" `
  -Direction Inbound -Protocol TCP -LocalPort 3389 `
  -RemoteAddress "10.10.10.0/24" -Action Allow -Profile Domain -Enabled True
```

**ATT&CK**: T1021.001 (Remote Desktop Protocol)  
**NIST 800-53**: AC-17, SC-8

---

## SMB Hardening

### Disable SMBv1

SMBv1 is exploited by EternalBlue (MS17-010) and is the transport for WannaCry and NotPetya. It should be disabled on all systems.

```powershell
# Disable SMBv1 server component
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Disable SMBv1 client component
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
  -Name "Start" -Value 4 -Type DWord  # 4 = Disabled

# Windows Features approach (Server with Desktop Experience)
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Verify
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Require SMB Signing

SMB signing prevents man-in-the-middle relay attacks (NTLM relay, Responder).

```powershell
# Server: Require signing (prevents clients from connecting without signing)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force

# Client: Require signing on outbound connections
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# Verify
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature
```

**GPO Path**: 
- Server: `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always)`
- Client: `Microsoft network client: Digitally sign communications (always)`

### Disable SMB Guest Authentication

```powershell
# Disable insecure guest authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
  -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord

# Verify
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
  -Name "AllowInsecureGuestAuth"
```

### Disable SMB Compression (CVE-2020-0796 Mitigation)

```powershell
# Disable SMB compression (SMBv3.1.1 compression — CVE-2020-0796 / SMBGhost)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "DisableCompression" -Value 1 -Type DWord

# Verify
Get-SmbServerConfiguration | Select-Object DisableCompression
```

### Audit SMB Shares

```powershell
# List all shares and their permissions
Get-SmbShare | Select-Object Name, Path, Description
Get-SmbShareAccess -Name *

# List open SMB sessions
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens

# List open files
Get-SmbOpenFile | Select-Object FileId, SessionId, Path, ShareRelativePath

# Close all sessions (use carefully)
# Get-SmbSession | Close-SmbSession -Force
```

**ATT&CK**: T1021.002 (SMB/Windows Admin Shares), T1557.001 (LLMNR/NBT-NS Poisoning)  
**NIST 800-53**: CM-7, SC-8

---

## LAPS (Local Administrator Password Solution)

### Windows LAPS (Built-in — Preferred)

Windows LAPS is built into Windows since April 2023 (KB5025228 for older systems). It stores randomized local admin passwords in Active Directory or Azure AD.

**Enable Windows LAPS**:

```powershell
# Check current LAPS status
Get-LapsAADPassword -DeviceIds (Get-AzureADDevice -SearchString $env:COMPUTERNAME)

# Enable Windows LAPS via GPO
# GPO Path: Computer Configuration > Administrative Templates > System > LAPS
# Settings to configure:
#   - Configure password backup directory: Active Directory
#   - Password Settings: complexity, length (default: 14), age (30 days)
#   - Do not allow password expiration time longer than required by policy: Enabled
#   - Enable password encryption: Enabled (requires AD functional level 2016+)
#   - Name of administrator account to manage: (leave blank for default admin)
```

**Active Directory Schema Update** (for Windows LAPS with AD):

```powershell
# Update AD schema for Windows LAPS (run as Schema Admin)
Update-LapsADSchema

# Grant permissions for computer objects to update their own password attribute
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=contoso,DC=com"

# Grant read permissions to specific group
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
  -AllowedPrincipals "CONTOSO\LAPS-Readers"

# Grant reset permissions
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
  -AllowedPrincipals "CONTOSO\LAPS-Admins"
```

**Retrieve LAPS Password**:

```powershell
# Retrieve local admin password from AD
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText

# Force immediate password rotation
Invoke-LapsPolicyProcessing
Reset-LapsPassword

# Retrieve from Azure AD
Get-LapsAADPassword -DeviceIds "device-guid-here" -AsPlainText
```

### Legacy Microsoft LAPS (Pre-2023)

```powershell
# Install legacy LAPS client MSI (from Microsoft Download Center)
# After installation, configure via GPO:
# Import LAPS ADMX templates
# GPO Path: Computer Configuration > Administrative Templates > LAPS

# Schema extension (one-time, run as Schema Admin)
Import-Module AdmPwd.PS
Update-AdmPwdADSchema

# Set permissions
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=contoso,DC=com"
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Workstations,DC=contoso,DC=com" `
  -AllowedPrincipals "CONTOSO\HelpDesk"

# Read password (legacy)
Get-AdmPwdPassword -ComputerName "WORKSTATION01"
```

**NIST 800-53**: AC-2, IA-5  
**ATT&CK**: T1078.003 (Local Accounts), T1110 (Brute Force)

---

## Compliance Scanning Tools

### CIS-CAT Pro

CIS-CAT Pro is the official scanning tool for CIS Benchmarks. It produces scored HTML/CSV reports mapped to CIS controls.

```powershell
# CIS-CAT Pro Assessor (Java-based) — requires CIS membership
# Download from: https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/

# Run assessment (CLI)
.\Assessor-CLI.bat -b benchmarks\CIS_Microsoft_Windows_Server_2022_Benchmark_v3.0.0-xccdf.xml `
  -p "Level 1 - Member Server" -rd C:\Reports -rn "Server01-Assessment"

# Run with remote target
.\Assessor-CLI.bat -t \\RemoteServer -b .\benchmarks\CIS_Windows_10_Enterprise_v3.0.0-xccdf.xml `
  -p "Level 1 - Corporate/Enterprise Environment"
```

### Microsoft Security Compliance Toolkit (SCT)

SCT includes baselines for Windows, Office, Edge, and more. Download from Microsoft Download Center.

```powershell
# LGPO.exe — apply GPO backups locally without domain
LGPO.exe /g ".\GPOs\{GUID}"

# Compare current settings against baseline
# PolicyAnalyzer.exe (GUI tool in SCT)
# Import baseline and compare with current settings

# Apply settings individually
LGPO.exe /s .\secguide.inf

# Export current local policy
LGPO.exe /b C:\CurrentGPO
```

### Nessus / Tenable

Key Tenable plugin families for Windows hardening compliance:

| Plugin Family | Plugin IDs | Description |
|---|---|---|
| Windows | 57608 | CIS Windows Server 2022 Level 1/2 audit |
| Windows | 21156 | Windows Patch Tuesday checks |
| Windows | 24272 | SMBv1 detection |
| Windows | 96982 | Windows Firewall status |
| Windows | 73182 | Windows Credential Guard check |
| General | 10107 | HTTP Server type detection (via SMB) |

```powershell
# Nessus agent status
Get-Service -Name "Tenable Nessus Agent"

# Manual compliance scan trigger (Nessus Agent)
& "C:\Program Files\Tenable\Nessus Agent\nessuscli.exe" agent status
& "C:\Program Files\Tenable\Nessus Agent\nessuscli.exe" scan list
```

### OpenSCAP on Windows

While OpenSCAP is primarily Linux-native, SCAP Workbench and the DISA SCAP Compliance Checker (SCC) run on Windows.

```powershell
# DISA SCAP Compliance Checker (SCC) — free for US Gov, DoD
# Download from: https://public.cyber.mil/stigs/scap/

# Run SCC from CLI
& "C:\Program Files\DISA\SCC\cscc.exe" --scan --stigs `
  -d "C:\Results" --stig "Windows_Server_2022_STIG"

# STIG Viewer — GUI tool for reviewing STIG checklists
# Download: https://public.cyber.mil/stigs/stig-viewer/
```

### PowerShell-Based Compliance Checks

```powershell
# Quick compliance check script (sample)
function Test-WindowsHardening {
    $results = @()

    # Check SMBv1
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    $results += [PSCustomObject]@{ Control="SMBv1 Disabled"; Status=if(!$smb1){"PASS"}else{"FAIL"} }

    # Check BitLocker
    $bl = Get-BitLockerVolume -MountPoint C:
    $results += [PSCustomObject]@{ Control="BitLocker Active"; Status=if($bl.ProtectionStatus -eq "On"){"PASS"}else{"FAIL"} }

    # Check Firewall
    $fw = Get-NetFirewallProfile -Profile Domain
    $results += [PSCustomObject]@{ Control="Domain Firewall Enabled"; Status=if($fw.Enabled){"PASS"}else{"FAIL"} }

    # Check WDigest
    $wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
    $results += [PSCustomObject]@{ Control="WDigest Disabled"; Status=if($wd -eq 0){"PASS"}else{"FAIL"} }

    # Check NLA for RDP
    $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp").UserAuthentication
    $results += [PSCustomObject]@{ Control="RDP NLA Enabled"; Status=if($nla -eq 1){"PASS"}else{"FAIL"} }

    $results | Format-Table -AutoSize
}
Test-WindowsHardening
```

---

## Quick Hardening Checklist

20-item prioritized hardening checklist with registry/GPO paths and recommended values.

| # | Control | Registry / GPO Path | Recommended Value | CIS/STIG Ref |
|---|---|---|---|---|
| 1 | Disable SMBv1 | `HKLM:\SYSTEM\CCS\Services\LanmanServer\Parameters\SMB1` | 0 | CIS 18.3.3 |
| 2 | Enable SMB Signing (Server) | GPO: MS network server: Digitally sign (always) | Enabled | CIS 2.3.8.1 |
| 3 | Disable WDigest | `HKLM:\SYSTEM\CCS\Control\SecurityProviders\WDigest\UseLogonCredential` | 0 | MS Security Guide |
| 4 | Enable LSA Protection | `HKLM:\SYSTEM\CCS\Control\Lsa\RunAsPPL` | 1 | CIS 2.3.11.3 |
| 5 | Set LAN Manager Auth Level | `HKLM:\SYSTEM\CCS\Control\Lsa\LmCompatibilityLevel` | 5 (NTLMv2 only) | CIS 2.3.11.7 |
| 6 | Disable Local Token Filter Policy | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` | 0 | MS Security Guide |
| 7 | Enable Windows Firewall (all profiles) | GPO: Windows Defender Firewall: Protect all network connections | Enabled | CIS 9.1.1 |
| 8 | Enable Credential Guard | `HKLM:\SYSTEM\CCS\Control\DeviceGuard\EnableVirtualizationBasedSecurity` | 1 | CIS Level 2 |
| 9 | Remove PowerShell v2 | Windows Features: MicrosoftWindowsPowerShellV2Root | Disabled | CIS 18.10.x |
| 10 | Enable Script Block Logging | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | 1 | CIS 18.10.89.1 |
| 11 | Require RDP NLA | `HKLM:\SYSTEM\CCS\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` | 1 | CIS 18.10.56.2.2 |
| 12 | Set RDP Encryption Level High | `HKLM:\SYSTEM\CCS\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel` | 3 | CIS 18.10.56.3.3 |
| 13 | Enable BitLocker (OS drive) | GPO: Require additional authentication at startup | Enabled | CIS Level 2 |
| 14 | Disable Autorun/Autoplay | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` | 255 | CIS 18.9.8.1 |
| 15 | Disable LLMNR | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` | 0 | CIS 18.5.4.2 |
| 16 | Enable UAC Secure Desktop | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | 2 | CIS 2.3.17.2 |
| 17 | Enable Advanced Audit Policy | `HKLM:\SYSTEM\CCS\Control\Lsa\SCENoApplyLegacyAuditPolicy` | 1 | CIS 17.x |
| 18 | Deploy LAPS | Windows LAPS via GPO / Intune | Active Directory backup enabled | CIS Control 5 |
| 19 | Enable ASR Rules | MDE / GPO: Configure ASR rules | Block mode for key rules | NIST CM-7 |
| 20 | Enforce AppLocker / WDAC | AppIDSvc enabled, policy deployed | Allowlist mode | CIS Level 2 |

---

## Compliance Framework Mapping Summary

| Control Area | CIS Benchmark | NIST 800-53 | DISA STIG | ATT&CK Mitigations |
|---|---|---|---|---|
| Account Policies | CIS 1.1, 1.2 | AC-2, IA-5 | V-93269 | M1036 |
| Audit Policy | CIS 17.x | AU-2, AU-12 | V-93511 | M1047 |
| SMB Hardening | CIS 18.3.x | CM-7, SC-8 | V-93565 | M1031 |
| Credential Guard | CIS Level 2 | SC-28, IA-5 | V-93235 | M1043 |
| BitLocker | CIS Level 2 | SC-28, MP-5 | V-93519 | M1041 |
| PowerShell Security | CIS 18.10.89 | CM-7, AU-2 | V-93557 | M1042 |
| RDP Hardening | CIS 18.10.56 | AC-17, SC-8 | V-93591 | M1035 |
| AppLocker / WDAC | CIS Level 2 | CM-14, SI-7 | V-93623 | M1038 |
| Windows Firewall | CIS 9.x | SC-7, CA-9 | V-93475 | M1031 |
| ASR Rules | — | SI-3, CM-7 | — | M1040 |
| LAPS | CIS Control 5 | AC-2, IA-5 | V-93149 | M1026 |

---

## Additional Resources

- [CIS Benchmarks (free registration)](https://www.cisecurity.org/cis-benchmarks/)
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [DISA STIGs — Windows](https://public.cyber.mil/stigs/downloads/)
- [Microsoft Defender for Endpoint ASR documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction)
- [Windows LAPS documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [WDAC policy creation guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-policy-design-guide)
- [CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/)
- [Microsoft Baseline Security Analyzer (deprecated — use SCT)](https://learn.microsoft.com/en-us/security-updates/mbsa/)
- [ATT&CK Mitigations index](https://attack.mitre.org/mitigations/enterprise/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
