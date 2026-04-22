# Vendor Prevention Policy Reference

> This reference catalogs recommended settings from official vendor documentation for endpoint, network, identity, and email security controls. All settings are sourced from vendor security guidance and best-practice documentation. Links to authoritative sources are included throughout.

---

## Microsoft Defender for Endpoint Prevention Policies

*Source: Microsoft Learn — Microsoft Defender for Endpoint documentation*

---

### Attack Surface Reduction (ASR) Rules — Complete Reference

*Official reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference*

ASR rules are policy-enforced controls that block specific behaviors commonly used by malware and attackers. Each rule targets a discrete attack technique and can be set to **Disabled**, **Audit**, or **Block** mode. Microsoft recommends a phased rollout: Audit first, then Block.

| GUID | Rule Name | Recommended Mode | ATT&CK Technique |
|---|---|---|---|
| 56a863a9-875e-4185-98a7-b882c64b5ce5 | Block abuse of exploited vulnerable signed drivers | Block | T1068 |
| 7674ba52-37eb-4a4f-a9a1-f0f9de6f2d1c | Block Adobe Reader from creating child processes | Block | T1204.002 |
| d4f940ab-401b-4efc-aadc-ad5f3c50688a | Block all Office applications from creating child processes | Block | T1566.001 |
| 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Block credential stealing from the Windows local security authority subsystem (lsass.exe) | Block | T1003.001 |
| be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Block executable content from email client and webmail | Block | T1566 |
| 01443614-cd74-433a-b99e-2ecdc07bfc25 | Block executable files from running unless they meet a prevalence, age, or trusted list criterion | Audit first, then Block | T1204 |
| 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Block execution of potentially obfuscated scripts | Block | T1027 |
| d3e037e1-3eb8-44c8-a917-57927947596d | Block JavaScript or VBScript from launching downloaded executable content | Block | T1059.007 |
| 3b576869-a4ec-4529-8536-b80a7769e899 | Block Office applications from creating executable content | Block | T1137 |
| 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 | Block Office applications from injecting code into other processes | Block | T1055 |
| 26190899-1602-49e8-8b27-eb1d0a1ce869 | Block Office communication application from creating child processes | Block | T1566.001 |
| e6db77e5-3df2-4cf1-b95a-636979351e5b | Block persistence through WMI event subscription | Block | T1546.003 |
| d1e49aac-8f56-4280-b9ba-993a6d77406c | Block process creations originating from PSExec and WMI commands | Block | T1047, T1569.002 |
| 33ddedf1-c6e0-47cb-833e-de6133960387 | Block rebooting machine in Safe Mode (preview) | Block | T1562.009 |
| b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | Block untrusted and unsigned processes that run from USB | Block | T1091 |
| c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb | Block use of copied or impersonated system tools (preview) | Block | T1036.003 |
| a8f5898e-1dc8-49a9-9878-85004b8a61e6 | Block Webshell creation for Servers | Block | T1505.003 |
| 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b | Block Win32 API calls from Office macros | Block | T1106 |
| c1db55ab-c21a-4637-bb3f-a12568109d35 | Use advanced protection against ransomware | Block | T1486 |

**PowerShell deployment — enable all rules in Block mode:**

```powershell
# Enable ALL recommended ASR rules in Block mode via PowerShell
# Requires Windows Defender / MDE with appropriate license
$rules = @(
    '56a863a9-875e-4185-98a7-b882c64b5ce5',  # Vulnerable signed drivers
    '7674ba52-37eb-4a4f-a9a1-f0f9de6f2d1c',  # Adobe Reader child processes
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a',  # All Office child processes
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',  # LSASS credential stealing
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',  # Email executable content
    '01443614-cd74-433a-b99e-2ecdc07bfc25',  # Executable prevalence check
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc',  # Obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d',  # JS/VBS executable launch
    '3b576869-a4ec-4529-8536-b80a7769e899',  # Office executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',  # Office code injection
    '26190899-1602-49e8-8b27-eb1d0a1ce869',  # Office comm child processes
    'e6db77e5-3df2-4cf1-b95a-636979351e5b',  # WMI persistence
    'd1e49aac-8f56-4280-b9ba-993a6d77406c',  # PSExec/WMI process creation
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',  # Unsigned USB processes
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',  # Win32 API from Office macros
    'c1db55ab-c21a-4637-bb3f-a12568109d35'   # Ransomware protection
)
foreach ($rule in $rules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule `
                     -AttackSurfaceReductionRules_Actions Enabled
}
# Verify current state
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
```

**ASR exclusion guidance (from Microsoft):** Exclude by specific file path only — not by extension. Example: `C:\Program Files\VendorApp\app.exe`. Broad exclusions (e.g., entire `C:\Users`) significantly reduce protection.

**Intune OMA-URI for ASR (example — Block Office child processes):**
- OMA-URI: `./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules`
- Data type: String
- Value: `d4f940ab-401b-4efc-aadc-ad5f3c50688a=2` (2 = Block, 1 = Audit, 0 = Disabled)

---

### Microsoft Defender Antivirus Policy Settings

*Source: https://learn.microsoft.com/en-us/defender-endpoint/next-generation-protection-overview*

| Setting | Recommended Value | Notes |
|---|---|---|
| Cloud-delivered protection | Enabled — High+ level | Enables cloud lookup for unknown files |
| MAPS reporting | Advanced MAPS | Sends full telemetry for cloud analysis |
| Automatic sample submission | Send safe samples (or All samples) | Required for cloud analysis to function |
| Real-time protection | Enabled | Never disable in production |
| Scan all downloaded files | Enabled | Default on; verify via policy |
| PUA protection | Block | Potentially unwanted application blocking |
| Network protection | Block (after Audit period) | Audit mode recommended for first 30 days |
| Controlled folder access | Enabled | Define protected folder list |
| Tamper protection | Enabled | Prevents local policy changes; cannot be disabled via PowerShell once set via Intune |
| Archive scanning | Enabled | Scan inside ZIP, RAR, etc. |
| Email scanning | Enabled | Scan .eml, .msg files |
| Scan mapped network drives | Enabled | May impact performance; test first |

**PowerShell verification:**

```powershell
Get-MpPreference | Select-Object `
    CloudBlockLevel,
    MAPSReporting,
    SubmitSamplesConsent,
    DisableRealtimeMonitoring,
    DisableIOAVProtection,
    PUAProtection,
    EnableNetworkProtection,
    EnableControlledFolderAccess,
    DisableTamperProtection
```

**Network protection modes:** 0 = Disabled, 1 = Block, 2 = Audit

**Controlled Folder Access modes:** 0 = Disabled, 1 = Enabled (Block), 2 = Audit, 3 = Block disk modification only, 4 = Audit disk modification only

---

### Microsoft Secure Score — High-Impact Recommendations

*Source: https://security.microsoft.com/securescore (Microsoft 365 Defender portal)*

| Recommendation | Approx. Points | Implementation |
|---|---|---|
| Block legacy authentication (Conditional Access) | +10 | CA policy: block when client app = Exchange ActiveSync / other legacy |
| Require MFA for all users | +9 | CA policy: require MFA for all cloud apps, all users |
| Enable SSPR (Self-Service Password Reset) | +3 | Azure AD > Password reset |
| Require MFA for Azure management | +3 | CA policy: target Azure Management app |
| Sign-in risk policy (Identity Protection P2) | +5 | CA policy: block high-risk, require MFA for medium |
| User risk policy | +4 | CA policy: require password change on high user risk |
| Enable Defender for Office 365 Safe Links | +5 | MDO policy: rewrite and check all URLs |
| Enable Defender for Office 365 Safe Attachments | +4 | MDO policy: Block mode |
| Enable DKIM signing | +5 | Exchange admin center > DKIM |
| Designate more than one global admin | +1 | Reduces single point of failure |
| Do not expire passwords | +1 | Microsoft research shows regular expiry reduces security |
| Require MFA for admins | +10 | CA policy scoped to admin roles |

---

## CrowdStrike Falcon Prevention Policies

*Source: CrowdStrike documentation — falcon.crowdstrike.com/documentation*

### Policy Architecture

Prevention Policies are assigned to **Host Groups**. Each policy is a collection of toggle settings grouped into categories. The recommended approach is a **ring-based rollout**: pilot group (IT/security), broad group, then all endpoints.

### Malware Protection Settings — Recommended Production Values

| Setting Category | Setting | Recommended Value | Notes |
|---|---|---|---|
| Sensor Anti-Malware | Cloud Anti-Malware Detection | Aggressive | Cloud ML lookup on every unknown executable |
| Sensor Anti-Malware | Cloud Anti-Malware Prevention | Aggressive | Block based on cloud verdict |
| Sensor Anti-Malware | Adware and PUP Detection | Moderate | Alert on PUP |
| Sensor Anti-Malware | Adware and PUP Prevention | Moderate | Block PUP |
| Sensor Anti-Malware | On-Sensor Machine Learning Detection | Aggressive | Local ML model; no cloud required |
| Sensor Anti-Malware | On-Sensor Machine Learning Prevention | Aggressive | Never set to Disabled in production |
| Sensor Anti-Malware | Quarantine | Enabled | Auto-quarantine all ML/cloud detections |
| Sensor Anti-Malware | Sensor Visibility Enhancement | Enabled | Sends additional telemetry to cloud |

### Exploit Protection Settings

| Setting | Recommended | Description |
|---|---|---|
| Heap Spray Preallocation | Enabled | Blocks exploit heap spray techniques |
| Null Page Allocation | Enabled | Prevents null pointer dereference exploits |
| SEH Overwrite Protection | Enabled | Structured Exception Handler overwrite protection |
| UASLR | Enabled | Upward Address Space Layout Randomization |
| SEHOP | Enabled | SEH Overwrite Protection at OS level |
| Stack Cookie (Stack Canary) | Enabled | Detects stack buffer overflow |
| Force ASLR | Enabled | Forces ASLR on all modules, even non-ASLR-compiled binaries |
| Bottom Up ASLR | Enabled | Randomizes bottom-up allocations |
| Export Address Filtering | Enabled | Prevents export table abuse (API hammering) |
| Import Address Filtering | Enabled | IAT hooking prevention |
| Heap Integrity Protection | Enabled | Detects heap corruption |
| Deny Loading of Suspicious Modules | Enabled | Blocks known suspicious DLLs |

### Indicators of Attack (IOA) — Behavioral Prevention

| IOA Category | Recommended Setting | Priority |
|---|---|---|
| Process Hollowing | Prevent | Critical — common post-exploitation technique |
| Credential Dumping | Prevent | Critical — catches LSASS access attempts |
| AMSI Bypass | Prevent | High — blocks PowerShell AMSI disablement |
| Suspicious Scripts | Prevent | High |
| Suspicious PowerShell Commands | Prevent and Kill | High |
| PowerShell Downgrade Attack | Prevent | Medium — blocks -Version 2 flag |
| Code Injection | Prevent | Critical |
| Bootloader | Prevent | High — blocks MBR/VBR modification |
| COM Class Hijacking | Prevent | Medium |
| Suspicious Registry Operations | Prevent | Medium |
| Exploitation | Prevent | Critical |
| Drive-by Download | Prevent | High |
| Malicious PowerShell Interpreter | Prevent and Kill | High |

### Recommended Deployment Phases

| Phase | Duration | Configuration | Goal |
|---|---|---|---|
| 1 — Detection Only | 2–4 weeks | All settings: Detect/Audit only | Baseline FP rate, identify exclusions needed |
| 2 — Moderate Prevention | 2–4 weeks | Conservative ML + Exploit: Prevent; IOAs: Detect | Validate exclusions, catch high-confidence threats |
| 3 — Aggressive Prevention | Ongoing | All ML/Exploit: Aggressive; all IOAs: Prevent | Full protection posture |

---

## SentinelOne Prevention Policies

*Source: SentinelOne Knowledge Base — support.sentinelone.com*

### Policy Modes

| Mode | Behavior |
|---|---|
| Detect | Alert only; no automatic remediation; threat is logged |
| Protect | Alert + automatic block, quarantine, or kill process |
| Detect + Protect | Behavioral detection with automatic remediation on trigger |

### Recommended Policy Settings

| Setting | Mode | Notes |
|---|---|---|
| Static AI — Malicious | Protect | ML model scores known and variant malware at write-time |
| Static AI — Suspicious | Detect (promote to Protect after tuning) | Higher FP potential; tune exclusions first |
| Behavioral AI — Malicious | Protect | Runtime behavioral analysis |
| Behavioral AI — Suspicious | Protect | Lower confidence behavioral detections |
| Anti-Exploit | Protect | Memory exploit techniques (ROP, heap spray, shellcode) |
| Anti-Ransomware | Protect + Auto Remediate | Includes volume shadow copy protection |
| Remote Shell | Protect | Blocks unauthorized remote shell connections |
| On-Write Static Analysis | Enabled | Scan every new or modified file at write time |
| Scan New Agents | Enabled | Full system scan on first agent enrollment |
| Network Quarantine for Threats | Enabled | Automatically isolates endpoint on active threat |
| Deep Visibility | Enabled | Full telemetry for threat hunting queries |

### Agent Mitigation Actions (Least to Most Disruptive)

```
Alert
  -> Alert + Quarantine File
    -> Alert + Kill Process
      -> Alert + Remediate (rollback)
        -> Alert + Network Quarantine (isolate endpoint)
```

**Auto-remediation (rollback):** SentinelOne takes VSS snapshots before execution and can revert filesystem changes from ransomware even after encryption begins.

### Exclusion Best Practices

- Exclude by **path + certificate** combination, not by path alone
- Never exclude entire drives or system directories
- Use **scope** exclusions (interoperability) for trusted security software (AV, backup agents)
- Review exclusion list quarterly; remove stale entries

---

## Palo Alto Networks Security Profiles

*Source: PAN-OS Administrator's Guide — docs.paloaltonetworks.com*

### Antivirus Profile — Recommended Security Settings

```
Profile: Clone from predefined "strict" profile

Per-application, per-direction settings:
  Action:
    virus:          reset-both   (drops the session; more effective than alert)
    wildfire-virus: reset-both
    spyware-DNS:    sinkhole + block-ip
  File Types: all (PE, Office, PDF, scripts, archives)
  Applications: any
  Decoders: HTTP, HTTPS, SMTP, IMAP, POP3, FTP, SMB
```

**Inline ML (PAN-OS 10.1+):** Enable for real-time file analysis without WildFire submission latency. Set to `enable` for: PE files, PowerShell, ELF.

### Anti-Spyware Profile — Recommended Settings

| Threat Severity | Action | Additional |
|---|---|---|
| Critical | block-ip (duration: 300s) + reset-both | Immediate block of source IP |
| High | block-ip (duration: 30s) + reset-both | |
| Medium | drop | Silent drop, no RST |
| Low | alert | Log only |
| Informational | allow | |

**DNS Security (requires subscription):**
- Enable all DNS security categories
- Block categories: malware, phishing, C2, dynamic-dns, newly-registered-domains, grayware
- Passive DNS Monitoring: Enabled
- DNS Sinkhole: Enabled with dedicated internal sinkhole IP (e.g., `10.0.0.99`) that logs all queries

### Vulnerability Protection Profile

| Setting | Value | Notes |
|---|---|---|
| Critical CVEs with active exploits | block-ip (30s) + reset-both | Treat like a firewall block |
| High CVEs | reset-both | Session tear-down |
| Medium CVEs | alert then block after 30 days | |
| Brute force protection | Enabled | Threshold: 5 attempts / 30s -> block-ip 300s |
| Packet capture | single-packet on alert; extended on block | Forensic evidence for SOC |

### URL Filtering Profile

**Block (not Alert) these categories:**

```
command-and-control
malware
phishing
hacking
dynamic-dns
newly-registered-domains (NRDs — 30 days old or less)
proxy-avoidance-and-anonymizers
cryptocurrency
unknown (review by category first)
```

**Alert (for visibility) — review for potential block:**
```
high-risk
peer-to-peer
gambling
adult
```

**Safe search enforcement:** Enable for search engines (Google, Bing, Yahoo) — append `&safe=strict` at the URL category level.

### WildFire Analysis Profile

| Setting | Recommended Value |
|---|---|
| Forward file types | All (PE, Office, PDF, APK, ELF, scripts, archives) |
| Forward for | All applications |
| Analysis | public-cloud + private-cloud (if WF Appliance licensed) |
| Real-time WildFire | Enabled (requires subscription) |
| Block on timeout | Yes — hold file until verdict received |

---

### Cortex XDR Prevention Profiles

*Source: Cortex XDR Administrator Guide — docs-cortex.paloaltonetworks.com*

| Module | Setting | Recommended Value |
|---|---|---|
| Behavioral Threat Protection (BTP) | Mode | Block |
| Anti-Ransomware Protection | Mode | Block + Restore (auto-restore encrypted files) |
| Child Process Protection | Scope | Block Office, Adobe, email clients spawning shells |
| Shellcode Protection | Mode | Block |
| DLL Hijacking Protection | Mode | Block |
| Credential Gathering Protection (LSASS) | Mode | Block |
| Kernel Exploit Protection | Mode | Block |
| Java Deserialization Protection | Mode | Block |
| .NET Deserialization Protection | Mode | Block |
| Cryptominer Protection | Mode | Block |
| Local Privilege Escalation | Mode | Block |

**Cortex XDR Agent Hardening Policy (recommended):**
- Enable tamper protection on the agent
- Require agent uninstall password
- Block agent service termination from non-admin processes

---

## Proofpoint Email Security Policies

*Source: Proofpoint documentation — help.proofpoint.com*

### Targeted Attack Protection (TAP) Settings — Enterprise

| Feature | Setting | Recommended Value |
|---|---|---|
| URL Defense | URL rewriting | Rewrite ALL URLs (not just suspicious) |
| URL Defense | Click-time protection | Enabled — check at click, not just at delivery |
| URL Defense | Block on timeout | Block (do not deliver if sandbox times out) |
| Attachment Defense | Block on timeout | Block (default is deliver — change this) |
| Attachment Defense | Password-protected archives | Block (unknown content cannot be analyzed) |
| Attachment Defense | Sandbox all Office/PDF/EXE | Enabled |
| Impostor/BEC | Display name spoofing | Block |
| Impostor/BEC | Lookalike domains | Block (edit distance <= 2 from your domain) |
| Impostor/BEC | Newly registered domain links | Block (< 30 days old) |

### Spam and Bulk Mail Thresholds

Proofpoint uses a 0–100 spam confidence score. Higher = more confident it is spam.

| Mail Type | Recommended Action | Threshold Notes |
|---|---|---|
| Spam | Quarantine or Tag | Score threshold: 75 (default 90 — lower = more aggressive) |
| Bulk Mail | Quarantine | Bulk threshold: 90 |
| Phish | Block (reject or high-risk quarantine) | Never just deliver with tag |
| Malware | Block and delete | Never quarantine — delete immediately |
| Impostor (BEC) | Quarantine with notification to security team | High-risk — always notify |
| Suspected Spam | Tag subject line | Lower-confidence threshold |

### Email Authentication Policy Actions

| Authentication Result | Recommended Action |
|---|---|
| SPF Hard Fail (-all) | Quarantine |
| SPF Soft Fail (~all) | Tag or Quarantine |
| DMARC Reject | Reject |
| DMARC Quarantine | Quarantine |
| DKIM fail only (no DMARC/SPF) | Deliver with tag (DMARC is primary signal) |
| No authentication (no SPF/DKIM/DMARC) | Scrutinize — often malicious for corporate email |

### VIP/Impostor Protection Rules

```
Rule: Block emails impersonating VIP list (Executive Protection)
  Match: From display name contains CEO/CFO/CISO name
  AND: from_domain != yourdomain.com
  Action: Block + Alert security team

Rule: Block lookalike domains
  Match: Envelope FROM domain Levenshtein distance <= 2 from yourdomain.com
  Action: Block

Rule: Newly Registered Domain links
  Match: URL domain registered < 30 days ago
  Action: Block URL / sandbox
```

---

## Zscaler Internet Access (ZIA) Policies

*Source: Zscaler Help Portal — help.zscaler.com/zia*

### URL Category Blocking — Recommended Production Defaults

**Block these categories (no user override):**

| Category | Reason |
|---|---|
| Malware Sites | Active malware distribution |
| Phishing Sites | Credential harvesting |
| Botnet | C2 communication |
| Newly Registered Domains (NRDs) | High attacker infrastructure usage with 30-day threshold |
| Peer-to-Peer (P2P) | Data exfiltration vector, policy violation |
| Anonymizers / Proxies | Security control bypass |
| Cryptocurrency Mining | Resource abuse |
| Dynamic DNS Providers | Common attacker infrastructure |
| Spyware / Adware | Malware-adjacent |

**Caution — Audit before Block:**

| Category | Notes |
|---|---|
| Hacking | May block legitimate security research and vendor sites |
| Unknown | High false positive potential; use caution page first |

### SSL Inspection Policy

| Traffic Type | Inspection | Reason |
|---|---|---|
| General web traffic | Inspect | Malware hides in HTTPS |
| Health / Medical (HIPAA) | Bypass | Regulatory compliance |
| Financial / Banking (PCI) | Bypass | Certificate pinning, compliance |
| Security vendor updates | Bypass | Avoid breaking update channels |
| Certificate-pinned apps | Bypass | Microsoft Teams, Salesforce, etc. |
| Windows Update / Apple / Google | Bypass | Prevent breaking OS updates |

**Minimum SSL inspection requirements:**
- Deploy Zscaler root CA to all endpoints via GPO / MDM
- Enable: Full SSL inspection with certificate validation
- Validate: `openssl s_client -connect target.com:443 | openssl x509 -noout -issuer`

### Advanced Threat Protection Settings

| Threat Type | Recommended Action |
|---|---|
| Malware | Block |
| Phishing | Block |
| Ransomware | Block |
| Botnets / C2 | Block |
| Adware | Block |
| Crypto Mining | Block |
| Suspicious Content | Block or Quarantine |
| IPS signatures | Enable all — IPS block mode after 2-week audit period |

**Sandbox (Zscaler Cloud Sandbox):**
- Submit: All unknown executables and Office documents
- Block on: Malicious verdict
- Action on timeout: Hold (caution page) or Block

### Cloud Firewall Recommended Rules

```
Rule 1: Allow standard user traffic
  Source: All users
  Protocol: TCP/UDP 80, 443
  Action: Allow via ZIA

Rule 2: Block non-HTTP/S outbound from endpoints
  Source: User endpoints
  Destination: Any
  Protocol: Any except TCP 80, 443, 53
  Action: Block + Log
  Reason: Prevents C2 over alternate ports (IRC, custom TCP, etc.)

Rule 3: Block suspicious ICMP
  Protocol: ICMP types != echo request/reply
  Action: Block
  Reason: ICMP tunneling prevention

Rule 4: Allow DNS to ZIA resolvers only
  Source: Endpoints
  Destination: ZIA DNS resolvers
  Protocol: UDP/TCP 53
  Action: Allow
  Block all other DNS destinations (prevents DNS-over-HTTPS bypass)
```

---

## CISA SCuBA (Secure Cloud Business Applications) Policies

*Source: https://www.cisa.gov/resources-tools/services/scuba — official CISA guidance*

### Microsoft 365 Baseline Assessment — ScubaGear

ScubaGear is CISA's official open-source assessment tool for M365 tenants.

**Installation and run:**

```powershell
Install-Module -Name ScubaGear -Scope CurrentUser
Import-Module ScubaGear
Invoke-SCuBA -ProductNames teams,exo,defender,aad,powerplatform
# Output: HTML report + JSON results in ./ScubaResults/
```

**GitHub:** https://github.com/cisagov/ScubaGear

### Key CISA M365 Mandatory Policies

| Policy ID | Control | Requirement |
|---|---|---|
| AAD-01 | Legacy authentication | MUST be blocked via Conditional Access |
| AAD-02 | High-risk sign-ins | MUST require MFA (Identity Protection P2) |
| AAD-03 | High-risk users | MUST require password change |
| AAD-04 | Privileged roles | MUST require phishing-resistant MFA (FIDO2/CBA) |
| Defender-01 | Common attachment types | MUST be blocked in Exchange anti-malware policy |
| Defender-02 | Safe Links | MUST be enabled with real-time URL scanning |
| Defender-03 | Safe Attachments | MUST be in Block mode (not just Dynamic Delivery) |
| Defender-04 | Anti-phishing | MUST enable impersonation protection for key domains |
| EXO-01 | Email authentication | SPF, DKIM, and DMARC MUST be configured and enforced |
| EXO-02 | DMARC policy | MUST be p=reject or p=quarantine for your domain |
| Teams-01 | External access | MUST restrict to approved domains only |
| Teams-02 | Anonymous join | MUST NOT allow anonymous meeting join without lobby |

### Google Workspace Baseline

*Source: CISA Google Workspace SCuBA Baseline — github.com/cisagov/ScubaGear*

| Control | Requirement |
|---|---|
| 2-Step Verification | MUST enforce for all users |
| Less Secure Apps | MUST be blocked (no basic auth to Gmail/APIs) |
| Advanced Protection Program | SHOULD enable for high-value accounts |
| DLP Rules | MUST configure for sensitive data types (SSN, credit card, PHI) |
| Email authentication (SPF/DKIM/DMARC) | MUST be enforced; DMARC p=reject recommended |
| Third-party OAuth apps | MUST restrict to admin-approved apps only |
| Google Drive sharing | SHOULD restrict external sharing to specific domains |
| Context-aware access | SHOULD require compliant device for sensitive apps |

---

## NSA/CISA Hardening Guidance

*Source: NSA Cybersecurity Technical Reports — media.defense.gov*

### NSA Top Ten Cybersecurity Mitigation Strategies

From NSA's "Top Ten Cybersecurity Mitigations" (NSA-CISA joint advisory — media.defense.gov):

| Rank | Mitigation | Implementation Notes |
|---|---|---|
| 1 | Update and patch operating systems and software | Patch within CISA KEV timelines; use WSUS/MECM/Intune |
| 2 | Implement multi-factor authentication | Phishing-resistant MFA (FIDO2) for privileged access; TOTP minimum for all users |
| 3 | Grant least privilege; disable unnecessary accounts | Review quarterly; disable guest, default, stale service accounts |
| 4 | Use email, DNS, and web filtering | Anti-phishing + DNS RPZ + web category filtering |
| 5 | Disable macro scripts | GPO: disable all macros or allow only signed macros |
| 6 | Apply application allowlisting | WDAC (preferred) or AppLocker; deny-all, allow-by-exception |
| 7 | Implement host-based intrusion detection | EDR (MDE, CrowdStrike, S1) + HIDS (Wazuh, OSSEC) |
| 8 | Use encryption protocols and VPNs | TLS 1.2+ only; disable SSL 3.0, TLS 1.0/1.1 |
| 9 | Secure hardware and software configurations | CIS Benchmarks, DISA STIGs, secure baseline images |
| 10 | Conduct regular backups | 3-2-1 rule; test restore quarterly; immutable/air-gapped backup |

### NSA PowerShell Security Guidance

*Source: NSA/CISA Cybersecurity Information Sheet "Keeping PowerShell: Security Measures to Use and Embrace" — media.defense.gov*

**Key finding:** NSA recommends keeping PowerShell — removing it forces attackers to use other LOLBins with less logging. PowerShell v5.1+ has AMSI, Script Block Logging, and module logging built in.

| Control | Implementation | Registry / GPO Path |
|---|---|---|
| Use PowerShell 5.1+ | Block PS v2 execution | Feature: MicrosoftWindowsPowerShellV2Root |
| Enable Script Block Logging | Log all executed code blocks | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1` |
| Enable Module Logging | Log all module commands | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging = 1` |
| Enable Transcription | Write all PS sessions to file | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting = 1` |
| Transcription output directory | Central network share (read-only from endpoint) | `OutputDirectory = \\\\siem-share\\pstranscripts\\` |
| Constrained Language Mode | Restrict .NET, COM, type acceleration | Enforced via WDAC (preferred) or AppLocker |

**Disable PowerShell v2 (no AMSI, no logging):**

```powershell
# Disable PowerShell v2 — requires restart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart

# Verify disabled
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
# State should be: Disabled
```

### CISA Known Exploited Vulnerabilities (KEV) Remediation

*Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog*

CISA BOD 22-01 requires federal agencies to remediate KEV entries within defined timelines. Non-federal organizations should treat KEV as a priority patching signal.

**Patch timelines:**
- KEV-listed CVEs: 2 weeks for federal agencies under BOD 22-01
- Critical/exploited CVEs not in KEV: 30 days (CISA recommendation)
- High CVEs: 60 days

**KEV API for continuous monitoring:**

```bash
# Pull all KEV entries with due dates after Jan 1, 2024
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '.vulnerabilities[] | select(.dueDate >= "2024-01-01") |
      {cveID, vendorProject, product, vulnerabilityName, dueDate, requiredAction}'

# Count by vendor — see which vendors have most exploited CVEs
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | \
  jq '[.vulnerabilities[].vendorProject] | group_by(.) | map({vendor: .[0], count: length}) | sort_by(-.count) | .[0:10]'
```

---

## Elastic Security Detection Rules

*Source: github.com/elastic/detection-rules — official Elastic Security repository*

The Elastic detection-rules repository is the authoritative source for production-ready Elastic SIEM rules, maintained by the Elastic Security Research team.

**Installation:**

```bash
git clone https://github.com/elastic/detection-rules
cd detection-rules
pip install -r requirements.txt
# Upload to Kibana (requires API key)
python -m detection_rules kibana upload-rule rules/ --space default
```

### Key Detection Rule Categories

**Credential Access:**
- LSASS Memory Dump Handle Access (Mimikatz, ProcDump patterns)
- Attempted Private Key or Certificate Theft Event
- Kerberoasting via Impacket
- DCSync via NTDSUtil

**Persistence:**
- Startup Folder Persistence via Unsigned Process
- Registry Run Keys / Startup Folder
- Scheduled Task Created by a Windows Script
- WMI Permanent Event Subscription

**Defense Evasion:**
- Potential Process Injection via PowerShell
- NTDLL Hooking via MapViewOfSection
- Disabling Windows Defender via PowerShell
- Indicator Removal — Clear Windows Event Logs

**Discovery:**
- Network Scanning with NMAP
- Enumeration of Administrator Accounts
- PowerView PowerShell Reconnaissance

**Lateral Movement:**
- Incoming Execution via WMI
- Remote Scheduled Task Creation via RPC
- PsExec Network Connection
- Pass-the-Hash via Mimikatz

### Rule Format (TOML)

```toml
[metadata]
creation_date = "2024/01/01"
maturity = "production"
updated_date = "2024/06/01"

[rule]
author = ["Elastic"]
description = "Detects attempts to dump LSASS memory using procdump."
name = "LSASS Memory Dump via ProcDump"
risk_score = 73
severity = "high"
tags = [
    "Domain: Endpoint",
    "OS: Windows",
    "Use Case: Threat Detection",
    "Tactic: Credential Access",
    "Data Source: Elastic Defend"
]
type = "eql"
query = '''
process where host.os.type == "windows" and event.category == "process" and
  event.type == "start" and
  process.name : ("procdump.exe", "procdump64.exe") and
  process.args : "--ma" and
  process.args : ("lsass", "lsass.exe")
'''

[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"
reference = "https://attack.mitre.org/techniques/T1003/"
```

---

## Splunk Enterprise Security Content Update (ESCU)

*Source: github.com/splunk/security_content — official Splunk Threat Research Team*

ESCU is the official Splunk detection content library maintained by the Splunk Threat Research Team.

### Installation

- **Splunkbase:** Search for "Splunk Security Essentials" and "DA-ESS-ContentUpdate"
- **GitHub:** `git clone https://github.com/splunk/security_content`
- **Content Hub:** Available directly in Splunk Enterprise Security UI

### Content Categories

| Category | Count (approx.) | Description |
|---|---|---|
| Detections | 1,000+ | ATT&CK-mapped analytics with FP filters |
| Baselines | 100+ | Establish normal behavior thresholds |
| Investigations | 100+ | SOC analyst workflows for pivoting |
| Analytic Stories | 100+ | Grouped detection + investigation + baseline per threat |

### Example ESCU Detection (Mimikatz)

```splunk-spl
| tstats `security_content_summariesonly` count
    min(_time) as firstTime
    max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=mimikatz.exe
  by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `detect_mimikatz_with_powershell_filter`
```

### Example ESCU Detection (PowerShell Download Cradle)

```splunk-spl
| tstats `security_content_summariesonly` count
    min(_time) as firstTime
    max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name=powershell.exe
    Processes.process IN ("*DownloadString*","*DownloadFile*","*WebClient*","*Invoke-Expression*","*IEX*")
  by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `suspicious_powershell_download_filter`
```

### Analytic Story Concept

An **Analytic Story** groups related detections, investigations, and baselines around a specific threat scenario.

| Analytic Story | Included Detections | Threat |
|---|---|---|
| Ransomware | 50+ | Precursor activities, execution, encryption, persistence |
| Credential Dumping | 30+ | Mimikatz, DCSync, LSASS access, SAM dump |
| Cobalt Strike | 40+ | Beacon patterns, named pipes, malleable C2 |
| Living Off The Land | 60+ | LOLBin abuse, fileless techniques |
| Active Directory Kerberos Attacks | 25+ | Kerberoasting, AS-REP roasting, Golden Ticket |

---

## Microsoft Sentinel Analytics Rules

*Source: github.com/Azure/Azure-Sentinel — official Microsoft repository*

### Installing Community Content

```bash
# Clone the official repository
git clone https://github.com/Azure/Azure-Sentinel

# Via Azure CLI — deploy a specific ARM template rule
az rest --method PUT \
  --url "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/alertRules/{rule-id}?api-version=2022-01-01-preview" \
  --body @rule.json
```

**Content Hub:** Sentinel UI > Content Hub > browse 200+ vendor solutions and community packs.

### Scheduled Analytics Rule Structure (ARM Template)

```json
{
  "kind": "Scheduled",
  "properties": {
    "displayName": "Suspicious PowerShell Download Cradle",
    "description": "Detects PowerShell commands commonly used to download and execute remote payloads.",
    "severity": "High",
    "enabled": true,
    "query": "SecurityEvent | where EventID == 4688 | where CommandLine has_any ('DownloadString','DownloadFile','WebClient','Invoke-Expression','IEX') | summarize count() by Computer, Account, CommandLine",
    "queryFrequency": "PT1H",
    "queryPeriod": "PT1H",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT5H",
    "suppressionEnabled": false,
    "tactics": ["Execution", "DefenseEvasion"],
    "techniques": ["T1059.001", "T1105", "T1027"],
    "entityMappings": [
      {
        "entityType": "Account",
        "fieldMappings": [{"identifier": "Name", "columnName": "Account"}]
      },
      {
        "entityType": "Host",
        "fieldMappings": [{"identifier": "HostName", "columnName": "Computer"}]
      }
    ]
  }
}
```

### High-Value Sentinel Community Rules

| Rule Name | Severity | Tactic |
|---|---|---|
| Brute force attack against Azure Portal | Medium | Credential Access |
| Anomalous failed logon (ML-based) | Medium | Credential Access |
| DNS events related to mining pools | Medium | Impact |
| User account created and deleted within 10 minutes | Medium | Persistence |
| MFA disabled for a user | Medium | Persistence |
| Rare subscription-level operations in Azure | Medium | Discovery |
| Successful sign-in from non-compliant device | Medium | Initial Access |
| Mass secret retrieval from Azure Key Vault | High | Credential Access |
| Privileged role assigned outside Privileged Identity Management | High | Privilege Escalation |
| NRT — Malicious inbox rule created after suspicious sign-in | High | Persistence |

---

## Official Source Directory

| Vendor / Organization | Content Type | Reference URL |
|---|---|---|
| Microsoft | ASR Rules complete reference | learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference |
| Microsoft | Security Baselines (GPO templates) | microsoft.com/en-us/download/details.aspx?id=55319 |
| Microsoft | Secure Score recommendations | security.microsoft.com/securescore |
| Microsoft | MDE Next-gen protection | learn.microsoft.com/en-us/defender-endpoint/next-generation-protection-overview |
| Microsoft | Sentinel community rules | github.com/Azure/Azure-Sentinel |
| CrowdStrike | Prevention Policy documentation | falcon.crowdstrike.com/documentation/85/prevention-policies |
| SentinelOne | Policy configuration guide | support.sentinelone.com |
| Palo Alto Networks | PAN-OS Administrator's Guide | docs.paloaltonetworks.com/pan-os |
| Palo Alto Networks | Cortex XDR Administrator Guide | docs-cortex.paloaltonetworks.com |
| Proofpoint | TAP and email security docs | help.proofpoint.com/proofpoint-essentials |
| Zscaler | ZIA policy reference | help.zscaler.com/zia |
| CISA | Known Exploited Vulnerabilities Catalog | cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA | SCuBA / ScubaGear tool | github.com/cisagov/ScubaGear |
| CISA | BOD 22-01 | cisa.gov/binding-operational-directive-22-01 |
| NSA | Cybersecurity Technical Reports | media.defense.gov |
| NSA | PowerShell Security guidance | media.defense.gov/2022/Jun/22/2003021689 |
| Elastic | Detection Rules repository | github.com/elastic/detection-rules |
| Splunk | Security Content (ESCU) | github.com/splunk/security_content |
| Sigma | Community detection rules | github.com/SigmaHQ/sigma |
| MITRE | ATT&CK Mitigations | attack.mitre.org/mitigations |
| CIS | CIS Controls v8 | cisecurity.org/controls |
| DISA | STIGs | public.cyber.mil/stigs |
