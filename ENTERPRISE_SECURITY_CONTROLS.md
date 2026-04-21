# Enterprise Security Controls Reference

> Vendor-specific configuration, policy tuning, and detection guidance for major enterprise security platforms.

## Table of Contents
- [1. Web Application Firewall (WAF) Rules](#1-web-application-firewall-waf-rules)
- [2. Microsoft Defender Attack Surface Reduction (ASR) Rules](#2-microsoft-defender-attack-surface-reduction-asr-rules)
- [3. CrowdStrike Falcon Prevention Policies](#3-crowdstrike-falcon-prevention-policies)
- [4. Tanium Modules and Use Cases](#4-tanium-modules)
- [5. Proofpoint Email Security Configuration](#5-proofpoint-email-security)
- [6. Zscaler Internet Access and ZPA](#6-zscaler-internet-access-zia-and-zscaler-private-access-zpa)

---

## 1. Web Application Firewall (WAF) Rules

### WAF Architecture and Modes
- **Detection mode**: Log only (no blocking); use to baseline false positives before enabling block mode
- **Prevention/Block mode**: Block matching requests; requires tuning to avoid false positives
- **Anomaly scoring (ModSecurity/OWASP CRS)**: Accumulate score per request; block if score exceeds threshold (default 5)
- **Deployment**: Reverse proxy in front of web app; CDN-integrated (Cloudflare, Akamai, AWS CloudFront)

### OWASP Core Rule Set (CRS) — Key Rule Groups

| Rule Group | ID Range | Protects Against | Tuning Notes |
|---|---|---|---|
| REQUEST-920 | 920000-920999 | Protocol enforcement (malformed headers, invalid methods) | Low false positives; enable first |
| REQUEST-930 | 930000-930999 | Local file inclusion (LFI) and path traversal | May flag legitimate dotdot in API paths; tune specific URIs |
| REQUEST-931 | 931000-931999 | Remote file inclusion (RFI) | Low false positives; enable early |
| REQUEST-932 | 932000-932999 | Remote code execution (RCE), command injection | May flag DevOps tooling; allowlist CI/CD source IPs |
| REQUEST-933 | 933000-933999 | PHP injection | Only apply to PHP apps; skip for Python/Node/Java stacks |
| REQUEST-941 | 941000-941999 | XSS (cross-site scripting) | High false positives on rich text editors; allowlist CMS endpoints |
| REQUEST-942 | 942000-942999 | SQL injection | Key rule; tune for API endpoints using JSON bodies with SQL-like syntax |
| REQUEST-944 | 944000-944999 | Java application attacks (Log4j, Struts, Spring) | Critical; Log4j JNDI rule 944150 specifically |

### Cloudflare WAF Rules

**Managed Rulesets**
- **Cloudflare OWASP Core Ruleset**: Sensitivity levels (Low/Medium/High); start with Low and increase
- **Cloudflare Managed Ruleset**: Cloudflare-proprietary rules for zero-days and emerging threats (auto-updated)
- **Exposed Credentials Check**: Block known breached credential pairs (credential stuffing defense)

**Custom WAF Rules (Expressions)**
```
# Block Log4j JNDI injection (all fields)
(http.request.uri.query contains "${jndi:" or http.request.headers["user-agent"] contains "${jndi:" or http.request.body contains "${jndi:")

# Block path traversal
(http.request.uri.path contains "../" or http.request.uri.path contains "..\")

# Rate limit login endpoint
(http.request.uri.path eq "/api/login") and rate(10/1m)

# Block country (Russia, North Korea, Iran, China) for non-CDN assets
(ip.geoip.country in {"RU" "KP" "IR" "CN"})

# Challenge suspicious user agents
(http.user_agent contains "sqlmap" or http.user_agent contains "nikto" or http.user_agent contains "Masscan")

# Block empty or missing User-Agent (bots)
(not http.user_agent exists or http.user_agent eq "")
```

**Bot Fight Mode / Super Bot Fight Mode**
- **Verified bots**: Allow Googlebot, Bingbot, etc.
- **Likely automated**: Challenge
- **Definitely automated**: Block
- **JS challenge**: Transparent to real users; blocks headless browsers

### AWS WAF Rules

**AWS Managed Rule Groups (use all for production)**

| Rule Group | ARN | Protects Against |
|---|---|---|
| AWSManagedRulesCommonRuleSet | aws:managed:common | OWASP Top 10 (SQLi, XSS, LFI, RFI) |
| AWSManagedRulesKnownBadInputsRuleSet | aws:managed:known-bad-inputs | Log4j, Spring4Shell, SSRF probes |
| AWSManagedRulesSQLiRuleSet | aws:managed:sqli | SQL injection detection |
| AWSManagedRulesAmazonIpReputationList | aws:managed:amazon-ip-reputation | Tor exit nodes, bots, scanners |
| AWSManagedRulesAnonymousIpList | aws:managed:anonymous-ip | VPN, proxy, Tor anonymizers |
| AWSManagedRulesLinuxRuleSet | aws:managed:linux | Linux-specific LFI and command injection |

**Custom AWS WAF Rules (JSON)**
```json
{
  "Name": "BlockSQLInjectionBody",
  "Priority": 10,
  "Statement": {
    "SqliMatchStatement": {
      "FieldToMatch": {"Body": {}},
      "TextTransformations": [
        {"Priority": 1, "Type": "URL_DECODE"},
        {"Priority": 2, "Type": "HTML_ENTITY_DECODE"}
      ]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockSQLInjectionBody"
  }
}
```

### Azure WAF (Front Door / Application Gateway)

**OWASP 3.2 Rule Sets**
- Enable all rule sets; start in Detection mode; review logs for 2 weeks; switch to Prevention
- Custom exclusions: Exclude specific parameters from specific rules when false positives confirmed
- Bot Manager: Block known bad bots; challenge unknown; allow verified search engine bots

**Azure WAF Custom Rules**
```hcl
# Block by IP range (Terraform)
resource "azurerm_web_application_firewall_policy" "example" {
  custom_rules {
    name      = "BlockMaliciousIPs"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"
    match_conditions {
      match_variables { variable_name = "RemoteAddr" }
      operator           = "IPMatch"
      negation_condition = false
      match_values       = ["203.0.113.0/24", "198.51.100.0/24"]
    }
  }
}
```

### Zscaler Cloud Firewall WAF (covered in Section 6)

---

## 2. Microsoft Defender Attack Surface Reduction (ASR) Rules

ASR rules block specific behaviors commonly used by malware — independent of signature detection. Each rule has three modes: **Off**, **Audit** (log only), **Block**.

### All ASR Rules Reference

| Rule Name | GUID | What It Blocks | Recommended Mode | False Positive Risk |
|---|---|---|---|---|
| Block abuse of exploited vulnerable signed drivers | 56a863a9-875e-4185-98a7-b882c64b5ce5 | Loading unsigned/vulnerable kernel drivers | Block | Low |
| Block Adobe Reader from creating child processes | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c | Adobe Reader spawning child processes | Block | Low |
| Block all Office apps from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a | Word/Excel/PowerPoint spawning child processes | Block | Medium (some macros) |
| Block credential stealing from Windows LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 | Memory reads of lsass.exe | Block | Medium (some AV products) |
| Block executable content from email client and webmail | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 | Attachments from Outlook running executables | Block | Low |
| Block executable files from running unless they meet prevalence, age, or trusted list criteria | 01443614-cd74-433a-b99e-2ecdc07bfc25 | Low-reputation unsigned executables | Block | High (custom/dev tools) |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Obfuscated PowerShell/JS/VBScript | Block | Medium |
| Block JavaScript or VBScript from launching downloaded executable content | d3e037e1-3eb8-44c8-a917-57927947596d | Script-based payload downloading | Block | Low |
| Block Office apps from creating executable content | 3b576869-a4ec-4529-8536-b80a7769e899 | Office apps writing .exe/.dll to disk | Block | Low |
| Block Office apps from injecting code into other processes | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 | Office apps injecting shellcode | Block | Low |
| Block Office communication app from creating child processes | 26190899-1602-49e8-8b27-eb1d0a1ce869 | Outlook spawning child processes | Block | Low |
| Block persistence through WMI event subscription | e6db77e5-3df2-4cf1-b95a-636979351e5b | WMI-based persistence | Block | Low |
| Block process creations originating from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c | PsExec/WMI lateral movement | Block | Medium (admin tasks) |
| Block untrusted and unsigned processes that run from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | USB autorun malware | Block | Low |
| Block Win32 API calls from Office macros | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b | Office macros calling low-level Win32 APIs | Block | Medium |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Ransomware file encryption behaviors | Block | Low |

### ASR Deployment via GPO
```
Computer Configuration > Administrative Templates > Windows Components >
Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction

Policy: Configure Attack Surface Reduction rules
Value name: <GUID>
Value: 0 (Off), 1 (Block), 2 (Audit)
```

### ASR Deployment via Intune (MDM)
```json
{
  "omaSettings": [
    {
      "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules",
      "displayName": "ASR Rules",
      "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|d1e49aac-8f56-4280-b9ba-993a6d77406c=2|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|c1db55ab-c21a-4637-bb3f-a12568109d35=1"
    }
  ]
}
```

### ASR Monitoring (KQL — Microsoft Defender for Endpoint)
```kusto
DeviceEvents
| where ActionType startswith "AsrBlocked"
| summarize count() by ActionType, FileName, FolderPath, DeviceName
| sort by count_ desc
```

---

## 3. CrowdStrike Falcon Prevention Policies

### Prevention Policy Categories

**Sensor-Based Machine Learning (ML)**
- **Sensor ML (on-sensor)**: Real-time ML scoring of executables before execution; works offline
  - Settings: Off / Cautious / Moderate / Aggressive / Extra Aggressive
  - Recommended: Aggressive for most environments; Extra Aggressive for high-security environments
  - Caveat: Extra Aggressive may flag custom internal tooling
- **Cloud ML (cloud-assisted)**: Upload unknown files to CrowdStrike cloud for deeper analysis
  - Settings: Off / Cautious / Moderate / Aggressive
  - Recommended: Aggressive; requires internet connectivity to CrowdStrike cloud

**Behavioral Protection (Indicators of Attack — IOA)**

IOAs are behavior-based detections independent of file signatures. Key prevention categories:

| IOA Category | What It Blocks | Enable? | Notes |
|---|---|---|---|
| Credential dumping | LSASS memory reads, SAM/NTDS.dit dump attempts | Yes | Critical; rarely false positives |
| Lateral movement | PsExec, WMI execution from remote hosts | Yes | May need exclusions for IT admin tools |
| Ransomware prevention | Volume shadow copy deletion, mass file encryption behaviors | Yes | Very high confidence |
| Malicious PowerShell | Encoded commands, AMSI bypass attempts, reflective loading | Yes | Monitor Audit mode first |
| Suspicious process tree | cmd.exe child of Word.exe, PowerShell child of PDF reader | Yes | Test with Audit first |
| Fileless attack prevention | Process hollow, reflective DLL injection, direct syscalls | Yes | High confidence |
| Script-based execution | JavaScript/VBScript executing PE files, mshta.exe abuse | Yes | Low false positives |
| Exploitation detection | Shellcode execution, ROP chain patterns, heap spray | Yes | Low false positives |
| Command and control | Known C2 framework IOAs (Cobalt Strike, Sliver, Havoc patterns) | Yes | High confidence |
| Privilege escalation | SeImpersonatePrivilege abuse, token manipulation, UAC bypass | Yes | Low false positives |

**Endpoint Detection (EDR vs. Prevention)**
- **Prevention (Block)**: Kills process, quarantines file, blocks execution — real-time
- **Detection only**: Generates alert but does not stop execution — use to tune before blocking
- **Sensor tamper protection**: Prevent disabling/uninstalling sensor (requires maintenance token to disable)
- **Reduced functionality mode (RFM)**: Sensor enters degraded mode if OS unsupported; alert on RFM endpoints

### CrowdStrike Exclusions (Best Practices)

**Process Exclusions (use sparingly)**
- Only exclude specific paths, not broad wildcard exclusions like `C:\*`
- Document business justification for every exclusion
- Prefer IOA exclusions over ML exclusions where possible

**Common Legitimate Exclusions Needed**

| Application | Recommended Exclusion Type | Path/Hash |
|---|---|---|
| Security testing (Nessus, Qualys agent) | Process exclusion | Specific scanner executable |
| Custom .NET applications flagged by ML | Hash-based exclusion | Specific binary hash (most precise) |
| Backup software writing many files rapidly | Behavior exclusion | Backup process + path |
| Vulnerability scanners doing credentialed scans | Network exclusion | Scanner IP + port ranges |
| LSASS-touching AV software | Process exclusion with justification | Specific AV process path only |

### CrowdStrike Real Time Response (RTR) Common Commands
```bash
# Enumerate running processes
runscript -Raw=```ps```

# Get network connections
runscript -Raw=```netstat -anob```

# Kill malicious process
kill <PID>

# Quarantine file
quarantine "C:\Users\victim\Downloads\malware.exe"

# Get file from remote host (forensic collection)
get "C:\Windows\Prefetch\MALWARE.EXE-ABC123.pf"

# Run custom PowerShell
runscript -CloudFile="PSInvestigate" -CommandLine="-TargetUser 'victim'"

# Put investigation script on host
put "investigate.ps1"
run "investigate.ps1"
```

### Fusion SOAR Automation (CrowdStrike Workflows)
- **Trigger** on High/Critical detection → auto-contain host (network isolation) → create ServiceNow ticket → notify SOC Slack channel
- **Auto-escalate** ransomware IOAs → immediate contain + page on-call → pull memory dump via RTR
- **Hash-based response**: Unknown hash with ML score >80 + network connection → automated sandbox detonation → update verdict → auto-close or escalate

---

## 4. Tanium Modules

### Core Tanium Platform Architecture
- **Tanium Client**: Lightweight agent on every endpoint; linear chain topology for bandwidth efficiency
- **Tanium Server**: Aggregates results; processes questions; manages modules
- **Question syntax**: `Get [sensor] from all machines with [condition]` — real-time inventory across 100K+ endpoints in seconds

### Tanium Modules Reference

**Tanium Core (Free with Platform)**
- Ask questions: `Get Operating System from all machines` — real-time OS inventory
- Deployed software: `Get Installed Applications containing "Adobe" from all machines where Is Windows equals true`
- Running processes: `Get Process Name[powershell.exe] from all machines` — find all running PowerShell instances
- Logged-in users: `Get Logged In Users from all machines` — useful during incident triage

**Tanium Patch**
- Scan for missing patches (Windows/Linux/macOS)
- Deploy patches in maintenance windows with rollback capability
- Reports: Patch compliance rate by OS, severity, criticality
- Integration: ServiceNow change management for patch deployment tickets

**Tanium Comply**
- CIS Benchmark compliance assessment (Windows, Linux, network devices)
- Custom SCAP/XCCDF/OVAL content support
- Gap reporting: Which benchmarks are failing across which endpoints?
- Remediation: Automated script deployment to fix common compliance failures

**Tanium Discover**
- Identify unmanaged assets on the network (no Tanium agent)
- Network scanning from managed endpoints — no need for central scanner infrastructure
- Asset fingerprinting: OS, open ports, services
- Integration with CMDB: Push discovered assets to ServiceNow

**Tanium Impact**
- Credential and privilege exposure mapping
- Identify endpoints with local admin credentials shared across multiple machines (lateral movement risk)
- Service account exposure: Which accounts have logged in to many endpoints? (PtH risk surface)
- Shadow admins: Identify non-obvious administrative access paths in AD

**Tanium Threat Response (EDR)**
- Real-time IOC scanning: Push YARA rules or hash lists; scan all endpoints in minutes
- Evidence collection: Collect memory dumps, event logs, file artifacts from remote hosts
- Timeline: Process execution history, network connections, file events per endpoint
- Signal/Detection: Alert on behavioral patterns; correlate with CrowdStrike or Microsoft Defender telemetry

**Tanium Protect**
- Application allowlisting (Windows): Block unapproved executables; BYOP (bring your own policy)
- Firewall management: Push host-based firewall rules across all endpoints
- BitLocker management: Report encryption status; enforce and recover keys

**Tanium Live Response (Incident Response)**
- Real-time file system navigation across remote endpoints
- Hash check: Run hash of suspicious file against VirusTotal via Tanium Connect integration
- Remediation playbooks: Automated response actions (delete file, kill process, isolate NIC)

### Tanium Sensor Examples (Power Queries)
```
# Find endpoints with specific process running
Get Running Processes containing "psexec" from all machines

# Find stale accounts logged in to multiple machines (PtH exposure)
Get Logged In Users from all machines where Logged In Users contains "svc_"

# Identify endpoints missing critical patch
Get Missing Patches containing "2023-" where CVSS Score >= 7.0 from all machines where Is Windows equals true

# Find endpoints with specific registry key (persistence hunting)
Get Registry Key Value[HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run] from all machines

# YARA scan for malware across fleet (Threat Response module)
Deploy YARA Rule "Cobalt_Strike_Beacon" to all machines where Is Windows equals true
```

---

## 5. Proofpoint Email Security

### Proofpoint Essentials / Enterprise Architecture
- MX record points to Proofpoint smart host → Proofpoint scans → delivers clean mail to Exchange/O365
- Outbound: Route through Proofpoint for DLP, encryption, IP reputation management
- Continuity: Emergency inbox when primary mail server down

### Spam and Phishing Detection

**Spam Confidence Levels (SCL)**

| Score | Action | Meaning |
|---|---|---|
| 0-49 | Deliver | Clean |
| 50-74 | Deliver with tag [SPAM] in subject | Suspicious |
| 75-89 | Quarantine (user accessible) | Likely spam |
| 90-100 | Quarantine (admin only) or Block | High-confidence spam |

**URL Defense (URL Rewriting)**
- Rewrites all URLs in email to Proofpoint proxy; clicks checked at time of delivery
- Time-of-click analysis: Block if URL changed to malicious after delivery (delayed weaponization)
- Sandbox: Automatically detonate suspicious URLs in isolated browser

**Attachment Defense**
- Sandbox all attachments: Office docs, PDFs, executables, archives
- Dynamic analysis: Detonate in isolated VM; behavioral analysis for macro execution, network connections, file drops
- Suspicious PDF: Auto-convert to safe PDF rendering (remove active content)
- File type blocking: Block `.exe`, `.js`, `.vbs`, `.ps1`, `.bat` attached to email

### DMARC / DKIM / SPF Configuration

**SPF Record**
```dns
v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:203.0.113.10 -all
```
- `-all` = hard fail (reject); `~all` = soft fail (mark); `?all` = neutral (no action — avoid)
- Maximum 10 DNS lookups per SPF evaluation — flattening required for complex setups

**DKIM Configuration**
```dns
# DNS TXT record (selector._domainkey.example.com)
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN...
```
- 2048-bit RSA key minimum; rotate annually
- Sign all outbound email; enable DKIM verification for inbound

**DMARC Record**
```dns
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc-rua@example.com; ruf=mailto:dmarc-ruf@example.com; pct=100; adkim=s; aspf=s"
```
- `p=reject`: Fail DMARC = reject; start with `p=none` → `p=quarantine` → `p=reject`
- `rua`: Aggregate reports (Valimail, Dmarcian, PowerDMARC for analysis)
- `adkim=s`, `aspf=s`: Strict alignment

### Proofpoint Targeted Attack Protection (TAP)

**Very Attacked People (VAP)**
- Identifies employees receiving the most sophisticated targeted attacks
- Use to prioritize security awareness training and additional controls (hardware MFA, additional scrutiny)
- Integrate with CrowdStrike: VAPs get stricter EDR prevention policies

**BEC Defense**
- Impostor email detection: AI/ML detecting display name spoofing, lookalike domains, executive impersonation
- Domain lookalike detection: `paypa1.com`, `microsof.com`, `target-corp.com` alerting
- Business Relationship Intelligence: Maps communication patterns; anomalous senders flagged

### Proofpoint DLP for Email
- Content inspection: Regex patterns for SSN, CCN, PII; custom dictionary
- Policy actions: Quarantine, encrypt, redirect to manager, block delivery
- Encryption: S/MIME or Proofpoint Encryption (PBEO) for sensitive outbound
- Integration: Connects to Information Rights Management (Azure RMS, Microsoft Purview)

---

## 6. Zscaler Internet Access (ZIA) and Zscaler Private Access (ZPA)

### Zscaler Internet Access (ZIA)

**Traffic Forwarding Methods**
- **PAC file**: Browser proxy configuration; suitable for managed devices
- **Zscaler Client Connector (ZCC)**: Agent-based; all traffic; recommended for full coverage
- **IPSec/GRE tunnel**: Site-to-site from branch routers; for non-agent deployments
- **NSS (Nanolog Streaming Service)**: Stream logs to SIEM (Splunk, Sentinel, QRadar)

**ZIA SSL Inspection**
- Decrypt HTTPS traffic for full content inspection; re-encrypt to destination
- Certificate pinning bypass: Apps with pinned certs bypass SSL inspection — add to bypass list
- SSL bypass categories: Banking, healthcare (HIPAA), government (regulated data)
- SSL bypass by URL: `*.internal-app.com` for internal CA-signed apps

**ZIA URL Filtering Policy**

| Category | Default Action | Recommended Action |
|---|---|---|
| Malware sites | Block | Block |
| Phishing sites | Block | Block |
| Botnet communication | Block | Block |
| Newly registered domains | Alert/Caution | Block for 30 days (high risk for phishing) |
| Peer-to-peer | Block | Block |
| Anonymous proxy/Tor | Block | Block |
| Social media | Allow | Allow with DLP inspection |
| Cloud storage (personal) | Allow | Caution or DLP-inspect (exfiltration risk) |
| Streaming media | Allow | Allow (bandwidth management optional) |
| Hacking/proxy avoidance | Block | Block |

**ZIA Advanced Threat Protection**
- **Intrusion Prevention (IPS)**: Signatures for exploits, port scans, protocol anomalies
- **DNS security**: Block malicious domains; DNS tunneling detection
- **Cloud Sandbox**: Detonate unknown files; integrate with CrowdStrike Threat Intelligence
- **Firewall**: App-aware, user-aware policy enforcement (e.g., block Tor for all users except security team)

**ZIA DLP (Data Loss Prevention)**
- ICAP integration: Inspect web traffic for sensitive data patterns
- Exact Data Match (EDM): Fingerprint specific customer/employee data
- Policies: Block upload of SSN/PCI data to personal cloud storage; allow to corporate OneDrive

**ZIA Bandwidth Control**
- Throttle streaming/social media during business hours
- Guarantee bandwidth for critical business apps (Office 365, Zoom, SAP)

### Zscaler Private Access (ZPA)

**ZPA Architecture**
- **App Connector**: Lightweight VM deployed in data center/cloud; outbound-only connections to Zscaler cloud
- **Zscaler Enforcement Node**: Zscaler cloud proxies user → app (no VPN concentrator needed)
- **Access Policy**: User/group + device posture → specific application (not network-level access)

**ZPA Access Policies**
```
Policy: "Contractors can access Web App Portal only"
- Source: User group = "Contractors" AND device posture = "Managed device enrolled in MDM"
- Destination: Application segment = "CorpWebPortal" (defined as https://portal.internal.com:443)
- Action: Allow

Policy: "Deny All except explicitly permitted"
- Source: Any
- Destination: Any
- Action: Deny (default deny at bottom of policy list)
```

**ZPA App Segments vs Application Groups**
- **App Segment**: Defines a specific application (FQDN + port + protocol); mapped to App Connectors
- **Application Group**: Group of App Segments for easier policy management
- **Server Group**: Collection of App Connectors that serve a group of apps

**ZPA Device Trust (Posture)**

| Posture Check | What It Verifies | Use Case |
|---|---|---|
| Device managed by MDM | Intune/Jamf enrollment | Ensure corporate-managed device only |
| CrowdStrike Falcon running | Sensor active, not in RFM | Require EDR before accessing sensitive apps |
| OS version minimum | macOS 13+ / Windows 11 | Block unsupported/vulnerable OS |
| Disk encryption enabled | BitLocker/FileVault on | Ensure data-at-rest protection |
| Screen lock configured | Lock screen timeout <= 5 min | Basic physical security |

**ZPA Integration with IdP**
- SAML 2.0 + SCIM: Sync groups from Okta/Azure AD for policy targeting
- Conditional Access: Require ZPA app session for Entra ID Conditional Access policy
- User risk: Entra ID Identity Protection risk signal → ZPA auto-block high-risk users

### Zscaler Posture Control (CNAPP)
- **Cloud Security Posture Management (CSPM)**: Continuous AWS/Azure/GCP misconfiguration detection
- **Cloud Infrastructure Entitlement Management (CIEM)**: Overpermissive IAM analysis
- **Kubernetes Security Posture Management (KSPM)**: K8s misconfiguration scanning

---

## Related Resources
- [Windows Hardening and GPO Reference](WINDOWS_HARDENING_GPO.md) — GPO-based hardening, attack surface reduction, service disabling
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — Sigma, YARA, and Suricata detection rules
- [Enterprise Infrastructure Reference](ENTERPRISE_INFRASTRUCTURE.md) — enterprise environment components
- [Security Operations](disciplines/security-operations.md) — SOC operations and tooling
- [Zero Trust Architecture](disciplines/zero-trust-architecture.md) — ZT principles and vendor implementation
