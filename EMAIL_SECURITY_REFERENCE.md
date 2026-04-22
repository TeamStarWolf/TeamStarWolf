# Email Security Reference

Comprehensive reference for email security architecture, authentication standards, phishing attack techniques, threat detection, and defensive controls.

---

## Email Authentication Standards

### SPF (Sender Policy Framework)

SPF authorizes mail servers to send on behalf of a domain. Published as a TXT DNS record.

```dns
; Basic SPF record
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:sendgrid.net -all

; Mechanisms
; ip4:x.x.x.x/cidr     — authorize IPv4 range
; ip6:x:x:x::/cidr     — authorize IPv6 range
; include:domain        — include another domain's SPF
; a                     — authorize domain's A record IP
; mx                    — authorize domain's MX record IPs
; exists:domain         — pass if domain exists in DNS
; redirect=domain       — use another domain's SPF (replaces current)
; -all   — FAIL all not matched (recommended)
; ~all   — SOFTFAIL (accept but mark)
; ?all   — NEUTRAL (no policy)
; +all   — PASS all (dangerous — never use)

; Test SPF record
nslookup -type=TXT domain.com
dig TXT domain.com
; Online: mxtoolbox.com/spf.aspx, dmarcian.com/spf-survey/
```

**SPF Limitations**: SPF only validates the MAIL FROM (envelope sender), not the From header visible to users. Attackers use this for display name spoofing.

---

### DKIM (DomainKeys Identified Mail)

DKIM adds a cryptographic signature to outbound emails. The private key signs the message; public key is published in DNS for verification.

```dns
; DKIM public key DNS record
; Format: selector._domainkey.domain.com TXT
google._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC..."

; Check DKIM record
dig TXT google._domainkey.example.com
nslookup -type=TXT google._domainkey.example.com

; Verify DKIM signature in email headers
; Look for: DKIM-Signature: v=1; a=rsa-sha256; d=sender.com; s=selector;
; b= is the signature; bh= is the body hash
```

**Key rotation**: Rotate DKIM keys annually or after any suspected compromise. Maintain old key in DNS for ~30 days after rotation (for in-transit messages).

---

### DMARC (Domain-based Message Authentication, Reporting and Conformance)

DMARC ties SPF and DKIM together with a policy for handling failures. Requires either SPF or DKIM to align with the From header domain.

```dns
; DMARC record at _dmarc.domain.com
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; pct=100; adkim=s; aspf=s"

; Key tags:
; p=    — policy: none (monitor), quarantine (spam folder), reject (block)
; rua=  — aggregate report destination (daily XML reports)
; ruf=  — forensic/failure report destination (per-failure, more detail)
; pct=  — percentage of messages policy applies to (start with 10, ramp to 100)
; adkim= — DKIM alignment: s=strict (exact domain match), r=relaxed (subdomain OK)
; aspf=  — SPF alignment: s=strict, r=relaxed

; DMARC deployment progression
; 1. p=none (monitoring only) — receive RUA reports, identify legitimate senders
; 2. p=quarantine pct=10 — quarantine 10% of failures
; 3. p=quarantine pct=100 — quarantine all failures
; 4. p=reject pct=100 — block all unauthenticated mail
```

**Tools**: DMARC Analyzer, dmarcian, Valimail, EasyDMARC — parse RUA reports and show sending sources.

---

### Additional Authentication Standards

**BIMI (Brand Indicators for Message Identification)**
Displays company logo in email clients (Gmail, Apple Mail, Yahoo). Requires DMARC at p=reject and a Verified Mark Certificate (VMC) from DigiCert or Entrust.
```dns
default._bimi.example.com TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"
```

**MTA-STS (Mail Transfer Agent Strict Transport Security)**
Forces TLS for inbound email, preventing STARTTLS downgrade attacks.
```
; .well-known/mta-sts.txt must be served at https://mta-sts.domain.com
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 86400
```

**ARC (Authenticated Received Chain)**
Preserves authentication results through forwarding chains (useful for mailing lists).

---

## Email Attack Techniques

### Business Email Compromise (BEC)

BEC causes > $2.9 billion in annual losses (FBI IC3). No malware — pure social engineering.

**Attack Variants**:
| Type | Method | Target |
|---|---|---|
| CEO Fraud | Impersonate executive | CFO/Finance team — wire transfer |
| Vendor/Supplier Fraud | Compromise vendor email or spoof | AP department — redirect payments |
| Attorney Impersonation | Impersonate legal counsel | Executives — "confidential" instructions |
| W-2 / HR Fraud | Impersonate HR/executive | Employees — tax form theft, payroll diversion |
| Real Estate Wire Fraud | Compromise attorney or realtor | Buyer/seller — redirect closing funds |

**BEC Indicators**:
- Email from personal account (gmail.com) impersonating executive
- Look-alike domain (exec0@c0mpany.com vs exec@company.com)
- Urgency language: "time-sensitive," "wire immediately," "do not call, email only"
- Reply-to address differs from From address
- Requests to bypass normal approval processes

---

### Phishing Attack Taxonomy

| Type | Description | Key Indicators |
|---|---|---|
| Spear Phishing | Targeted, personalized emails using OSINT | References real projects, colleagues, internal terms |
| Whaling | Targets C-suite executives | High-value targets; often BEC variant |
| Vishing | Voice phishing — calls impersonating IT, banks, IRS | Real-time pressure; credential harvesting by voice |
| Smishing | SMS phishing with malicious links | Short links, urgent language, package notifications |
| AiTM Phishing | Attacker-in-the-middle: reverse proxy captures session cookie bypassing MFA | Evilginx2, Modlishka, Microsoft warns about large-scale campaigns |
| Credential Harvesting | Replica login pages for O365, Google, VPN | URL mismatch, HTTP, certificate errors |
| Attachment-based | Malicious Office docs, PDFs, ISOs, LNK files | Macros, embedded exploits, container file abuse |
| QR Code Phishing (Quishing) | QR code in email body — bypass URL scanners | Mobile device credential theft |

---

### AiTM (Attacker-in-the-Middle) Phishing

AiTM phishing proxies legitimate login pages, capturing session cookies and bypassing MFA. Widely used by Scattered Spider, Storm-1167, and financially motivated threat actors.

**How It Works**:
1. Attacker deploys reverse proxy (Evilginx2, Caffeine, EvilProxy) pointing to O365/Google
2. Victim receives phishing link pointing to attacker's proxy
3. Victim authenticates normally (MFA prompt passes through)
4. Attacker captures session cookie → authenticated access without MFA

**Evilginx2 Phishlets**:
```bash
# Popular phishlets for major services
# Microsoft O365, Google, LinkedIn, Dropbox, GitHub, AWS console
# Configured at attacker-controlled domain

# Detection indicators:
# - Login from new IP/geolocation immediately after phishing click
# - Impossible travel (sign-in from city A then city B minutes apart)
# - New device added to account
# - Inbox rules created (attacker covering tracks)
# - Token lifetime unusually short (stolen tokens expire)
```

**Detection**:
```kql
// AiTM detection in Microsoft Sentinel — new IP login + MFA success
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where AuthenticationDetails has "MFA"
| where IPAddress !in (known_corporate_IPs)
| join kind=inner (
    MailboxAuditLog
    | where TimeGenerated > ago(1d)
    | where Operation == "Set-InboxRule"
) on $left.UserId == $right.UserId
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RuleParameters
```

---

## Email Header Analysis

### Reading Email Headers

```
Return-Path: <sender@attacker.com>          # Actual bounce address (envelope sender)
Received: from mail.attacker.com            # SMTP relay chain — READ BOTTOM TO TOP
  by mail.victim.com with SMTP; timestamp
Message-ID: <unique@server.com>             # Unique identifier
From: "CEO Name" <ceo@company.com>          # Visible to recipient (spoofable)
Reply-To: hacker@gmail.com                  # Where replies go (common in BEC)
X-Originating-IP: 198.51.100.4             # Originating client IP (if present)
X-Mailer: Microsoft Outlook 16.0           # Email client used
Authentication-Results: spf=fail;           # SPF/DKIM/DMARC results
  dkim=none; dmarc=fail action=none
X-Spam-Status: Yes, score=8.4             # Spam filter score
```

**Key Analysis Points**:
1. **Received headers** — trace email path from bottom (originating server) to top (your MX)
2. **Return-Path vs From** — mismatch indicates spoofing
3. **Reply-To mismatch** — reply goes elsewhere than From address
4. **Authentication results** — SPF fail, DKIM none/fail, DMARC fail = suspicious
5. **X-Originating-IP** — original sender IP (may be missing for privacy)
6. **Received SPF / DKIM** — check alignment

**Tools**:
- `MxToolbox Email Header Analyzer`: mxtoolbox.com/EmailHeaders.aspx
- `Google Admin Toolbox`: toolbox.googleapps.com/apps/messageheader/
- `Microsoft Message Header Analyzer`: aka.ms/mha
- `mailheader.org` — simple online analyzer

---

## Microsoft Defender for Office 365 (MDO)

### Key Policies

**Anti-Phishing Policy — Recommended Settings**:
```
Impersonation Protection:
  - Enable user impersonation protection: ON (add key executives)
  - Enable domain impersonation protection: ON
  - Enable mailbox intelligence: ON
  - Add trusted senders: [legitimate partners]

Spoof Intelligence:
  - Enable spoof intelligence: ON
  - Action for spoofed senders: Move to Junk

Advanced Phishing Thresholds: 3 (Aggressive) for high-security environments

Safety Tips:
  - Show first contact safety tip: ON
  - Show user impersonation safety tip: ON
  - Show domain impersonation safety tip: ON
```

**Safe Attachments (MDO Plan 1+)**:
```
Policy:
  - Safe Attachments unknown malware response: Block
  - Redirect: ON — send to security team mailbox for investigation
  - Apply Safe Attachments policy if scanning can't complete: ON
  - Safe Attachments for SharePoint, OneDrive, Teams: ON (tenant-wide)
```

**Safe Links (MDO Plan 1+)**:
```
Policy:
  - On: Rewrite URLs; check at click time
  - Real-time URL scanning: ON
  - Apply Safe Links to internal email: ON
  - Do not track user clicks: OFF (keep enabled for investigation)
  - Do not let users click through to original URL: ON (for high-risk users)
  - Safe Links for Office apps: ON
```

### Hunting with MDO

```kql
// Emails with URLs that were detonated as malicious
EmailEvents
| where TimeGenerated > ago(7d)
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction

// Clicks on Safe Links that were blocked
UrlClickEvents
| where TimeGenerated > ago(7d)
| where ActionType == "ClickBlocked"
| summarize count() by NetworkMessageId, AccountUpn, Url
| order by count_ desc

// BEC indicators — new inbox rules post-login
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "New-InboxRule"
| where Application == "Microsoft Exchange Online"
| project TimeGenerated, AccountDisplayName, AccountObjectId, RawEventData
```

---

## Proofpoint Key Settings Reference

*(Complements [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) Proofpoint section)*

### TAP (Targeted Attack Protection) Configuration

**URL Defense**:
```
Rewrite Mode: Aggressive (rewrites all URLs including in plaintext)
URL Analysis: Enable "Follow URL redirects"
Sandbox Detonation: ON for unknown URLs
Time-of-click analysis: ON — check at click, not just delivery
Unscannable: Quarantine (not allow)
```

**Attachment Defense**:
```
Sandbox all Office documents: ON
Sandbox executables: ON
Sandbox archives (ZIP, RAR, 7z): ON — extract and scan contents
Block password-protected archives: Consider per use case
Suspicious URL reputation in attachments: ON
```

### Email Filtering Priority

1. **Connection Policies** (IP reputation — block at MTA level before content analysis)
2. **Anti-Spam** (bulk email, spam classification)
3. **Virus/Malware** (known signatures)
4. **URL Defense** (link rewriting and detonation)
5. **Attachment Defense** (sandboxing)
6. **Targeted Attack / BEC detection** (display name spoofing, lookalike domains)
7. **DLP** (data loss prevention — content inspection)
8. **Quarantine / Delivery** (final disposition)

### Proofpoint DMARC Integration

```
Configure Proofpoint as DMARC processor:
1. DMARC analyzer subscription → add Proofpoint RUA address
2. STS > DMARC Management > configure failure policy enforcement
3. Enable BEC auto-quarantine for p=none domains (catch before DMARC enforcement)
```

---

## Phishing Simulation and Awareness Testing

### GoPhish Setup

```bash
# Install
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip && cd gophish/
chmod +x gophish
./gophish
# Admin UI: https://localhost:3333 (admin / default password shown on first run)

# Configuration
# 1. Sending Profile: SMTP server, from address (match your test domain)
# 2. Landing Page: Clone target login page or use template
# 3. Email Template: Craft lure email, insert {{.URL}} for tracking link
# 4. User Group: Import target users from CSV
# 5. Campaign: Link all above, set schedule

# Metrics collected:
# - Email opened rate
# - Link clicked rate
# - Credentials submitted rate
# - Report rate (users who reported the phish)
```

### Phishing Simulation Metrics and Benchmarks

| Metric | Industry Average | Good Performance | Poor Performance |
|---|---|---|---|
| Phish Click Rate | 14-18% | < 5% | > 30% |
| Credential Submit Rate | 8-12% | < 3% | > 20% |
| Report Rate | 10-15% | > 25% | < 5% |
| Time to Report | — | < 5 minutes | > 30 minutes |

**Simulation Best Practices**:
- Start with baseline (untrained) phishing test to measure starting rate
- Target highest-risk users (finance, HR, executives, IT admins) first
- Use relevant lures (IT password reset, HR benefits, package delivery)
- Provide immediate training for clickers (not shaming — educational)
- Measure improvement over quarterly campaigns
- Include report button (PhishAlarm, Report Phishing button in Outlook)

---

## Email Security Tools and Resources

| Tool | Category | Description |
|---|---|---|
| GoPhish | Phishing Simulation | Open-source phishing platform |
| Evilginx2 | Adversary Simulation | AiTM reverse proxy for red team phishing |
| SwissPost Security | Header Analysis | swisskyrepo.github.io/phishing-faq |
| PhishTool | Phishing Analysis | Automated header and link analysis |
| Browserless | URL Sandbox | Headless browser for URL detonation |
| URLScan.io | URL Analysis | Public URL sandbox with screenshot and network data |
| Hybrid Analysis | Attachment Sandbox | CrowdStrike-backed file sandbox |
| MxToolbox | DNS/Mail Testing | SPF, DKIM, DMARC, blacklist checking |
| mail-tester.com | Deliverability | Test email spam score before campaigns |
| hunter.io | OSINT | Find email addresses for target domains |
| The Harvester | OSINT | Email harvesting from search engines |

## Related Resources
- [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) — Proofpoint, Defender for O365, Zscaler email security
- [Social Engineering Discipline](disciplines/social-engineering.md) — Phishing and pretexting techniques
- [Security Awareness Discipline](disciplines/security-awareness.md) — Phishing simulation programs
- [Threat Actors](THREAT_ACTORS.md) — BEC and phishing threat actors (Scattered Spider, TA453)
- [IR Playbooks](IR_PLAYBOOKS.md) — BEC and phishing incident response procedures
