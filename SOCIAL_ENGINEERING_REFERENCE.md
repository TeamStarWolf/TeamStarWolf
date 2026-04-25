# Social Engineering Reference

A comprehensive attacker methodology and defender awareness reference covering phishing, vishing, smishing, pretexting, and physical social engineering.

---

## Table of Contents

- [Social Engineering Psychology](#social-engineering-psychology)
- [Phishing (Email)](#phishing-email)
  - [Phishing Taxonomy](#phishing-taxonomy)
  - [Spear Phishing Construction](#spear-phishing-construction)
  - [AiTM Phishing — Technical Deep Dive](#aitm-phishing--technical-deep-dive)
  - [Phishing Simulation Programs](#phishing-simulation-programs)
- [Vishing (Voice Social Engineering)](#vishing-voice-social-engineering)
- [Smishing (SMS Social Engineering)](#smishing-sms-social-engineering)
- [Pretexting](#pretexting)
- [Physical Social Engineering](#physical-social-engineering)
- [Open-Source Intelligence for SE](#open-source-intelligence-for-se)
- [Defense and Detection](#defense-and-detection)
  - [Security Awareness Training Program](#security-awareness-training-program)
  - [Technical Controls Against Social Engineering](#technical-controls-against-social-engineering)
  - [Reporting Culture](#reporting-culture)
- [ATT&CK Mappings](#attck-mappings)

---

## Social Engineering Psychology

Social engineering attacks succeed by exploiting predictable human cognitive patterns rather than technical vulnerabilities. Understanding the psychology behind these attacks is foundational to both executing them in authorized red-team engagements and defending against them.

### Cialdini's 6 Principles of Influence

| Principle | How Attackers Use It | Example |
|---|---|---|
| **Reciprocity** | "I did something for you, now you owe me" | Attacker sends a small gift, then calls asking for access |
| **Commitment / Consistency** | "You said X before, be consistent now" | "You said you value security — that's why I need your help" |
| **Social Proof** | "Everyone else does it" | "All the other employees already completed this verification" |
| **Authority** | "I am IT / legal / the CEO" | Impersonating CISO to demand immediate password reset |
| **Liking** | "We met before / we have common ground" | Name-dropping a mutual colleague found via LinkedIn |
| **Scarcity / Urgency** | "Act now or face consequences" | "Your account will be suspended in 30 minutes" |

### Cognitive Biases Exploited

- **Confirmation bias** — targets accept information that aligns with existing beliefs (e.g., "we did have an IT issue yesterday")
- **Optimism bias** — "this won't happen to me / this caller seems legitimate"
- **Authority bias** — automatic deference to perceived seniority or expertise
- **Action bias under time pressure** — under artificial urgency, people skip verification steps and act reflexively
- **Inattentional blindness** — when focused on one task, people miss anomalies in context

### SE Attack Lifecycle

```
Research (OSINT on target)
    ↓
Pretext Development
    ↓
Initial Contact (email / phone / physical)
    ↓
Rapport Building
    ↓
Exploitation (credential harvest / access / data)
    ↓
Cover Tracks / Exit
```

Each phase maps to ATT&CK Reconnaissance (TA0043), Resource Development (TA0042), and Initial Access (TA0001).

---

## Phishing (Email)

### Phishing Taxonomy

| Type | Target | Method | Example |
|---|---|---|---|
| Generic phishing | Mass audience | Spray and pray | Fake PayPal / bank email |
| Spear phishing | Specific individual | Personalized with OSINT | Fake email from "your manager" |
| Whaling | C-suite executives | High-value target | Fake M&A notification to CEO |
| BEC (Business Email Compromise) | Finance / HR staff | Compromised or spoofed exec | Fake wire transfer request |
| AiTM phishing | MFA bypass | Adversary-in-the-middle proxy | EvilProxy, Modlishka, Evilginx |
| Quishing | Mobile users | QR code → phishing URL | Fake parking meter QR, DocuSign QR |
| Smishing | Mobile users | SMS with malicious link | Fake package delivery SMS |
| Vishing | Phone | Voice social engineering | Fake IT helpdesk call |

### Spear Phishing Construction

**OSINT inputs for personalization:**

- **LinkedIn** — job title, team, manager name, recent posts, current projects, tenure
- **Company website** — org chart, press releases, current initiatives, event calendar
- **Email format discovery** — hunter.io, clearbit, LinkedIn email reveal tools
- **Domain registration / WHOIS** — technology vendors, legal contacts
- **Recent events** — acquisition, security incident, leadership change, layoffs — all create urgency pretexts

**Pretext scenarios by target role:**

| Target Role | Effective Pretexts |
|---|---|
| Finance / AP | Vendor invoice change, urgent wire transfer, audit request |
| IT helpdesk | Password reset, MFA troubleshooting, license activation, phishing alert |
| Executive assistant | Calendar conflict, board document, travel booking change |
| HR staff | New hire onboarding, benefits enrollment, compliance training deadline |
| Developer | GitHub notification, CI/CD alert, package security advisory, npm/pip package |
| Legal | Contract for signature, NDA review, regulatory filing deadline |
| C-suite | M&A document, board packet, investor communication |

**Anatomy of a convincing spear phish:**

1. **Sender spoofing / lookalike domain** — `support@paypa1.com`, `noreply@company-security.com`
2. **Personalized greeting** — full name, correct title, reference to real project
3. **Plausible context** — references recent company event, shared tool, known colleague
4. **Single clear call to action** — one link, one attachment, never multiple requests
5. **Urgency or authority** — time pressure or authority figure cited
6. **Professional formatting** — logo, footer, legal disclaimer matching target company

### AiTM Phishing — Technical Deep Dive

**How it works:** The attacker deploys a reverse proxy (Evilginx / EvilProxy / Modlishka) between the victim and the legitimate Identity Provider. The victim authenticates against the real IdP *through the proxy*, and the attacker captures the post-MFA session cookie — bypassing MFA entirely.

```
Victim browser  →  Attacker proxy (evilginx)  →  Real Microsoft/Google IdP
                         ↑
                  captures session cookie after MFA completes
```

**Evilginx2 workflow:**

```bash
# Start Evilginx2 with phishlets directory
./evilginx -p ./phishlets/ -developer

# Configure in the evilginx interactive console
phishlets hostname o365 login.evil-domain.com
phishlets enable o365
lures create o365
lures get-url 0
# Returns: https://login.evil-domain.com/AbCdEf

# Monitor captured sessions
sessions
sessions 1
```

**What gets captured:**

- Full session token (valid for hours/days depending on IdP policy)
- Username and password (in some phishlet configurations)
- IP address, user agent, timestamp

**Detection signals:**

- Session characteristics mismatch: IP geolocation, user agent, or ASN differs from enrollment
- Entra ID / AAD CAE (Continuous Access Evaluation) can detect token anomalies and revoke mid-session
- Sentinel KQL to correlate successful MFA with token use from a different IP:

```kql
SigninLogs
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project UserId, UserDisplayName, IPAddress, UserAgent, TimeGenerated, SessionId
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | project UserId, IPAddress as TokenUseIP, TimeGenerated as TokenTime, SessionId
) on UserId, SessionId
| where IPAddress != TokenUseIP
| where abs(datetime_diff('minute', TimeGenerated, TokenTime)) < 60
```

**Defenses:**

| Control | Effectiveness |
|---|---|
| FIDO2 / hardware security keys | Phishing-resistant — session cookie not reusable on attacker domain |
| Conditional Access: require compliant device | Session cookie unusable on non-compliant attacker device |
| Entra ID CAE | Token revocation on anomalous conditions mid-session |
| Named location policies | Flag sign-ins from unexpected countries or IPs |
| Token binding (in development) | Would tie tokens to TLS session, defeating proxy theft |

### Phishing Simulation Programs

**GoPhish setup:**

```bash
# Docker deployment
docker pull gophish/gophish
docker run -p 3333:3333 -p 8080:8080 gophish/gophish
# Admin UI: https://localhost:3333 (default admin/gophish)
```

**Campaign components:**

| Component | Purpose |
|---|---|
| Sending Profile | SMTP relay config (SendGrid, SES, or self-hosted postfix) |
| Email Template | HTML email with tracking pixel + link |
| Landing Page | Credential capture or awareness redirect |
| User Group | Target list imported from CSV |

**Metrics tracked:**

- Email Opened (tracking pixel)
- Link Clicked
- Data Submitted (credential entry)
- Report Clicked (if Phish Alert Button integrated)

**Industry benchmarks (Proofpoint State of the Phish 2024):**

- Click rate before awareness training: ~14–17% average
- Click rate after comprehensive training: ~3–5%
- Organizations with simulations + training see ~64% reduction in click rates
- Failure to simulate vishing: 30% of orgs do not simulate voice attacks

**Simulation best practices:**

- Run 6+ campaigns per year minimum with varied pretexts
- Avoid "gotcha" culture — position as learning tools, not performance evaluations
- Deliver immediate just-in-time training on click (not a week later)
- Measure **reporting rate** as the primary success metric, not just click rate
- Rotate pretext categories: IT reset, HR benefit, finance, package delivery, external vendor
- Legal requirements: written authorization from leadership, inform legal / HR / comms teams

---

## Vishing (Voice Social Engineering)

### Common Vishing Pretexts

- **IT helpdesk impersonation** — "I'm from IT, we detected suspicious activity on your account. I need to verify your identity, then walk you through resetting your credentials."
- **Microsoft / Apple tech support scam** — "Your device is sending error reports to our servers. We need remote access to resolve this."
- **Bank fraud department** — "We flagged unusual transactions on your account. To prevent a hold, I need to verify a few details."
- **IRS / Tax authority** — "There are unpaid taxes creating a warrant for your arrest unless resolved immediately with a prepaid card."
- **Vendor / supplier update** — "We're updating our banking details for the upcoming payment. Can you update your records?"
- **Internal audit** — "I'm from corporate audit. I need to verify your current system access before the quarterly review."
- **Recruiter / headhunter** — "I found your profile — can I get your personal email and phone to send over an opportunity?"

### Vishing Attack Flow

```
1. Caller ID spoofing
   └── caller_id_spoofed_as: "Microsoft Support +1-800-642-7676"

2. Urgency / authority establishment
   └── "We need to resolve this in the next 30 minutes before the security team locks the account"

3. Identity verification — gather info, not provide it
   └── "Let me verify you — what's your employee ID and current email?"

4. Escalating information gathering
   └── Username → current password or last used password → MFA code → security questions

5. Remote access request
   └── "Please download this diagnostic tool at support-tool[.]com" (AnyDesk / TeamViewer / ScreenConnect)

6. Persistence / follow-on access
   └── Install RAT, create new admin account, exfiltrate credentials
```

### Voice Cloning (AI-Enhanced Vishing)

Modern tools can generate convincing voice clones from as few as 3 seconds of audio:

| Tool | Notes |
|---|---|
| ElevenLabs | High-quality synthesis from short samples; widely misused |
| Murf AI | Commercial voice studio with cloning capability |
| Resemble AI | Real-time voice cloning API |
| RVC (Retrieval-based Voice Conversion) | Open-source, runs locally |

**Real-world incidents:**

- **$25M Hong Kong deepfake video call (2024)** — finance employee tricked via multi-person deepfake video conference impersonating CFO and colleagues
- **$243K energy company voice clone (2019)** — CEO voice cloned, CFO authorized wire transfer
- **Scattered Spider vishing campaigns (2022–2023)** — extensive helpdesk vishing to reset MFA and gain initial access to MGM, Caesars, and others

**Defenses:**

- **Voice verification code words** — pre-established safe word between caller and recipient
- **Callback verification** — hang up, call the person back at a known, verified number
- **Multi-person authorization** for high-value transactions (wire transfers, account changes)
- **Out-of-band confirmation** — require email confirmation from known address before acting on phone request
- **Employee training** — practice scripts for politely refusing or escalating suspicious calls

---

## Smishing (SMS Social Engineering)

### Common Smishing Templates

- **Package delivery** — "Your USPS package #94001... requires action. Confirm address: [link]"
- **Bank alert** — "ALERT: Unusual activity on your account. Secure it now: [link]"
- **Two-factor request** — "Your verification code is 847291. Never share this code." (sent to prime the victim, then attacker calls asking for it)
- **Gift card / prize** — "You've been selected for a $500 Amazon gift. Claim at: [link]"
- **Gov / IRS** — "IRS: A tax refund of $1,842 is pending your confirmation. Visit: [link]"

### Smishing Technical Methods

- **SIM swapping** — social engineer carrier support to transfer victim's number to attacker SIM; enables MFA bypass
- **SMS spoofing** — tools like Twilio, Sinch, or bulk SMS gateways allow arbitrary sender ID in many countries
- **Smishing kits** — pre-built phishing pages optimized for mobile viewports (16:9 ratio, no desktop elements)

**Defenses:**

- Never click links in unsolicited SMS messages; navigate directly to official site
- Enable SIM lock / SIM PIN at carrier level
- Use authenticator apps rather than SMS-based MFA wherever possible
- Carrier-level spam filtering (T-Mobile Scam Shield, AT&T ActiveArmor)

---

## Pretexting

### Building Believable Pretexts

**Key elements of an effective pretext:**

| Element | Description |
|---|---|
| **Backstory** | Prior email thread fabricated, LinkedIn connection, name of a shared acquaintance, prior vendor relationship |
| **Specific details** | Correct internal project names, real names from org chart, accurate internal terminology and acronyms |
| **Plausible request** | Matches the target's job function and decision authority — don't ask a helpdesk rep to approve a wire transfer |
| **Pressure mechanism** | Urgency, authority, or fear — but calibrated to seem legitimate, not panicked |
| **Exit strategy** | How to disengage without arousing suspicion; leave the target with a plausible explanation |

### OSINT Sources for Pretext Development

| Source | Data Gathered |
|---|---|
| LinkedIn | Job title, team, manager, tenure, skills, recent posts, mutual connections |
| Company website | Org chart, press releases, current initiatives, event calendar, office locations |
| Job postings | Tech stack in use (Active Directory, Workday, ServiceNow, etc.) |
| SEC filings (10-K, 8-K) | Executives, M&A activity, legal matters |
| Pastebin / GitHub leaks | Internal email addresses, credentials, internal URLs |
| Social media | Personal details, family, hobbies — for rapport building |
| Conference talks / papers | Internal projects, team names, tools mentioned publicly |

### Common Pretexts by Scenario

| Scenario | Sample Pretext |
|---|---|
| **New vendor** | "I'm setting up the payment processing for the XYZ contract that Sarah approved last week — can you send over your ACH details?" |
| **IT audit** | "I'm conducting the annual security audit mandated by compliance. I need to verify your current system access and ensure your account is in scope." |
| **Recruiter** | "I found your profile on LinkedIn — would you be open to a confidential discussion? Can I get your personal email?" |
| **IT support** | "We're migrating to a new VPN client. I need your current credentials to verify migration compatibility." |
| **Delivery / maintenance** | Physical access via "HVAC contractor" or "IT equipment delivery needing a signature in the server room" |
| **Legal / compliance** | "We received a regulatory inquiry that includes your department. I need to gather some information before the deadline tomorrow." |
| **Acquisitions** | "This is confidential — we're in due diligence for the ABC acquisition. I need your data exports for the data room." |

---

## Physical Social Engineering

### Tailgating / Piggybacking

**How it works:** An attacker follows an authorized person through a secured door, exploiting social norms around holding doors open.

**Psychological driver:** People feel socially obligated not to challenge someone behind them — challenging someone feels rude, and most employees lack training to do it politely.

**Variants:**

- Carry heavy boxes / equipment (people rush to hold the door)
- Wear delivery/contractor uniform
- Be on the phone (seems busy and legitimate)
- Follow a large group entering during shift change

**Countermeasures:**

- Mantrap / airlock (two-door sequential entry requiring badge at each)
- Turnstiles (one person per badge tap)
- Security guard at entry points
- Employee training: politely challenge anyone not badging in, or call security
- Anti-passback in access control systems (prevents using same badge for second entry without exit)

### Badge Cloning

| Technology | Frequency | Vulnerability | Tools |
|---|---|---|---|
| HID Prox / EM4100 | 125 kHz | No encryption — trivially cloneable | Proxmark3 (`lf hid clone`), Flipper Zero |
| MIFARE Classic | 13.56 MHz | Cryptographic weakness (CRYPTO1 broken) | Proxmark3, ACR122U + mfoc/mfcuk |
| MIFARE DESFire EV1 | 13.56 MHz | Older EV1 has sector-level key issues | Proxmark3 (requires key extraction first) |
| SEOS / DESFire EV2/EV3 | 13.56 MHz | Modern encryption — significantly harder | Proxmark3 (limited attack surface) |
| Apple / Google Wallet NFC | 13.56 MHz | Device-bound credentials — not cloneable | N/A |

**Physical pentest tools:**

```
Proxmark3 RDV4    — Research-grade RFID tool; read, emulate, clone all major card types
Flipper Zero      — Portable multi-tool; 125 kHz read/write, NFC, IR, RF
Wiegotcha         — ESP32-based device; intercepts Wiegand data on reader wire
ESPKey            — Covert implant; sits on Wiegand bus and exfiltrates badge data
Long-range reader — Covert 125 kHz read at 3–12 inches without physical contact
```

**Countermeasures:**

- Upgrade to SEOS / DESFire EV2 or EV3 across all facilities
- Implement anti-cloning features (CSN randomization where available)
- Monitor for access anomalies (badge used at two distant readers within impossible time window)
- Mobile credentials (Apple/Google Wallet) — device-bound, phishing-resistant

### Dumpster Diving

Unshredded corporate documents found in trash or recycling:

- Org charts, internal memos, printed emails
- Hardware asset tags (reveals device models and serial numbers for targeted attacks)
- Decommissioned hard drives (if not degaussed or physically destroyed)
- Medical / financial records (HIPAA / PCI implications)
- Handwritten passwords or PINs

**Countermeasures:**

- Cross-cut shredder policy (strip shredders are insufficient — reconstructable)
- Secure document destruction bins with locked lids and certified destruction vendor
- Clean desk policy — no sensitive documents left unattended
- Hard drive destruction program: NIST 800-88 compliant wiping or physical destruction

### Shoulder Surfing

Observe passwords, PINs, screen content in public spaces, open offices, coffee shops, or shared workspaces.

**Contexts:**

- Laptop in airport / coffee shop — screen visible to those behind
- ATM PIN entry — observation from proximity
- Open-plan office — screen visible to passersby

**Countermeasures:**

- Privacy screens (3M privacy filter reduces viewing angle to ~30 degrees)
- Screen lock policy (auto-lock at 60–120 seconds of inactivity)
- Physical awareness — position screens away from public sightlines
- Password manager with autofill (avoids typing passwords visibly)

### Lock Bypass

| Technique | Target | Tools |
|---|---|---|
| Lock picking | Pin tumbler locks | Pick set, tension wrench |
| Bumping | Pin tumbler locks | Bump key |
| Shimming | Padlocks with shackle | Shim stock |
| Under-door tool | Push-bar / lever handles | UDT (inflatable bladder + wire reach) |
| Door gap tool | Crash bars | Latch bypass tool |
| REX sensor spoof | Motion-activated exit | Paper / spray can to trigger sensor from exterior |

**Countermeasures:**

- High-security locks (Medeco, Abloy Protec2) with pick/bump resistance
- Video surveillance at all entry points with retention
- Alarm systems with door-open sensors
- Security officers / patrols

---

## Open-Source Intelligence for SE

### LinkedIn Enumeration

```bash
# linkedin2username — generate username list from company LinkedIn
pip install linkedin2username
linkedin2username -u attacker@email.com -c "TargetCompany" -n 5
# Outputs: first.last, flast, firstl, etc.

# theHarvester — email and subdomain enumeration
theHarvester -d targetcompany.com -b linkedin -l 200
theHarvester -d targetcompany.com -b google,bing,yahoo -l 500
```

### Email Format Discovery and Validation

```bash
# hunter.io API — discover email format and find addresses
curl "https://api.hunter.io/v2/domain-search?domain=targetcompany.com&api_key=KEY"

# emailhippo / NeverBounce — validate email existence without sending
# clearbit — enrich email to get name, title, LinkedIn profile

# After discovering format (first.last@company.com):
# Cross-reference LinkedIn employees → build targeted list
```

### OSINT Toolchain for SE Campaigns

```
Target: TargetCorp employee "Jane Smith" in Finance

1. LinkedIn     → title: "Accounts Payable Manager", manager: "Bob Jones"
2. Hunter.io    → email format: first.last@targetcorp.com → jane.smith@targetcorp.com
3. Clearbit     → confirms email + phone (sometimes)
4. Google dork  → site:targetcorp.com filetype:pdf → internal documents with internal terminology
5. Job postings → "Experience with SAP Concur and NetSuite" → tech stack discovered
6. Press release → "TargetCorp recently announced a new ERP migration with Accenture"
7. Pretext crafted → fake email from "Accenture ERP Team" asking Jane to verify her SAP credentials
                     for the migration cutover happening this Friday (urgency)
```

---

## Defense and Detection

### Security Awareness Training Program

**Program structure:**

| Component | Frequency | Format |
|---|---|---|
| Phishing simulations | Monthly | GoPhish, KnowBe4, Cofense, Proofpoint TAP |
| Micro-learning modules | Monthly | 3–5 minute videos on single topics |
| Deep dive courses | Quarterly | 20–30 minute interactive courses |
| In-person / live training | Annual | Tabletop exercises, live vishing demos |
| Just-in-time training | On click | Immediate popup/page for simulation failures |

**Topics to rotate:**

- Phishing and spear phishing recognition
- Vishing and how to handle suspicious calls
- Physical security: tailgating, badge awareness
- Social media OPSEC: what not to post
- BEC and wire transfer fraud
- AiTM phishing and why MFA alone isn't sufficient
- QR code / quishing awareness
- Pretexting recognition

**Metrics:**

| Metric | Target |
|---|---|
| Phishing simulation click rate | < 5% after 12 months |
| Phishing report rate | > 60% of simulations reported |
| Training completion rate | > 95% of staff |
| Mean time to report (MTTR) | < 1 hour for live phishing |
| Repeat clickers | Tracked individually for targeted coaching |

**Platforms:**

- **KnowBe4** — market leader; large template library, PhishER for inbox management
- **Proofpoint Security Awareness Training (SAT)** — integrated with email gateway for real threat simulation
- **Cofense** — strong reporting culture focus; Cofense Reporter PAB
- **SANS Security Awareness** — compliance-focused with strong content library
- **Curricula** (acquired by Huntress) — engaging story-based content

### Technical Controls Against Social Engineering

| Control | Attack Mitigated | Implementation |
|---|---|---|
| FIDO2 / hardware security keys | AiTM phishing, credential theft | Entra ID + YubiKey / Google Titan |
| Conditional Access (compliant device) | AiTM session theft | Intune + Conditional Access Policy |
| Email authentication (SPF / DKIM / DMARC) | Email spoofing, BEC | DNS records; `DMARC p=reject` |
| Anti-phishing ML (email gateway) | Phishing delivery | Proofpoint TAP, Microsoft Defender for Office 365 |
| URL detonation / sandboxing | Malicious link in email | Safe Links (MDO), Proofpoint URL Defense |
| Anti-phishing training + simulation | Spear phishing clicks | GoPhish, KnowBe4, Cofense |
| Caller ID verification / callback | Vishing | Callback to known number, code words |
| Wire transfer 2-person authorization | BEC fraud | Process control, out-of-band verbal confirmation |
| Physical access controls (mantrap) | Tailgating | Mantrap, turnstile, anti-passback |
| Modern card technology (SEOS/DESFire EV2) | Badge cloning | Access control upgrade program |
| Clean desk policy | Shoulder surfing, dumpster diving | Enforcement + shredder program |
| Privacy screens | Shoulder surfing | Standard laptop peripherals policy |
| SIM lock / carrier PIN | SIM swapping | Employee advisory + carrier enrollment |

### Email Authentication (SPF / DKIM / DMARC) Reference

**SPF** — authorizes which IPs may send on behalf of a domain:
```
v=spf1 include:spf.protection.outlook.com include:_spf.google.com ~all
# -all = hard fail; ~all = soft fail (safer to start with ~all)
```

**DKIM** — cryptographic signature proving message integrity:
```
# Selector record at: selector._domainkey.example.com
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...
```

**DMARC** — policy for SPF/DKIM failures, with reporting:
```
# _dmarc.example.com TXT record
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100
# p=none (monitor) → p=quarantine (spam) → p=reject (block) — graduated rollout
```

**BIMI** — Brand Indicators for Message Identification (logo shown in inbox when DMARC=reject):
```
# default._bimi.example.com TXT record
v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem
```

### Incident Response for Phishing

**Detection sources:**

- User reports via Phish Alert Button (PAB)
- Email gateway quarantine alerts
- SIEM correlation (link click + external DNS query + credential entry timing)
- EDR alerts (malicious download following link click)

**Response steps:**

1. **Triage** — determine if real threat or simulation; check against active campaigns
2. **Contain** — use PAB / email gateway API to pull all instances of same email from all inboxes
3. **Scope** — identify all recipients; check mail flow logs for delivery vs. quarantine
4. **Check for compromise** — search SIEM/EDR for evidence of link clicks, file downloads, credential entry
5. **Remediate** — block sender domain/IP, block malicious URL at proxy/email gateway
6. **Communicate** — alert affected users; send org-wide advisory if widespread
7. **Document** — log TTPs, IOCs; update detections

**KQL — detect phishing link clicks from email:**

```kql
EmailEvents
| where Timestamp > ago(24h)
| where DeliveryAction == "Delivered"
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(24h)
    | where ActionType == "ClickAllowed"
) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url
| sort by Timestamp desc
```

### Reporting Culture

Building a reporting culture is the single highest-leverage investment in security awareness:

- **Make it frictionless** — one-click Phish Alert Button (Cofense PAB, KnowBe4 PAB, Microsoft Report Message)
- **No blame for clicking** — reporting is the success behavior; clicking is the learning opportunity
- **Close the feedback loop** — tell reporters whether it was a real threat or a simulation, and what happened as a result
- **Celebrate reporters** — recognize high reporters in team meetings, internal newsletters
- **Measure MTTR** — mean time to report for live phishing should be under 1 hour; faster reporting limits blast radius

---

## ATT&CK Mappings

| Technique ID | Name | SE Relevance |
|---|---|---|
| T1566 | Phishing | Core phishing delivery — attachments and links |
| T1566.001 | Spearphishing Attachment | Targeted phishing with malicious attachment |
| T1566.002 | Spearphishing Link | Targeted phishing with credential-harvesting link |
| T1566.003 | Spearphishing via Service | Phishing via LinkedIn, Teams, Slack, WhatsApp |
| T1534 | Internal Spearphishing | Phishing from compromised internal account |
| T1598 | Phishing for Information | Reconnaissance phishing (gathering data, not deploying malware) |
| T1656 | Impersonation | Pretexting as trusted entity in voice or written communication |
| T1659 | Content Injection | Injecting content into legitimate communication threads (reply-chain phishing) |
| T1204 | User Execution | Victim executes malicious file / link delivered via SE |
| T1078 | Valid Accounts | Credential harvest via phishing / vishing |
| T1539 | Steal Web Session Cookie | AiTM session cookie theft |
| T1557 | Adversary-in-the-Middle | AiTM phishing proxy |
| T1528 | Steal Application Access Token | OAuth token harvesting via phishing |

---

*Reference maintained by TeamStarWolf. Techniques described are for authorized security testing and defender education only.*
