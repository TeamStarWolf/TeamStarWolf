# Secure Coding Reference

A comprehensive reference for writing secure code, covering OWASP Top 10 (2021), input validation, authentication, cryptography, secure SDLC tooling, and supply chain security. Mapped to OWASP SAMM, NIST SSDF (SP 800-218), CWE Top 25, and MITRE ATT&CK.

---

## Table of Contents

1. [OWASP Top 10 (2021)](#owasp-top-10-2021)
2. [Input Validation & Output Encoding](#input-validation--output-encoding)
3. [Authentication & Session Management](#authentication--session-management)
4. [Cryptography in Code](#cryptography-in-code)
5. [File Upload Security](#file-upload-security)
6. [Dependency & Supply Chain Security](#dependency--supply-chain-security)
7. [Security Testing in SDLC](#security-testing-in-sdlc)
8. [Secure Design Principles](#secure-design-principles)
9. [Language-Specific Quick Guides](#language-specific-quick-guides)
10. [HTTP Security Headers Reference](#http-security-headers-reference)
11. [Framework & Standards Mapping](#framework--standards-mapping)

---

## OWASP Top 10 (2021)

### A01 — Broken Access Control

**Description**: Access control enforces policy so users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of all data, or performing a business function outside the user's limits. Includes IDOR (Insecure Direct Object Reference), privilege escalation, and missing function-level access control. CWE-284, CWE-285, CWE-639. ATT&CK: T1078 (Valid Accounts), T1548 (Abuse Elevation Control Mechanism).

**Vulnerable — IDOR example (Python/Flask):**
```python
# BAD: User can access any invoice by changing the ID
@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    invoice = db.session.get(Invoice, invoice_id)
    return jsonify(invoice.to_dict())  # No ownership check!
```

**Secure — Object-level authorization:**
```python
from flask_login import login_required, current_user

@app.route("/invoice/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    # Enforce ownership at query time — never fetch then check
    invoice = Invoice.query.filter_by(
        id=invoice_id,
        owner_id=current_user.id   # Bind to authenticated user
    ).first_or_404()
    return jsonify(invoice.to_dict())
```

**Detection**: Code review for missing `owner_id`/`user_id` filters; fuzz object IDs (sequential integers, UUIDs); use BOLA/BFLA automated scanners. Add authorization middleware centrally rather than per-route.

---

### A02 — Cryptographic Failures

**Description**: Formerly "Sensitive Data Exposure." Root cause is weak or missing cryptography protecting data in transit or at rest. Includes use of deprecated algorithms (MD5, SHA-1, DES, RC4), weak key lengths, missing TLS, hardcoded keys, and ECB mode. CWE-326, CWE-327, CWE-328. ATT&CK: T1552 (Unsecured Credentials), T1040 (Network Sniffing).

**Vulnerable — MD5 password hashing:**
```python
import hashlib
# BAD: MD5 is a fast hash — billions of attempts/second with GPU
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

**Secure — bcrypt (cost ≥12):**
```python
import bcrypt

def store_password(password: str) -> bytes:
    # cost=12 is ~300ms on commodity hardware — deliberately slow
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)
```

**Secure — Argon2id (NIST SP 800-63B recommended):**
```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=19456,  # 19 MiB — OWASP minimum
    parallelism=1,
    hash_len=32,
    salt_len=16
)

def store_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
```

**Detection**: Grep codebase for `md5`, `sha1`, `DES`, `RC4`; use Semgrep rule `python.cryptography.security.insecure-hash-algorithms`; check TLS config with `testssl.sh`.

---

### A03 — Injection

**Description**: User-supplied data is sent to an interpreter without validation or escaping. Includes SQL, OS command, LDAP, XPath, NoSQL, and template injection. CWE-89 (SQL), CWE-78 (OS Command), CWE-90 (LDAP). ATT&CK: T1190 (Exploit Public-Facing Application).

**Vulnerable — SQL Injection:**
```python
# BAD: String concatenation — classic SQLi
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchone()
# Payload: username = "' OR '1'='1" -- dumps entire table
```

**Secure — Parameterized query (Python sqlite3/SQLAlchemy):**
```python
# sqlite3 — use ? placeholders
import sqlite3
def get_user(username: str):
    conn = sqlite3.connect("app.db")
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return row

# SQLAlchemy ORM — parameters handled automatically
from sqlalchemy.orm import Session
def get_user_orm(session: Session, username: str):
    return session.query(User).filter(User.username == username).first()
```

**Vulnerable — OS Command Injection:**
```python
import os
# BAD: shell=True with user input
def ping_host(host):
    os.system(f"ping -c 1 {host}")
# Payload: host = "127.0.0.1; cat /etc/passwd"
```

**Secure — subprocess with shell=False:**
```python
import subprocess, re

def ping_host(host: str) -> str:
    # Validate input against allow-list pattern first
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
        raise ValueError("Invalid hostname")
    result = subprocess.run(
        ["ping", "-c", "1", host],   # List form — no shell expansion
        capture_output=True, text=True, timeout=5, shell=False
    )
    return result.stdout
```

**LDAP Injection — Secure escaping (Python ldap3):**
```python
from ldap3.utils.conv import escape_filter_chars

def authenticate_user(username: str, password: str) -> bool:
    safe_username = escape_filter_chars(username)
    search_filter = f"(uid={safe_username})"
    # ... perform LDAP bind
```

**Detection**: `bandit -r . -t B608` (SQL); `semgrep --config=p/sql-injection`; taint analysis in CodeQL; DAST fuzzing with ZAP active scan.

---

### A04 — Insecure Design

**Description**: Missing or ineffective security controls at the design level — no threat modeling, no rate limiting by design, unsafe business logic. Cannot be fixed by implementation alone. CWE-73, CWE-183, CWE-209. ATT&CK: T1110 (Brute Force), T1499 (Endpoint Denial of Service).

**STRIDE Threat Modeling:**

| Threat | Description | Example | Mitigations |
|--------|-------------|---------|-------------|
| **S**poofing | Impersonating something or someone | Forged JWT, ARP spoofing | Authentication, MFA |
| **T**ampering | Modifying data or code | MITM modifying API requests | HMAC signing, TLS, integrity checks |
| **R**epudiation | Denying an action occurred | User denies placing order | Audit logging, digital signatures |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Verbose error messages, IDOR | Access control, data minimization |
| **D**enial of Service | Making system unavailable | API without rate limits | Rate limiting, input size limits |
| **E**levation of Privilege | Gaining higher permissions | Path traversal to admin config | Least privilege, input validation |

**Design controls**: Rate limiting on all authentication endpoints (e.g., 5 attempts per 15 min); account lockout with backoff; anti-automation (CAPTCHA for high-risk flows); separate admin functionality to different host/port; model data flows in architecture diagrams before coding.

**Detection**: Threat model review during design phase; security stories in sprint planning; OWASP SAMM assessment; architecture review gate before production.

---

### A05 — Security Misconfiguration

**Description**: Insecure default configurations, incomplete configurations, open cloud storage, verbose error messages, unnecessary features enabled. CWE-16, CWE-611. ATT&CK: T1592 (Gather Victim Host Information).

**Vulnerable configurations:**
```python
# BAD: Flask debug mode in production
app = Flask(__name__)
app.config["DEBUG"] = True          # Exposes interactive debugger
app.config["SECRET_KEY"] = "dev"    # Hardcoded weak secret
app.config["SQLALCHEMY_ECHO"] = True  # Logs all SQL to output

# BAD: Verbose error handler leaks stack trace
@app.errorhandler(500)
def internal_error(e):
    return str(e), 500  # Sends full traceback to client
```

**Secure configuration:**
```python
import os, secrets

app = Flask(__name__)
app.config.update(
    DEBUG=False,
    TESTING=False,
    SECRET_KEY=os.environ["SECRET_KEY"],   # Load from env/vault
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True,            # HTTPS only
    SQLALCHEMY_ECHO=False,
)

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error"}), 500  # Generic message
```

**Detection**: CIS Benchmarks automated scanning; `checkov` for IaC; `docker-bench-security`; review security headers with `securityheaders.com`; Nessus/OpenVAS configuration audits.

---

### A06 — Vulnerable and Outdated Components

**Description**: Using components with known vulnerabilities — libraries, frameworks, OS packages. CWE-1035, CWE-937. ATT&CK: T1195 (Supply Chain Compromise), T1203 (Exploitation for Client Execution).

**SCA (Software Composition Analysis) tools:**
```bash
# Python — pip-audit (NIST NVD + PyPA advisory database)
pip install pip-audit
pip-audit --requirement requirements.txt --output json -o audit.json

# Node.js
npm audit --audit-level=high
npm audit fix

# Ruby
gem install bundler-audit
bundle-audit check --update

# Rust
cargo install cargo-audit
cargo audit

# Java (OWASP Dependency-Check)
dependency-check --project myapp --scan ./target --format JSON
```

**Lock file with hash verification (Python):**
```
# requirements.txt — pin exact versions with hashes
bcrypt==4.1.3 \
    --hash=sha256:3d5a8df1... \
    --hash=sha256:b8a3e2f4...
cryptography==42.0.8 \
    --hash=sha256:9cf3e1a2...
# Install: pip install --require-hashes -r requirements.txt
```

**Detection**: Integrate SCA into CI pipeline as a blocking gate; subscribe to GitHub Dependabot alerts; monitor CVE feeds (NVD, OSV.dev); set CVSS threshold for blocking (e.g., fail build on HIGH/CRITICAL).

---

### A07 — Identification and Authentication Failures

**Description**: Confirms the user's identity, authentication, and session management. Weaknesses include credential stuffing, brute force, session fixation, weak tokens, missing MFA. CWE-287, CWE-384, CWE-307. ATT&CK: T1110 (Brute Force), T1539 (Steal Web Session Cookie).

**Session Fixation — Vulnerable:**
```python
# BAD: Session ID not regenerated after login
@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        session["user_id"] = user.id  # Old session ID retained!
        return redirect("/dashboard")
```

**Secure — Regenerate session ID on privilege change:**
```python
from flask import session
from flask_login import login_user

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        # Clear old session data and generate new session ID
        old_data = dict(session)
        session.clear()
        session.update(old_data)
        session.modified = True
        login_user(user)
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid credentials"), 401
```

**Cryptographically secure token generation:**
```python
import secrets

# Python — 32 bytes = 256-bit entropy URL-safe token
token = secrets.token_urlsafe(32)

# Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

**Detection**: Automated credential stuffing testing; verify session cookie attributes (HttpOnly, Secure, SameSite); test for session fixation; check for missing account lockout.

---

### A08 — Software and Data Integrity Failures

**Description**: Code and infrastructure not protected against integrity violations. Includes insecure deserialization, unsigned updates, and malicious CI/CD pipeline code. CWE-502, CWE-345, CWE-494. ATT&CK: T1195 (Supply Chain Compromise), T1059 (Command and Scripting Interpreter).

**Vulnerable — Python pickle deserialization:**
```python
import pickle
# BAD: Deserializing untrusted data — arbitrary code execution
@app.route("/load_session", methods=["POST"])
def load_session():
    data = pickle.loads(request.data)  # RCE if data is malicious
    return jsonify(data)

# Exploit payload example:
# class Exploit(object):
#     def __reduce__(self):
#         return (os.system, ('id',))
# pickle.dumps(Exploit())
```

**Secure alternatives:**
```python
import json

# Use JSON for data serialization — no code execution
@app.route("/load_session", methods=["POST"])
def load_session():
    try:
        data = json.loads(request.data)   # Safe — no code execution
        # Validate schema before using
        validate_session_schema(data)
        return jsonify(data)
    except (json.JSONDecodeError, ValidationError):
        return jsonify({"error": "Invalid data"}), 400

# If you must deserialize objects, use safer alternatives:
# - msgpack with schema validation
# - marshmallow / pydantic for structured deserialization
# - protobuf / thrift with strict schemas
```

**Supply chain integrity:**
```bash
# Verify package signatures with Sigstore/Cosign
cosign verify-blob --certificate cert.pem --signature sig.sig artifact.tar.gz

# GitHub Actions — pin to SHA to prevent tag mutation attacks
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Detection**: Ban `pickle.loads(untrusted)` via Semgrep; require signed commits; enable branch protection with required reviews; scan CI pipelines with `zizmor` or `actionlint`.

---

### A09 — Security Logging and Monitoring Failures

**Description**: Insufficient logging, detection, monitoring, and active response. Breaches go undetected for an average of 207 days (IBM Cost of a Data Breach 2023). CWE-223, CWE-778. ATT&CK: T1070 (Indicator Removal).

**What to log (security events):**
```python
import logging, json
from datetime import datetime, timezone

security_logger = logging.getLogger("security")

def log_security_event(event_type: str, user_id: str, ip: str, details: dict):
    """Structured security event logging."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,    # e.g., "login_failure", "access_denied"
        "user_id": user_id,
        "source_ip": ip,
        "details": details,
        # NO: password, credit card, SSN, PII in logs
    }
    security_logger.warning(json.dumps(event))

# Log: auth success/failure, access control violations,
#       privilege changes, input validation failures,
#       admin actions, data exports, session events
```

**What NOT to log:**
```python
# BAD — PII and secrets in logs
logger.info(f"User {username} logged in with password {password}")
logger.debug(f"Card number: {card_number}, CVV: {cvv}")
logger.info(f"Session token: {session_token}")
logger.error(f"DB error for query: SELECT * FROM users WHERE ssn='{ssn}'")

# GOOD — log events without sensitive values
logger.info(f"Login attempt for user_id={user_id} from ip={ip} result=success")
logger.info(f"Payment processed for order_id={order_id} amount_cents={amount}")
```

**Detection**: Deploy SIEM with alert rules for: 10+ failed logins in 5 min; after-hours admin access; privilege escalation events; mass data export; impossible travel. Use structured logging (JSON) for easy parsing. Test logging completeness with OWASP Testing Guide.

---

### A10 — Server-Side Request Forgery (SSRF)

**Description**: Web app fetches a remote resource without validating the user-supplied URL. Allows attackers to access internal services, cloud metadata, and bypass firewalls. CWE-918. ATT&CK: T1090 (Proxy), T1552 (Unsecured Credentials — cloud IMDS).

**Vulnerable — SSRF to internal/cloud metadata:**
```python
import requests
# BAD: User controls the URL — accesses internal services
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = requests.get(url, timeout=10)    # SSRF!
    return resp.content

# Attacker payloads:
# ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# ?url=http://10.0.0.1/admin
# ?url=file:///etc/passwd
```

**Secure — Allow-list with DNS rebinding protection:**
```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = {"api.example.com", "cdn.example.com"}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if hostname not in ALLOWED_DOMAINS:
            return False
        # Resolve and check for private/loopback ranges (SSRF via DNS rebinding)
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
        return True
    except Exception:
        return False

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        return jsonify({"error": "URL not allowed"}), 400
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return resp.content
```

**Cloud IMDS context**: AWS EC2 metadata at `169.254.169.254`, Azure at `169.254.169.254` (same), GCP at `metadata.google.internal`. All return IAM credentials. Mitigate with IMDSv2 (AWS), IMDS access disabled at the workload level, and network-layer egress filtering.

**Detection**: ZAP active scan SSRF rules; Burp Collaborator for out-of-band detection; block `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` in egress WAF/firewall rules.

---

## Input Validation & Output Encoding

### Validation Principles

**Allow-list over deny-list**: Define exactly what is permitted; reject everything else. Deny-lists are incomplete by definition — there is always a bypass.

```python
import re
from typing import Optional

# ALLOW-LIST validation examples
def validate_username(value: str) -> bool:
    """Only alphanumeric + underscore, 3-32 chars."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', value))

def validate_email(value: str) -> bool:
    """RFC 5321 simplified — use a library for production."""
    return bool(re.match(r'^[^@\s]{1,64}@[^@\s]{1,253}\.[a-zA-Z]{2,}$', value))

def validate_integer_range(value: str, min_val: int, max_val: int) -> Optional[int]:
    """Type-check then range-check."""
    try:
        n = int(value)
        if min_val <= n <= max_val:
            return n
    except (ValueError, TypeError):
        pass
    return None

# Validate: type, length, range, format, business rules
# Validate at the INPUT boundary — before any processing
```

**Pydantic for structured validation (Python):**
```python
from pydantic import BaseModel, Field, validator
import re

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254)
    age: int = Field(..., ge=13, le=120)
    
    @validator("email")
    def email_must_be_valid(cls, v):
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v.lower()
```

### Output Encoding Contexts

Output encoding must match the context where data is rendered:

| Context | Risk | Python Method | JavaScript Method |
|---------|------|---------------|-------------------|
| HTML body | XSS | `html.escape(s)` | `element.textContent = s` |
| HTML attribute | XSS | `html.escape(s, quote=True)` | `element.setAttribute(attr, s)` |
| JavaScript string | XSS | `json.dumps(s)` | `JSON.stringify(s)` |
| URL parameter | Open redirect, injection | `urllib.parse.quote(s)` | `encodeURIComponent(s)` |
| CSS value | CSS injection | Avoid user data in CSS | `CSS.escape(s)` |

```python
import html, json
from urllib.parse import quote

# Python output encoding examples
user_input = '<script>alert("xss")</script>'

# HTML body context
safe_html = html.escape(user_input)
# => '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

# JSON encoding for JavaScript context
safe_js = json.dumps(user_input)
# => '"<script>alert(\\"xss\\")</script>"'

# URL encoding
safe_url = quote(user_input, safe='')
```

```javascript
// JavaScript — prefer DOM APIs over string concatenation
const userInput = '<img src=x onerror=alert(1)>';

// SAFE — textContent never executes HTML
document.getElementById('output').textContent = userInput;

// UNSAFE — avoid innerHTML with untrusted data
// document.getElementById('output').innerHTML = userInput;  // XSS!

// When rich HTML is required — use DOMPurify
const clean = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});
document.getElementById('output').innerHTML = clean;
```

### Content Security Policy (CSP)

```http
# Strict nonce-based CSP — prevents inline script execution
Content-Security-Policy: 
  default-src 'none';
  script-src 'nonce-{RANDOM_PER_REQUEST}' 'strict-dynamic';
  style-src 'nonce-{RANDOM_PER_REQUEST}';
  img-src 'self' https:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests;
  report-uri /csp-violations;

# Deployment — start with report-only to identify violations
Content-Security-Policy-Report-Only: default-src 'none'; script-src 'nonce-...'
```

```python
# Flask — generate nonce per request
import secrets
from flask import g

@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def add_csp_header(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
        f"style-src 'nonce-{nonce}'; "
        f"img-src 'self'; connect-src 'self';"
    )
    return response
```

---

## Authentication & Session Management

### Password Hashing

**PBKDF2-HMAC-SHA256 (NIST SP 800-132, ≥600,000 iterations per NIST 2023):**
```python
import hashlib, os, base64

def hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=600_000,   # NIST 2023 minimum
        dklen=32
    )
    return base64.b64encode(salt + key).decode('utf-8')

def verify_password(password: str, stored: str) -> bool:
    import hmac
    decoded = base64.b64decode(stored.encode('utf-8'))
    salt, key = decoded[:32], decoded[32:]
    candidate = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600_000, 32)
    return hmac.compare_digest(candidate, key)  # Constant-time comparison
```

### JWT Security

**Algorithm confusion vulnerability and secure configuration:**
```python
import jwt  # PyJWT

# BAD: accepts any algorithm including alg:none
def decode_bad(token):
    return jwt.decode(token, key, algorithms=["HS256", "RS256"])
    # Attacker can forge token with alg:none

# GOOD: pin algorithm explicitly
def decode_token(token: str, public_key: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],      # Explicitly pin — never use ["*"]
            options={
                "require": ["exp", "iat", "sub", "aud"],
                "verify_exp": True,
            },
            audience="https://api.example.com"   # Validate audience
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")

def create_token(user_id: str, private_key: str) -> str:
    import time
    return jwt.encode({
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 900,    # 15-minute expiry
        "aud": "https://api.example.com",
        "jti": secrets.token_urlsafe(16), # JWT ID for revocation
    }, private_key, algorithm="RS256")
```

### TOTP Multi-Factor Authentication

```python
import pyotp, qrcode, secrets

def setup_mfa(user_id: str) -> dict:
    """Generate TOTP secret and QR code URI for user enrollment."""
    totp_secret = pyotp.random_base32()  # 160-bit random secret
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=f"user_{user_id}",
        issuer_name="MyApp"
    )
    # Store totp_secret encrypted in database
    # Generate QR code from provisioning_uri for display
    return {"secret": totp_secret, "uri": provisioning_uri}

def verify_totp(stored_secret: str, user_token: str) -> bool:
    """Verify TOTP with ±1 time-step tolerance."""
    totp = pyotp.TOTP(stored_secret)
    return totp.verify(user_token, valid_window=1)  # 30s window

# Backup codes — store hashed, one-time use
def generate_backup_codes() -> list[str]:
    return [secrets.token_hex(5).upper() for _ in range(10)]
    # Store as bcrypt hashes; mark used after consumption
```

### OAuth 2.0 + PKCE

```python
import hashlib, base64, secrets

def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    code_verifier = secrets.token_urlsafe(32)   # 43-128 chars
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return code_verifier, code_challenge

# Authorization URL construction
state = secrets.token_urlsafe(16)  # CSRF protection
code_verifier, code_challenge = generate_pkce_pair()

auth_url = (
    f"{AUTHORIZATION_ENDPOINT}"
    f"?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&scope=openid profile"
    f"&state={state}"                      # Store in session, verify on callback
    f"&code_challenge={code_challenge}"
    f"&code_challenge_method=S256"
)
# Store tokens in HttpOnly cookies — not localStorage (XSS accessible)
```

---

## Cryptography in Code

### AES-256-GCM (Authenticated Encryption)

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """AES-256-GCM encryption. key must be 32 bytes."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)          # 96-bit nonce — unique per encryption
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext       # Prepend nonce for storage

def decrypt(data: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """AES-256-GCM decryption with authentication tag verification."""
    aesgcm = AESGCM(key)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
    # Raises InvalidTag if tampered — authentication failure

# Key generation
key = AESGCM.generate_key(bit_length=256)
```

### RSA-OAEP for Key Encapsulation

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096          # 4096-bit for long-term keys; 2048 minimum
    )
    return private_key, private_key.public_key()

def rsa_encrypt(plaintext: bytes, public_key) -> bytes:
    """Use OAEP padding — NEVER use PKCS1v15 for new code."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(ciphertext: bytes, private_key) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
```

### Key Derivation

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os, base64

# HKDF — derive multiple keys from a master key
def derive_key(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(master_key)

encryption_key = derive_key(master, b"encryption")
signing_key = derive_key(master, b"signing")

# PBKDF2 for password-based key derivation
def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    key = kdf.derive(password.encode())
    return key, salt
```

### Cryptographic Randomness

```python
import secrets

# Python — cryptographically secure random
token = secrets.token_urlsafe(32)     # URL-safe base64 token
hex_token = secrets.token_hex(32)     # Hex string
random_int = secrets.randbelow(1000)  # Random int in [0, 1000)
random_bytes = secrets.token_bytes(32)

# NEVER use for security-sensitive values:
import random  # BAD — predictable PRNG
random.random()
random.randint(0, 1000000)
```

```javascript
// Node.js
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
const uuid = crypto.randomUUID();

// Browser
const array = new Uint8Array(32);
crypto.getRandomValues(array);
```

### What Not To Use

| Avoid | Use Instead | Reason |
|-------|-------------|--------|
| MD5, SHA-1 (passwords) | bcrypt, Argon2id | Fast hashes — trivially brute-forced |
| ECB mode | GCM or CBC+HMAC | ECB leaks patterns (penguin attack) |
| PKCS1v15 padding | OAEP | Padding oracle attacks |
| DES, 3DES, RC4 | AES-256-GCM | Broken — key length or stream cipher weaknesses |
| Hardcoded keys | KMS, HSM, Vault | Key rotation impossible; exposed in repos |
| Custom crypto | Standard libraries | Subtle timing/implementation flaws |
| `random` module | `secrets` module | MT19937 is predictable with 624 outputs |

---

## File Upload Security

### Validation

```python
import magic   # python-magic (libmagic bindings)
import hashlib, os
from pathlib import Path

# Allow-list of permitted MIME types and extensions
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "application/pdf"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

def validate_upload(file_data: bytes, filename: str) -> tuple[bool, str]:
    # Check file size
    if len(file_data) > MAX_FILE_SIZE:
        return False, "File too large"
    
    # Check extension (allow-list)
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension not allowed: {ext}"
    
    # Check magic bytes — not Content-Type header (client-controlled)
    detected_mime = magic.from_buffer(file_data[:1024], mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        return False, f"File type not allowed: {detected_mime}"
    
    # Verify MIME matches extension
    expected_mimes = {".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                      ".png": "image/png", ".gif": "image/gif", ".pdf": "application/pdf"}
    if detected_mime != expected_mimes.get(ext):
        return False, "MIME type does not match extension"
    
    return True, "OK"
```

### Secure Storage

```python
import secrets
from pathlib import Path

# Store OUTSIDE web root — never in /static/ or /public/
UPLOAD_DIR = Path("/var/app/uploads")  # Not web-accessible

def store_upload(file_data: bytes, original_filename: str) -> str:
    """Store with random filename to prevent path prediction."""
    ext = Path(original_filename).suffix.lower()
    safe_filename = secrets.token_urlsafe(32) + ext
    upload_path = UPLOAD_DIR / safe_filename
    
    # Ensure no path traversal
    upload_path = upload_path.resolve()
    if not str(upload_path).startswith(str(UPLOAD_DIR.resolve())):
        raise ValueError("Path traversal detected")
    
    upload_path.write_bytes(file_data)
    return safe_filename

# Serve with secure headers
@app.route("/download/<filename>")
@login_required
def download_file(filename):
    # Verify ownership before serving
    if not current_user.owns_file(filename):
        abort(403)
    response = send_from_directory(UPLOAD_DIR, filename)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
```

---

## Dependency & Supply Chain Security

### Lock Files and Hash Verification

```bash
# Python — pip-compile with hashes
pip install pip-tools
pip-compile --generate-hashes requirements.in -o requirements.txt
pip install --require-hashes -r requirements.txt  # Fails on hash mismatch

# Node.js — package-lock.json
npm ci   # Uses lock file exactly — use in CI, not npm install

# Pipenv with hash verification
pipenv install --deploy  # Fails if Pipfile.lock is out of date
```

### Dependency Confusion & Typosquatting

```bash
# Dependency confusion attack: attacker publishes a public package
# with the same name as your private internal package at a higher version.
# npm/pip may prefer the public package.

# Mitigations:
# 1. Publish private packages to a private registry with scoping
#    npm: use @company/package-name scoping
#    pip: configure index-url to private PyPI only

# 2. Configure pip to use only your private index
# pip.conf:
[global]
index-url = https://your-private-pypi.example.com/simple/
no-index = false  # Do NOT set this if you need PyPI too
extra-index-url = https://pypi.org/simple/  # Fallback — dependency confusion risk!
# For strict private-only:
# index-url = https://private-pypi/simple/
# (no extra-index-url)
```

### GitHub Actions Supply Chain Security

```yaml
# Pin ALL actions to full commit SHA — not mutable tags
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # OIDC — avoid long-lived credentials
      contents: read
    steps:
      # Tag v4 → pinned SHA (use Dependabot to keep updated)
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
      
      # Zizmor — GitHub Actions security linter
      - name: Lint GitHub Actions
        run: pip install zizmor && zizmor .github/workflows/

      # SCA scan as pipeline gate
      - name: Audit dependencies
        run: pip-audit --requirement requirements.txt --fail-on-vuln
```

### SBOM Generation

```bash
# Syft — generates SBOM in CycloneDX or SPDX format
syft packages dir:. -o cyclonedx-json=sbom.cdx.json
syft packages dir:. -o spdx-json=sbom.spdx.json

# Grype — vulnerability scan against SBOM
grype sbom:sbom.cdx.json --fail-on high

# cyclonedx-bom (Python)
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json
```

### Artifact Signing with Sigstore/Cosign

```bash
# Sign artifact (keyless — OIDC-based identity)
cosign sign-blob artifact.tar.gz --bundle artifact.bundle

# Verify signature
cosign verify-blob artifact.tar.gz \
  --bundle artifact.bundle \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"

# GitHub Actions — sign release artifacts
- name: Sign artifact
  uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da  # v3.7.0
  run: cosign sign-blob dist/myapp.tar.gz --yes
```

---

## Security Testing in SDLC

### SAST (Static Application Security Testing)

**Semgrep:**
```bash
# OWASP Top 10 rules
semgrep --config=p/owasp-top-ten .

# Language-specific security rules
semgrep --config=p/python .
semgrep --config=p/javascript .
semgrep --config=p/java .

# Custom rule example — detect hardcoded credentials
# rules/no-hardcoded-secrets.yaml:
# rules:
#   - id: hardcoded-password
#     pattern: password = "..."
#     message: "Hardcoded password detected"
#     severity: ERROR
#     languages: [python]

semgrep --config=rules/ --output=results.json --json .
```

**Bandit (Python):**
```bash
# Recursive scan with JSON output
bandit -r ./src -f json -o bandit-report.json -l -i

# Common checks:
# B101: assert usage (disabled in -O)
# B301: pickle usage
# B303: MD5 hash usage
# B501-B510: TLS/SSL misconfiguration
# B601-B612: Shell injection

# CI integration — fail on medium+ severity
bandit -r . --severity-level medium --confidence-level medium -f json -o bandit.json
# Exit code 1 if issues found
```

**CodeQL (GitHub Actions):**
```yaml
name: CodeQL Analysis
on: [push, pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: github/codeql-action/init@ff0a06e83cb2de871e5a09832bc6a81e7276941f  # v3.27.5
        with:
          languages: ${{ matrix.language }}
          queries: security-and-quality
      - uses: github/codeql-action/autobuild@ff0a06e83cb2de871e5a09832bc6a81e7276941f
      - uses: github/codeql-action/analyze@ff0a06e83cb2de871e5a09832bc6a81e7276941f
```

### DAST (Dynamic Application Security Testing)

**OWASP ZAP:**
```bash
# Baseline scan — passive scan only, no active attacks
docker run --rm owasp/zap2docker-stable zap-baseline.py \
  -t https://staging.example.com \
  -J zap-baseline-report.json \
  -r zap-baseline-report.html \
  --exit-code 1

# Full active scan
docker run --rm owasp/zap2docker-stable zap-full-scan.py \
  -t https://staging.example.com \
  -J zap-full-report.json

# API scan with OpenAPI spec
docker run --rm owasp/zap2docker-stable zap-api-scan.py \
  -t https://staging.example.com/openapi.yaml \
  -f openapi \
  -J zap-api-report.json

# GitHub Actions integration — fail pipeline on alerts
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.12.0
  with:
    target: 'https://staging.example.com'
    fail_action: true
    issue_title: 'ZAP Security Report'
```

### Secrets Scanning

```bash
# TruffleHog — filesystem and git history
trufflehog filesystem . --json > trufflehog-report.json
trufflehog git file://. --since-commit HEAD~50 --json

# detect-secrets (pre-commit hook integration)
pip install detect-secrets
detect-secrets scan --baseline .secrets.baseline .
# Add to .pre-commit-config.yaml:
# - repo: https://github.com/Yelp/detect-secrets
#   hooks:
#     - id: detect-secrets
#       args: ['--baseline', '.secrets.baseline']

# GitLeaks
gitleaks detect --source . --report-format json --report-path gitleaks.json
gitleaks git --source . --log-opts "-50"
```

### IaC Security Scanning

```bash
# Checkov — Terraform, CloudFormation, Kubernetes, Dockerfile
pip install checkov
checkov -d . --output-file-path checkov-report --output json
checkov -d ./terraform --framework terraform --check HIGH
checkov -f Dockerfile --framework dockerfile

# tfsec — Terraform-specific
tfsec . --format json --out tfsec.json

# KICS (Keeping Infrastructure as Code Secure)
kics scan -p . -o ./kics-results --report-formats json

# Terrascan
terrascan scan -t terraform -i terraform/ --output json
```

### Shift-Left Security Gates

```
Commit → SAST (Semgrep/Bandit/ESLint) + Secrets (detect-secrets/gitleaks)
Build  → SCA (pip-audit/npm audit) + SBOM generation
Test   → DAST (ZAP baseline) + IaC scan (Checkov)
Staging → Full ZAP scan + penetration testing
Prod   → Runtime WAF + monitoring + alerting
```

---

## Secure Design Principles

### Core Principles

| Principle | Description | Example |
|-----------|-------------|---------|
| **Defense in Depth** | Multiple overlapping controls — failure of one does not compromise the system | WAF + input validation + parameterized queries + least privilege |
| **Least Privilege** | Processes and users should have the minimum access needed | DB user with only SELECT on needed tables; containers with read-only filesystem |
| **Fail Secure** | On error, default to the more secure state | Auth failure → deny access; crypto error → abort, never proceed |
| **Separation of Concerns** | Isolate security-sensitive components | Separate auth service; dedicated secrets store |
| **Economy of Mechanism** | Keep design simple — complexity increases attack surface | Simple allowlists over complex deny-lists; avoid feature creep in security code |
| **Secure Defaults** | Out-of-the-box configuration is the secure one | Password complexity enforced by default; MFA opt-out not opt-in |
| **Complete Mediation** | Every access to every resource must be checked | Per-request authorization checks; no caching of access decisions across privilege changes |
| **Open Design** | Security should not depend on secrecy of design | Kerckhoffs's principle — assume attackers know the algorithm |
| **Psychological Acceptability** | Security controls should not make legitimate access significantly harder | SSO over per-app passwords; password managers over complex rotation policies |

### STRIDE Threat Modeling Process

```
1. DECOMPOSE — Create Data Flow Diagram (DFD) of system
   - External entities (users, third-party services)
   - Processes (application code, APIs)
   - Data stores (databases, caches, files)
   - Data flows (connections between components)
   - Trust boundaries (network perimeters, process isolation)

2. ENUMERATE — Apply STRIDE to each element
   - For each process: S, T, R, I, D, E
   - For each data store: T, I, D
   - For each data flow: S, T, I
   - For each external entity: S, R

3. MITIGATE — Map threats to controls
   Spoofing → Authentication (MFA, mutual TLS)
   Tampering → Integrity controls (signing, HMAC, parameterized queries)
   Repudiation → Non-repudiation (audit logging, digital signatures)
   Info Disclosure → Confidentiality (encryption, access control)
   Denial of Service → Availability (rate limiting, circuit breakers)
   Elevation of Privilege → Authorization (RBAC, least privilege)

4. VALIDATE — Review mitigations and residual risk
   - Are controls implemented correctly?
   - What is the residual risk?
   - Does risk acceptance require sign-off?
```

---

## Language-Specific Quick Guides

### Python

```python
# AVOID: eval() / exec() with untrusted input — arbitrary code execution
# BAD:
user_expr = request.args.get("expr")
result = eval(user_expr)   # RCE

# GOOD: use ast.literal_eval for limited literal evaluation only
import ast
try:
    result = ast.literal_eval(user_expr)  # Only evaluates literals
except (ValueError, SyntaxError):
    result = None

# AVOID: subprocess with shell=True
import subprocess
# BAD:
subprocess.run(f"ls {user_dir}", shell=True)
# GOOD:
subprocess.run(["ls", user_dir], shell=False, check=True)

# AVOID: pickle for untrusted data (see A08)
# AVOID: yaml.load() — use yaml.safe_load()
import yaml
# BAD:
data = yaml.load(untrusted_string)    # RCE via !!python/object
# GOOD:
data = yaml.safe_load(untrusted_string)

# AVOID: XML with external entity parsing (XXE)
from defusedxml import ElementTree  # Use defusedxml, not xml.etree
tree = ElementTree.parse(xml_file)

# SQLAlchemy — always use ORM or parameterized text()
from sqlalchemy import text
# BAD:
db.execute(f"SELECT * FROM users WHERE id = {user_id}")
# GOOD:
db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

### JavaScript / Node.js

```javascript
// Helmet — set security headers in Express
const helmet = require('helmet');
app.use(helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    xssFilter: true,
}));

// express-validator — input validation
const { body, validationResult } = require('express-validator');
app.post('/user',
    body('username').isAlphanumeric().isLength({ min: 3, max: 32 }),
    body('email').isEmail().normalizeEmail(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
        // Safe to process
    }
);

// AVOID: eval() — use JSON.parse() for data
// BAD: eval('(' + userJson + ')');
const data = JSON.parse(userJson);  // GOOD

// Prototype pollution prevention
const _ = require('lodash');
// BAD: deep merge with user-controlled keys
// Attacker: {"__proto__": {"admin": true}}
// GOOD: use Object.create(null) for untrusted object bases
const safeObj = Object.assign(Object.create(null), userInput);

// Rate limiting
const rateLimit = require('express-rate-limit');
app.use('/api/auth', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
}));
```

### Java

```java
// PreparedStatement — parameterized queries
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ? AND status = ?"
);
stmt.setString(1, username);   // Safe — no concatenation
stmt.setString(2, "active");
ResultSet rs = stmt.executeQuery();

// XXE Prevention — disable external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setExpandEntityReferences(false);

// Avoid ObjectInputStream for untrusted data
// Use Jackson/Gson with strict type binding instead:
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL); // BAD — deserialization gadget risk
// GOOD — explicit type binding only
UserRequest req = mapper.readValue(json, UserRequest.class);

// SecureRandom — not java.util.Random
import java.security.SecureRandom;
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
```

### Go

```go
// html/template — auto-escapes HTML context
import "html/template"

tmpl := template.Must(template.New("page").Parse(`
    <h1>Hello, {{.Name}}</h1>
`))
// Name is auto-escaped — safe against XSS

// database/sql — parameterized queries
import "database/sql"
stmt, err := db.Prepare("SELECT * FROM users WHERE id = $1")
row := stmt.QueryRow(userID)  // Safe — no string interpolation

// crypto/rand — not math/rand
import "crypto/rand"
import "encoding/hex"
b := make([]byte, 32)
_, err := rand.Read(b)   // Cryptographically secure
token := hex.EncodeToString(b)

// Path traversal prevention
import "path/filepath"
func safeJoin(base, rel string) (string, error) {
    joined := filepath.Join(base, rel)
    abs, err := filepath.Abs(joined)
    if err != nil || !strings.HasPrefix(abs, base) {
        return "", errors.New("path traversal detected")
    }
    return abs, nil
}
```

---

## HTTP Security Headers Reference

| Header | Recommended Value | Purpose | Notes |
|--------|-------------------|---------|-------|
| `Content-Security-Policy` | `default-src 'none'; script-src 'nonce-{n}' 'strict-dynamic'; style-src 'nonce-{n}'; img-src 'self' https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` | Prevents XSS, clickjacking, data injection | Use `report-uri` to collect violations; start with Report-Only |
| `X-Frame-Options` | `DENY` | Prevents clickjacking (legacy) | Superseded by CSP `frame-ancestors`; keep for older browsers |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing | Required — stops browser from executing files as wrong type |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls Referer header leakage | Use `no-referrer` for highest privacy; `strict-origin` for analytics compatibility |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Disable browser features not used | Formerly Feature-Policy; disable all APIs not needed |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Forces HTTPS for 1 year | Only set over HTTPS; submit to HSTS preload list for highest assurance |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates browsing context | Mitigates Spectre cross-origin attacks; required for `SharedArrayBuffer` |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Prevents cross-origin resource loading unless explicitly permitted | Required alongside COOP for high-performance features |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevents resources being included by other origins | Use `cross-origin` for CDN assets that should be publicly embeddable |
| `Cache-Control` (sensitive pages) | `no-store` | Prevents sensitive data caching | Apply to all authenticated/sensitive responses |
| `X-XSS-Protection` | `0` (disabled) | Legacy XSS filter — now disabled | Modern browsers deprecated; CSP is the replacement |

**Quick-add Flask middleware:**
```python
@app.after_request
def add_security_headers(response):
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cache-Control": "no-store",
    })
    return response
```

---

## Framework & Standards Mapping

### OWASP SAMM (Software Assurance Maturity Model)

| Section | SAMM Practice | SAMM Level |
|---------|---------------|------------|
| Input Validation | Implementation — Secure Build | Level 1 |
| SAST/DAST | Verification — Security Testing | Level 2 |
| Threat Modeling | Design — Threat Assessment | Level 2 |
| Dependency Management | Implementation — Secure Build | Level 1 |
| Crypto | Implementation — Secure Architecture | Level 2 |
| Logging | Operations — Incident Management | Level 1 |

### NIST SSDF (SP 800-218) Mapping

| Section | SSDF Practice | Task |
|---------|---------------|------|
| Input Validation | PW.5 | PW.5.1 — Use vetted modules and services |
| Authentication | PW.6 | PW.6.1 — Follow secure coding practices |
| SAST | PW.7 | PW.7.1 — Automated source code review |
| DAST | PW.8 | PW.8.1 — Dynamic test of executables |
| Dependency Security | PW.4 | PW.4.1 — Acquire and maintain well-secured software |
| Incident Logging | RV.1 | RV.1.2 — Manage vulnerabilities |

### CWE Top 25 Cross-Reference

| CWE | Name | Section |
|-----|------|---------|
| CWE-89 | SQL Injection | A03 Injection |
| CWE-79 | XSS | Input Validation & Output Encoding |
| CWE-20 | Improper Input Validation | Input Validation |
| CWE-125 | Out-of-bounds Read | Language-Specific (C/C++) |
| CWE-78 | OS Command Injection | A03 Injection |
| CWE-416 | Use After Free | Language-Specific |
| CWE-22 | Path Traversal | File Upload Security |
| CWE-287 | Improper Authentication | Authentication & Session |
| CWE-798 | Hardcoded Credentials | Cryptography in Code |
| CWE-502 | Deserialization of Untrusted Data | A08 Integrity Failures |
| CWE-434 | Unrestricted Upload | File Upload Security |
| CWE-326 | Inadequate Encryption Strength | Cryptography in Code |
| CWE-918 | SSRF | A10 SSRF |
| CWE-284 | Improper Access Control | A01 Broken Access Control |
| CWE-306 | Missing Authentication | Authentication & Session |

### MITRE ATT&CK Technique Mapping

| Technique | ID | Mitigation in This Reference |
|-----------|----|------------------------------|
| Exploit Public-Facing Application | T1190 | A03 Injection, Input Validation |
| Valid Accounts | T1078 | A01 Access Control, A07 Auth Failures |
| Supply Chain Compromise | T1195 | Dependency & Supply Chain Security |
| Unsecured Credentials | T1552 | Cryptography in Code, A02 Crypto |
| Brute Force | T1110 | A07 Auth Failures, rate limiting |
| Steal Web Session Cookie | T1539 | Session Management, HttpOnly cookies |
| Command and Scripting Interpreter | T1059 | A08 Integrity, avoid pickle/eval |
| Network Sniffing | T1040 | A02 Crypto, TLS enforcement |
| Server Software Component | T1505 | A06 Vulnerable Components |

---

## Quick Reference Checklist

### Code Review Security Checklist

- [ ] All user input validated against an allow-list (type, length, range, format)
- [ ] Output encoded for the correct context (HTML, JS, URL, CSS)
- [ ] No string concatenation in SQL queries — parameterized only
- [ ] No `shell=True` in subprocess calls with user-controlled input
- [ ] No `eval()`, `exec()`, `pickle.loads()` with untrusted data
- [ ] Password hashing uses bcrypt (cost ≥12) or Argon2id — not MD5/SHA-1
- [ ] Session ID regenerated on login (prevent fixation)
- [ ] Session cookies have HttpOnly, Secure, SameSite=Strict
- [ ] JWT algorithm pinned explicitly — `alg:none` rejected
- [ ] No hardcoded credentials, API keys, or secrets in source code
- [ ] File uploads validated by magic bytes, not Content-Type header
- [ ] Upload storage is outside web root with random filenames
- [ ] AES-256-GCM or equivalent authenticated encryption used (not ECB)
- [ ] `secrets` module used for token generation (not `random`)
- [ ] Dependencies pinned with hash verification; SCA scan in CI
- [ ] Security events logged (auth failures, access violations) — no PII/passwords in logs
- [ ] Error responses do not leak stack traces or internal details
- [ ] All authenticated endpoints have authorization checks (not just authentication)
- [ ] SSRF protection: URL allow-list, no fetch to internal/169.254.x.x ranges
- [ ] Security headers set on all responses (HSTS, CSP, X-Content-Type-Options)

---

*Mapped to OWASP SAMM v2.0, NIST SSDF SP 800-218, CWE Top 25 (2023), and MITRE ATT&CK Enterprise v15. See also [API Security Reference](API_SECURITY_REFERENCE.md), [Container Security Reference](CONTAINER_SECURITY_REFERENCE.md), and [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md).*
