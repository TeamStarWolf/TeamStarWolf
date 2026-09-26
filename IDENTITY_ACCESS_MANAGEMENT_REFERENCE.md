# Identity & Access Management (IAM) Reference

> A comprehensive cybersecurity reference covering IAM fundamentals, authentication technologies, authorization models, identity providers, PAM, IGA, Zero Trust identity, machine identity, security monitoring, and governance/compliance.

| | |
|---|---|
| **Read this when** | choosing or hardening MFA and passwordless auth, designing RBAC/ABAC or PAM controls, building IAM detections (credential stuffing, MFA fatigue, impossible travel), mapping IAM to SOC 2 / PCI / NIST / HIPAA |
| **Start at** | [IAM Fundamentals](#_1-iam-fundamentals), [Authentication Technologies](#_2-authentication-technologies), [IAM Security Monitoring](#_9-iam-security-monitoring) |
| **Pairs with** | [Identity Security](IDENTITY_SECURITY_REFERENCE.md), [Zero Trust](ZERO_TRUST_REFERENCE.md), [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) |

---

## Table of Contents

1. [IAM Fundamentals](#_1-iam-fundamentals)
2. [Authentication Technologies](#_2-authentication-technologies)
3. [Authorization Models](#_3-authorization-models)
4. [Identity Providers & Federation](#_4-identity-providers-amp-federation)
5. [Privileged Access Management](#_5-privileged-access-management)
6. [Identity Governance & Administration](#_6-identity-governance-amp-administration)
7. [Zero Trust Identity](#_7-zero-trust-identity)
8. [Machine Identity & Workload Identity](#_8-machine-identity-amp-workload-identity)
9. [IAM Security Monitoring](#_9-iam-security-monitoring)
10. [IAM Governance & Compliance](#_10-iam-governance-amp-compliance)

---

## 1. IAM Fundamentals

### The Four Pillars (IAAA)

| Pillar | Definition | Example Controls |
|--------|-----------|-----------------|
| **Identification** | Claiming an identity (who are you?) | Username, employee ID, email address, certificate CN |
| **Authentication** | Proving the claimed identity | Password, MFA token, biometric, smart card, FIDO2 key |
| **Authorization** | Determining what the authenticated identity may do | RBAC roles, ABAC policies, ACLs, OAuth scopes |
| **Accounting** | Recording what was done | Audit logs, SIEM events, session recording, access reviews |

### IAM Maturity Model

```
Level 1 – Ad-hoc
  Manual provisioning, shared accounts, no lifecycle management,
  no MFA, spreadsheet-based access tracking.

Level 2 – Defined
  Documented provisioning process, role definitions exist,
  basic MFA deployed, annual access reviews, IdP in place.

Level 3 – Managed
  Automated joiner/mover/leaver (JML), IGA platform deployed,
  PAM for privileged accounts, risk-based MFA, SoD controls,
  quarterly certifications, SCIM provisioning to key apps.

Level 4 – Optimized
  Zero Trust enforcement, continuous access evaluation,
  JIT ephemeral privilege, machine identity governance,
  AI-assisted access reviews, ITDR telemetry, passwordless
  primary auth, full NHI inventory.
```

### Principal Types

| Type | Description | Key Risks |
|------|-------------|-----------|
| **Human Users** | Employees, contractors, partners, customers | Credential theft, phishing, insider threat |
| **Service Accounts** | Non-interactive accounts for applications/services | Password never rotates, over-privileged, orphaned |
| **Machine Identities** | Servers, devices, IoT, certificates | Certificate expiry, stolen private key, sprawl |
| **Workload Identities** | Pods, functions, pipelines, containers | Overly broad IAM roles, token exfiltration |

### Governance vs Management vs PAM

```
IAM Governance        → WHAT access should exist (policy, risk, compliance)
IAM Management        → HOW access is provisioned/de-provisioned (IGA tooling)
PAM                   → WHO gets elevated privilege and WHEN (vaulting, JIT)
```

### IAM Architecture Components

| Component | Acronym | Role |
|-----------|---------|------|
| Identity Provider | IdP | Issues assertions about identity (Okta, Entra ID, Keycloak) |
| Service Provider | SP | Relies on IdP assertions to grant access |
| Policy Decision Point | PDP | Evaluates policy and returns Permit/Deny |
| Policy Enforcement Point | PEP | Intercepts requests and enforces PDP decisions |
| Policy Administration Point | PAP | Where policies are authored and stored |
| Policy Information Point | PIP | Provides attribute data to the PDP |

### Key Standards Reference

| Standard | Version | Purpose |
|----------|---------|---------|
| **SCIM** | 2.0 (RFC 7643/7644) | Automated user provisioning across systems |
| **LDAP** | v3 (RFC 4511) | Directory access protocol; Active Directory transport |
| **OAuth** | 2.1 (draft) | Delegated authorization framework |
| **OpenID Connect** | 1.0 | Identity layer on top of OAuth 2.0 |
| **SAML** | 2.0 | XML-based SSO federation standard |
| **FIDO2** | 1.0 | Passwordless authentication specification |
| **WebAuthn** | Level 2 | W3C API implementing FIDO2 in browsers |
| **XACML** | 3.0 | Policy language for ABAC/PBAC |
| **SPIFFE** | 1.0 | Workload identity framework |

### IAM Failure Modes

- **Verizon DBIR 2024**: 74% of breaches involve the human element; credential-based attacks remain the top initial access vector.
- **Credential stuffing**: Automated use of leaked credential pairs against other services. Countered by MFA, breached password lists, rate limiting, CAPTCHA.
- **Privilege abuse**: Legitimate users exceeding authorized access scope. Detected via UEBA, access reviews, JIT enforcement.
- **Account takeover (ATO)**: Adversary authenticates as a legitimate user. Attack surface includes SIM swap, phishing, adversary-in-the-middle (AiTM), MFA bypass.
- **Orphaned accounts**: Accounts not disabled after offboarding. Exploited for re-entry months after departure.
- **Service account sprawl**: Accumulation of static credentials for applications; rarely rotated or inventoried.

### MITRE ATT&CK — IAM-Relevant Techniques

| Technique ID | Name | Description |
|-------------|------|-------------|
| **T1078** | Valid Accounts | Use of legitimate credentials (local, domain, cloud, default) |
| **T1078.001** | Default Accounts | Factory default credentials on devices |
| **T1078.002** | Domain Accounts | AD domain credentials via password spray, kerberoasting |
| **T1078.004** | Cloud Accounts | Cloud IAM account compromise |
| **T1110** | Brute Force | Password spraying, stuffing, dictionary attacks |
| **T1110.001** | Password Guessing | Targeted credential guessing |
| **T1110.003** | Password Spraying | Low-and-slow to avoid lockout |
| **T1556** | Modify Authentication Process | Skeleton key, DCShadow, AAD backdoor |
| **T1606** | Forge Web Credentials | SAML golden ticket, OAuth token abuse |
| **T1528** | Steal Application Access Token | OAuth token theft from browser/app storage |
| **T1539** | Steal Web Session Cookie | Session hijacking post-authentication |
| **T1621** | Multi-Factor Authentication Request Generation | MFA fatigue/push bombing |

---
---

## 2. Authentication Technologies

### Password Security — NIST SP 800-63B Guidelines

| Requirement | NIST SP 800-63B Guidance |
|------------|--------------------------|
| **Minimum length** | 8 characters (memorized secrets); 6-digit OTPs |
| **Maximum length** | At least 64 characters must be supported |
| **Complexity rules** | NOT mandated — remove composition requirements |
| **Periodic rotation** | NOT required unless compromise is suspected |
| **Breached password check** | REQUIRED — check against known-compromised lists |
| **Password hints/questions** | NOT permitted |
| **Password managers** | ENCOURAGED — do not prevent paste |
| **Lockout** | Implement rate limiting, not hard lockout (allows DoS) |

**Breached Password Check Implementation:**
```python
import hashlib, requests

def is_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
    hashes = dict(line.split(':') for line in r.text.splitlines())
    return int(hashes.get(suffix, 0))
```

### MFA Types — Security Comparison

| MFA Type | Protocol/Spec | Security Level | Phishing Resistant | Notes |
|---------|--------------|---------------|-------------------|-------|
| **TOTP** | RFC 6238 / HOTP+time | Medium | No | 30-second window, SHA-1 HMAC; apps: Google Authenticator, Authy, 1Password |
| **HOTP** | RFC 4226 | Medium | No | Counter-based; synchronization drift issues |
| **SMS OTP** | Telco SS7 | Low | No | SIM swap vulnerable, SS7 interception, number porting |
| **Push Notification** | Vendor | Medium-High | Partial | Duo/Microsoft Authenticator; add number matching + geo context |
| **FIDO2/WebAuthn** | FIDO Alliance / W3C | Very High | Yes | Hardware key or platform authenticator; phishing-proof via rpId |
| **Smart Card / PIV** | PKCS#11 / FIPS 201 | Very High | Yes | DoD CAC, PIV card; requires card reader infrastructure |
| **Biometric** | Platform-specific | Medium-High | Yes | Attack surface: spoof with synthetic fingerprint/face; liveness detection critical |

### FIDO2 / WebAuthn Deep Dive

**Architecture:**
```
Browser (Client)  ←→  Relying Party (Website)  ←→  FIDO Server
      ↕
 Authenticator
  (Platform/Roaming)
```

**Authenticator Types:**

| Type | Examples | Transport |
|------|---------|-----------|
| **Platform** | Windows Hello, Touch ID, Face ID | Built-in (USB internal, NFC internal) |
| **Roaming** | YubiKey, Titan Key, Feitian | USB-A, USB-C, NFC, BLE |

**Attestation Types:**

| Type | Description | Trust Level |
|------|-------------|------------|
| `none` | No attestation provided | Low (accept any) |
| `self` | Signed by the authenticator itself | Low |
| `packed` | FIDO Alliance packed format | Medium-High |
| `tpm` | Signed by TPM endorsement key | High |
| `android-key` | Android Keystore attestation | High |
| `fido-u2f` | Legacy U2F format | Medium |

**Key Concepts:**
```
rpId          → Relying Party ID (domain); prevents cross-origin phishing
                Registration: rpId = "example.com"
                Auth attempt from "evil.com" → REJECTED (different rpId)

AAGUID        → Authenticator AAGUID identifies device model
                Allows enterprise to enforce specific hardware models

Discoverable  → Credential stored on authenticator; no username entry required
Credentials     (formerly "resident keys")

Conditional UI → Browser autofill for passkeys (WebAuthn with mediation:conditional)
```

**Registration Flow:**
```
1. RP sends challenge + rpId + user info
2. Browser calls navigator.credentials.create()
3. Authenticator generates keypair, signs challenge
4. Public key + attestation returned to RP
5. RP stores public key mapped to user
```

**Authentication Flow:**
```
1. RP sends challenge
2. Browser calls navigator.credentials.get()
3. Authenticator signs challenge with private key
4. RP verifies signature against stored public key
5. Access granted
```

### Passkeys (Synced Discoverable Credentials)

| Platform | Storage Backend | Cross-Device Sync |
|---------|----------------|-------------------|
| **Apple** | iCloud Keychain | Yes (Apple devices) |
| **Google** | Google Password Manager | Yes (Android/Chrome) |
| **Microsoft** | Windows Hello / Microsoft Authenticator | Yes (Entra ID joined) |
| **1Password** | Encrypted vault | Yes (cross-platform) |
| **Bitwarden** | Self-hosted or cloud vault | Yes |

**Passkey vs Traditional FIDO2:**
```
Traditional FIDO2:  Credential stored ON device only (not synced)
Passkey:            Credential synced across trusted devices via cloud keychain
                    Trade-off: portability vs single-device security
```

### TOTP Implementation Reference (RFC 6238)

```python
import hmac, hashlib, struct, time, base64

def totp(secret_b32: str, t: int = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper())
    t = t or int(time.time())
    counter = struct.pack('>Q', t // step)
    h = hmac.new(key, counter, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)
```

### Push Notification MFA — Security Controls

```
Number Matching:   User must enter code shown on login screen into push prompt
                   Defeats "yes-fatigue" attacks (MFA fatigue/push bombing)

Geographic Context: Show sign-in location in push; user can identify anomalous
                    location and deny

Additional Context: Show app name, device, and time in push notification

Velocity Limiting: Block/alert on >3 push requests in 1 minute to same user
```

### SIM Swap Attack Mitigation

```
1. Migrate users from SMS OTP to TOTP or FIDO2
2. For SMS-required flows: enable SIM swap detection API (Twilio Verify, etc.)
3. Request port-in validation with carrier
4. Educate users: social engineering vector for SIM swap at carrier stores
5. Monitor: new phone number associations in IdP logs
```

---
---

## 3. Authorization Models

### Role-Based Access Control (RBAC)

**Core Concepts:**
```
User → Role → Permission

Example:
  alice      → security_analyst → [read:logs, write:detections, read:incidents]
  bob        → soc_manager      → [read:logs, read:detections, read:incidents,
                                   approve:escalations]
```

**Role Engineering Approaches:**

| Approach | Method | Best For |
|---------|--------|---------|
| **Top-Down** | Start from business functions, derive roles | Greenfield IAM programs |
| **Bottom-Up** | Mine existing entitlements, cluster into roles | Legacy system cleanup |
| **Hybrid** | Top-down structure, bottom-up validation | Enterprise IGA projects |

**Role Mining (Bottom-Up):**
```python
# Conceptual clustering approach
from sklearn.cluster import KMeans
import numpy as np

# Matrix: users × entitlements (binary)
access_matrix = np.array([...])
kmeans = KMeans(n_clusters=10)  # 10 candidate roles
role_assignments = kmeans.fit_predict(access_matrix)
```

**Role Hierarchy:**
```
Admin
 └── Manager
      └── Analyst
           └── Read-Only
```

**Separation of Duties (SoD) Matrix:**

| | Create PO | Approve PO | Pay Invoice | Create Vendor | Approve Vendor |
|--|:---------:|:----------:|:-----------:|:-------------:|:--------------:|
| Create PO | — | CONFLICT | OK | OK | OK |
| Approve PO | CONFLICT | — | CONFLICT | OK | OK |
| Pay Invoice | OK | CONFLICT | — | OK | OK |
| Create Vendor | OK | OK | OK | — | CONFLICT |
| Approve Vendor | OK | OK | OK | CONFLICT | — |

**Role Explosion Problem:**
```
Symptoms:  Thousands of fine-grained roles; roles for every combination
           of department × location × seniority

Solutions:
  1. Role composition:    Senior_Analyst = Analyst + ThreatHunter
  2. Parameterized roles: Analyst(region=EMEA)
  3. ABAC layer:          Base role + attribute-based conditions
```

**RBAC in Cloud Platforms:**

| Platform | Implementation |
|---------|---------------|
| **AWS IAM** | IAM Roles with attached policies; trust policies for cross-account |
| **Azure RBAC** | Built-in and custom roles; scope: subscription/RG/resource |
| **GCP IAM** | Predefined/custom roles; binding: member + role + resource |

### Attribute-Based Access Control (ABAC)

**Attribute Categories:**
```
Subject Attributes:   user.department, user.clearance, user.location, user.role
Resource Attributes:  document.classification, file.owner, db.environment
Environment Attrs:    time.hour, network.zone, session.mfaCompleted, threat.risk
Action:               read, write, delete, execute, approve
```

**ABAC Policy Example (XACML Conceptual):**
```xml
<Policy>
  <Target>
    <AnyOf><AllOf>
      <Match MatchId="string-equal">
        <AttributeValue>read</AttributeValue>
        <AttributeDesignator Category="action" AttributeId="action-id"/>
      </Match>
    </AllOf></AnyOf>
  </Target>
  <Rule RuleId="allow-cleared-user-in-hours" Effect="Permit">
    <Condition>
      <Apply FunctionId="and">
        <!-- user.clearance >= resource.classification -->
        <!-- environment.time between 0800-1800 -->
        <!-- network.zone = internal -->
      </Apply>
    </Condition>
  </Rule>
</Policy>
```

**OPA/Rego as ABAC Policy Engine:**
```rego
package authz

default allow = false

allow {
    input.user.department == input.resource.owner_dept
    input.user.clearance >= input.resource.classification_level
    is_business_hours
    input.context.mfa_completed == true
}

is_business_hours {
    hour := time.clock(time.now_ns())[0]
    hour >= 8
    hour < 18
}
```

**ABAC in Cloud:**

| Platform | Implementation |
|---------|---------------|
| **AWS** | Condition keys in IAM policies (`aws:PrincipalTag`, `s3:prefix`) |
| **Azure** | ABAC on Storage (blob index tags); Conditional Access for identity |
| **GCP** | IAM Conditions with CEL expressions |

### Policy-Based Access Control (PBAC)

```
PBAC = Centralized external authorization
       Policy authored centrally, evaluated at runtime
       Decoupled from application code

Platforms:
  PlainID        → Business-friendly policy authoring
  Axiomatics     → XACML-based fine-grained authorization
  Styra          → OPA management plane (Declarative Authorization Service)
  AWS Verified   → Permissions policy language (Cedar)
  Access (Cedar)
```

**Cedar Policy Example (AWS Verified Permissions):**
```
permit (
  principal in Group::"finance",
  action == Action::"approve_payment",
  resource in PaymentSystem::"prod"
)
when {
    principal.clearance >= resource.required_clearance &&
    context.mfa_authenticated == true
};
```

### Relationship-Based Access Control (ReBAC)

**Google Zanzibar Model:**
```
Tuple format:  <object>#<relation>@<subject>

Examples:
  doc:budget#viewer@user:alice        (alice can view budget doc)
  doc:budget#editor@group:finance     (finance group can edit)
  group:finance#member@user:bob       (bob is a member of finance)

Derived: bob can edit budget (via group membership → editor relation)
```

**Open Source ReBAC Implementations:**

| System | Language | Notes |
|--------|---------|-------|
| **OpenFGA** | Go | CNCF sandbox; Okta-backed; FGA modeling language |
| **Ory Keto** | Go | Zanzibar-compatible REST/gRPC API |
| **SpiceDB** | Go | Production-grade Zanzibar; AuthZed commercial |
| **Warrant** | Go/TypeScript | SaaS and self-hosted |

**OpenFGA Model Example:**
```
model
  schema 1.1

type user

type document
  relations
    define owner: [user]
    define editor: [user, group#member] or owner
    define viewer: [user, group#member] or editor

type group
  relations
    define member: [user]
```

### Least Privilege Implementation

```
JIT Provisioning:
  1. User requests elevated access
  2. Manager/workflow approves
  3. System grants time-limited role (e.g., 4 hours)
  4. Access automatically revoked at expiry
  5. Session recorded during elevated window

Just-Enough-Access (JEA):
  Instead of: db_admin role (full database access)
  Grant:       read:customers_table WHERE region='EMEA'

Standing Privilege Reduction:
  Target: 0 permanently assigned privileged roles
  Reality: Measure % of admins with standing privilege
  Tool:    Azure PIM, CyberArk, HashiCorp Vault
```

---
---

## 4. Identity Providers & Federation

### Active Directory / Microsoft Entra ID

**Active Directory Domain Services (AD DS):**

| Component | Description |
|-----------|-------------|
| **Domain** | Administrative boundary; DNS namespace |
| **Forest** | Security boundary; collection of domains |
| **Trust** | Cross-domain/forest authentication path (one-way, two-way, transitive) |
| **Kerberos** | Default auth protocol (RFC 4120); AS-REQ/TGT/TGS flow |
| **NTLM** | Legacy challenge-response; vulnerable to pass-the-hash/relay |
| **Group Policy** | Centralized config management via GPOs linked to OUs/domains |
| **AD CS** | PKI: certificate templates, CAs, OCSP, CRL |
| **AD Tiering** | T0 (forest root/DC), T1 (server admin), T2 (workstation admin) |

**AD LDAP Query Examples:**
```ldap
# Find all Domain Admins
(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))

# Find accounts with no password expiry
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Find SPNs for Kerberoasting
(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Find AdminSDHolder-protected accounts
(&(adminCount=1)(objectClass=user))
```

**Entra ID (Azure AD) Components:**

**Conditional Access Policy Structure:**
```
Conditions:
  Users/Groups     → Who
  Cloud Apps       → Which application
  Sign-in risk     → Identity Protection risk level (Low/Medium/High)
  User risk        → User risk score (Low/Medium/High)
  Device platform  → iOS/Android/Windows/macOS
  Location         → Named locations (IP ranges, countries)
  Client apps      → Browser/Mobile/Desktop/Legacy auth
  Device filter    → Compliant/Hybrid joined/specific attributes

Grant Controls (require ALL or ANY):
  Require MFA
  Require compliant device (Intune)
  Require Hybrid AD joined device
  Require approved client app
  Require app protection policy (MAM)
  Require password change (risk remediation)

Session Controls:
  Sign-in frequency    → Re-auth interval (e.g., 4 hours)
  Persistent browser   → Disable "stay signed in"
  MCAS session proxy   → Real-time session monitoring/blocking
  Token binding        → Prevent token theft replay
```

**Entra ID PIM (Privileged Identity Management):**
```
Eligible Assignments:    Role assigned but not active; activation required
Active Assignments:      Immediately usable; limited duration
Just-In-Time:            User activates role on demand (with justification)
Approval Workflow:       Designated approvers must approve activation
Time-Bound:              Assignments expire automatically
Access Reviews:          Periodic review of active/eligible assignments
```

**Entra ID Connect (Hybrid Sync):**
```
Security Considerations:
  - Sync account has DCSync rights in AD — protect it like a Tier 0 asset
  - Pass-through Authentication agent has access to AD DCs
  - Password writeback — cloud can reset AD passwords; review if desired
  - Seamless SSO computer account (AZUREADSSOACC$) — protect this account
  - Staging mode — second server; test sync before cutover
```

### Okta

**Core Components:**

| Component | Function |
|-----------|---------|
| Universal Directory | Master user store with custom attributes |
| Lifecycle Management | Automated provisioning/de-provisioning via SCIM, HR |
| Okta Workflows | No-code automation for complex identity flows |
| FastPass | Passwordless FIDO2-based auth; device trust integrated |
| Okta Verify | Push MFA app with number matching, biometric |
| SCIM Provisioning | Standards-based provisioning to downstream apps |
| Identity Governance | Access certifications, entitlement management |
| SSPM | SaaS Security Posture Management for Okta configuration |

**Okta 2022-2023 Breach Lessons:**
```
2022 Lapsus$:  Support contractor access compromised;
               lesson: restrict support tool access, monitor contractor sessions

2023 HAR file: Customer-uploaded HAR files contained session tokens;
               lesson: scrub credentials from support uploads, use session binding

Mitigations:
  - Phishing-resistant MFA (FIDO2) for all Okta admin access
  - Admin console IP allowlisting
  - Suspicious activity reporting enabled
  - Monitor: admin impersonation events, support tool access logs
```

### Ping Identity

| Product | Function |
|---------|---------|
| **PingFederate** | Enterprise federation server (SAML, OAuth, OIDC) |
| **PingOne** | Cloud IDaaS platform |
| **PingAccess** | Access management with centralized policy |
| **PingDirectory** | High-performance LDAP directory |
| **PingAuthorize** | Fine-grained authorization (ABAC/PBAC) |

### Auth0 by Okta

```
Tenant:          Isolated Auth0 instance (dev/staging/prod separation required)
Applications:    Regular Web / SPA / Native / Machine-to-Machine
APIs:            Resource servers with audience and scope definitions
Actions:         Node.js functions at specific login pipeline points
Organizations:   B2B multi-tenancy; per-org branding and connections

Login Flow:
  Universal Login → Auth0 hosted pages (recommended)
  Classic:        → Embedded Lock widget (CSP issues)

Key Security Settings:
  Brute force protection:  enabled
  Breached password:       enabled
  Attack protection:       IP throttling, bot detection
  Refresh token rotation:  enabled with absolute expiry
  Token binding:           enable where supported
```

### Keycloak

```
Realm:           Top-level namespace; separate realms = isolated tenants
Client:          App registered to authenticate via Keycloak
Client Scope:    Set of claims/roles mapped to client tokens
Identity Provider: External IdP federation (SAML, OIDC, social)
User Federation: Sync from external LDAP/AD (sync or proxy mode)
Themes:          Custom login/email/account UI
SPI:             Service Provider Interface for custom extensions

Security Hardening:
  - Disable master realm admin console access from internet
  - Enable brute force protection (realm settings)
  - Set token lifespans: access=5m, refresh=30m, session=8h
  - Client credential secrets: rotate regularly
  - Audit events: enable all login/admin events, external storage
  - TLS: require HTTPS for all realms in production
```

### SAML 2.0 SSO Flow

```
SP-Initiated Flow:
  1. User → Service Provider (unauthenticated)
  2. SP generates AuthnRequest, redirects to IdP (HTTP Redirect binding)
  3. User authenticates at IdP
  4. IdP generates SAMLResponse (signed assertion)
  5. Browser POST to SP Assertion Consumer Service (ACS)
  6. SP validates signature, extracts attributes, creates session

Key Security Checks:
  - Validate assertion signature against IdP cert
  - Validate NotBefore/NotOnOrAfter timestamps
  - Validate Audience restriction (must match SP entity ID)
  - Validate InResponseTo (prevents replay of unsolicited responses)
  - InResponseTo check requires SP to track outstanding request IDs
```

### OIDC / OAuth 2.1 Flow Reference

```
Authorization Code + PKCE (recommended for all clients):
  1. Client generates code_verifier, code_challenge = SHA256(code_verifier)
  2. Auth request: /authorize?response_type=code&code_challenge=...
  3. User authenticates; auth code returned to redirect_uri
  4. Token exchange: POST /token with code + code_verifier
  5. Server validates: SHA256(code_verifier) == code_challenge
  6. Returns: access_token + id_token + refresh_token

Token Types:
  access_token:   Bearer credential for API calls; short-lived (5-60 min)
  id_token:       JWT with user claims; for client consumption only
  refresh_token:  Long-lived; exchange for new access tokens; rotate on use
```

---
---

## 5. Privileged Access Management

### Privileged Account Types

| Account Type | Description | Risk Profile |
|-------------|-------------|-------------|
| **Local Administrator** | Built-in/created local admin on workstations | Lateral movement via pass-the-hash |
| **Domain Administrator** | AD Domain Admin group membership | Complete domain compromise if stolen |
| **Schema Admin** | Can modify AD schema | Catastrophic — persistent backdoor possible |
| **Service Accounts** | Runs services/applications; often over-privileged | Rarely rotated; often SPNs — Kerberoastable |
| **Application Accounts** | Hardcoded in apps/configs | Shared across teams; never expire |
| **Emergency (Break-Glass)** | Last-resort admin access; rarely used | Must be monitored; requires dual custody |
| **Cloud Root/Owner** | AWS root, Azure Owner, GCP project Owner | Disable root access keys; use only for recovery |

### Privileged Account Risks

```
Lateral Movement:     Stolen admin credential → pivot across entire network segment
Privilege Escalation: Service account → Domain Admin via misconfigured delegation
Credential Theft:     Pass-the-hash (NTLM), Pass-the-ticket (Kerberos TGT/TGS)
Insider Threat:       Authorized admin abuses access (no peer review, no recording)
Kerberoasting:        SPN accounts — request TGS ticket, crack offline
AS-REP Roasting:      Accounts with pre-auth disabled — crack hash offline
```

### Enterprise PAM Platforms

**CyberArk:**
```
Digital Vault:       Encrypted credential repository (AES-256); air-gapped option
CPM (Central Policy Manager):
                     Automated credential rotation per policy
                     Supports: Windows local, domain, service accounts, UNIX, DB
PSM (Privileged Session Manager):
                     Session proxy; keystroke logging, screen capture, video
                     Users never see credentials; isolated RDP/SSH jump
PTA (Privileged Threat Analytics):
                     Behavioral analytics on privileged sessions
                     Detects: golden ticket, abnormal commands, time anomalies

REST API Example:
  # Logon
  POST /PasswordVault/API/auth/Cyberark/Logon
  Body: {"username":"admin","password":"...","concurrentSession":false}
  Returns: session token

  # Get accounts
  GET /PasswordVault/API/Accounts?filter=safeName eq MySafe
  Headers: Authorization: <session_token>

  # Get password
  POST /PasswordVault/API/Accounts/{id}/Password/Retrieve
  Body: {"reason":"Incident INC-12345","ticketingSystemName":"ServiceNow"}
```

**BeyondTrust:**
```
Password Safe:          Credential vaulting and session management
Privileged Remote Access (PRA): Secure vendor/contractor remote access
                        Web-based jump; no VPN required; full session recording
Endpoint Privilege Management (EPM):
                        Least privilege on endpoints; application control
                        Elevate specific apps without giving local admin
```

**Delinea (formerly Thycotic/Centrify):**
```
Secret Server:          On-prem or cloud credential vault
                        Web UI + API; role-based access to secrets
Privilege Manager:      Endpoint least privilege; application whitelisting
Connection Manager:     Session recording and management
```

**One Identity Safeguard:**
```
Safeguard for Privileged Passwords:  Vault and rotation
Safeguard for Privileged Sessions:   Session proxy and recording
Safeguard for Privileged Analytics:  Behavioral analytics
```

### PAM Capabilities Reference

| Capability | Description | Key Metric |
|-----------|-------------|-----------|
| **Credential Vaulting** | Encrypted storage; no plaintext credential exposure | % privileged accounts vaulted |
| **Password Rotation** | Automatic rotation post-checkout or on schedule | Rotation compliance % |
| **Session Recording** | Keystroke + screen capture; tamper-evident storage | Session recording coverage % |
| **JIT Ephemeral Accounts** | Create temp account; delete after session | Standing privilege reduction % |
| **Dual Control** | Second approver required for sensitive systems | Coverage of critical systems |
| **Break-Glass** | Emergency access with immediate notification | Alert within 5 minutes |
| **Secrets Injection** | Inject creds into CI/CD without human exposure | Hardcoded secret count |

### Cloud PAM

**AWS:**
```bash
# STS — Short-Lived Credentials
aws sts assume-role   --role-arn arn:aws:iam::123456789:role/SecurityAudit   --role-session-name incident-response-alice   --duration-seconds 3600

# IAM Identity Center (SSO) — Centralized access
# Users authenticate via IdP → assume permission sets
# No long-term access keys; session-based

# Secrets Manager — Credential Rotation
aws secretsmanager rotate-secret   --secret-id prod/database/admin   --rotation-lambda-arn arn:aws:lambda:...:RotateSecret
```

**Azure:**
```
Entra ID PIM:
  - Eligible assignments require activation (MFA + justification)
  - Maximum activation duration: configurable (e.g., 8 hours)
  - Approval workflow: optional secondary approver
  - Alert on permanent active assignments

Managed Identities:
  - System-assigned: tied to resource lifecycle
  - User-assigned: reusable across resources; manage centrally
  - No credential management; token from IMDS endpoint
```

**HashiCorp Vault — Dynamic Secrets:**
```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/mydb   plugin_name=postgresql-database-plugin   connection_url="postgresql://{{username}}:{{password}}@db:5432/app"   allowed_roles="analyst-role"   username="vault" password="vaultpass"

# Create dynamic role (ephemeral credentials)
vault write database/roles/analyst-role   db_name=mydb   creation_statements="CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}'     VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"   default_ttl=1h max_ttl=4h

# Get ephemeral credentials
vault read database/creds/analyst-role
# Returns: username=v-token-analyst-AbCdEf, password=..., lease_duration=1h
# Vault auto-revokes at TTL expiry; full audit trail
```

**GCP PAM (Preview):**
```
Just-in-time access to Google Cloud resources
Entitlement: defines who can request what role on which resource
Grant: time-limited role binding created on approval
Audit: all requests, approvals, and grants logged to Cloud Audit Logs
```

### PAM KPIs and Metrics

| Metric | Target | Measurement |
|--------|--------|------------|
| **Standing Privilege Reduction %** | >80% reduction | Privileged accounts without standing access / total |
| **Session Recording Coverage %** | 100% of PAM-managed sessions | Recorded sessions / total privileged sessions |
| **Credential Rotation Compliance %** | >95% | Accounts rotated on schedule / total vaulted |
| **Mean Time to Provision (MTTP)** | <2 hours | Time from request to access grant |
| **Mean Time to Deprovision (MTTD)** | <4 hours from termination | Time from HR event to access removal |
| **Break-Glass Events** | <2/month | Track frequency; each requires incident report |
| **Orphaned Service Account %** | <5% | Accounts with no login in 90+ days |

---
---

## 6. Identity Governance & Administration

### IGA Platforms

| Platform | Deployment | Key Strengths |
|---------|-----------|--------------|
| **SailPoint IdentityNow** | SaaS/cloud | AI-powered role management, certifications, access requests, SoD |
| **SailPoint IIQ** | On-prem | Mature, highly customizable, large enterprise |
| **Saviynt** | Cloud-native | Converged IGA+PAM+SSPM; strong cloud coverage |
| **IBM Security Verify Governance** | Hybrid | Deep SAP integration, compliance reporting |
| **One Identity Manager** | On-prem/cloud | Strong AD/Exchange integration, attestation |
| **Omada Identity** | SaaS | European compliance focus, GDPR alignment |
| **Sailpoint IdentityAI** | SaaS | AI-driven peer group analysis for access recommendations |

### Access Certification Campaigns

**Campaign Types:**

| Type | Reviewer | Scope | Frequency |
|------|---------|-------|-----------|
| **Manager Certification** | Direct manager | All direct reports' access | Quarterly |
| **Role Owner Certification** | Business role owner | All members of their role | Semi-annual |
| **Application Owner Certification** | App owner | All accounts with access | Annual or on change |
| **Entitlement Certification** | Entitlement owner | Who has specific permission | Triggered by risk event |
| **Service Account Certification** | IT owner | All service accounts | Annual |

**Certification Fatigue Mitigation:**
```
Risk-Based Filtering:
  - Highlight accounts flagged by UEBA as anomalous
  - Surface accounts not used in 60+ days (likely orphaned)
  - Flag SoD violations for mandatory review
  - Auto-approve low-risk, recently certified, fully-used entitlements

Reviewer Guidance:
  - Show last login date, access frequency, peer comparison
  - One-click revoke with reason code
  - Mobile-friendly reviewer UI

Automated Revocation:
  - No response in 7 days → escalate to manager's manager
  - No response in 14 days → auto-revoke (documented policy)
  - Notify user of access removal
```

### Joiner-Mover-Leaver (JML) Lifecycle

**Joiner Process:**
```
Trigger:  HR system event (new hire record created)
Step 1:   IGA receives HR event (real-time via API or daily feed)
Step 2:   Create identity in IdP (Entra ID / Okta)
Step 3:   Assign baseline role based on job code / department
Step 4:   Provision downstream apps via SCIM (email, HRIS, ticketing)
Step 5:   Generate email/welcome packet with temp credentials
Step 6:   Assign equipment (laptop, badge) via ServiceNow integration
Step 7:   Day-1: Manager completes access request for additional apps
SLA:      Account ready before first day of work
```

**Mover Process:**
```
Trigger:  HR position change event (transfer, promotion, org change)
Step 1:   IGA detects delta in HR role/department
Step 2:   New baseline roles assigned per new job code
Step 3:   Previous department roles removed (default: remove all old roles)
Step 4:   Trigger certification campaign for any retained access
Step 5:   Manager must re-approve retained access within 5 days
Step 6:   Provision new apps; de-provision apps no longer needed
Risk:     "Accumulation of access" — roles accumulate across multiple moves
```

**Leaver Process:**
```
Trigger:  HR termination event (voluntary/involuntary)
SLA:      Involuntary: disable within 1 hour; Voluntary: end of last day

Step 1:   Disable AD/Entra ID account (blocks all SSO-federated apps)
Step 2:   Revoke all active sessions (Okta: /api/v1/users/{id}/sessions)
Step 3:   Disable all downstream app accounts
Step 4:   Revoke cloud IAM access (AWS, Azure, GCP)
Step 5:   Remove from all distribution lists and shared mailboxes
Step 6:   Disable MFA tokens and app passwords
Step 7:   Revoke VPN certificates
Step 8:   Notify IT for equipment retrieval
Step 9:   Retain account in disabled state for 90 days (litigation hold)
Step 10:  Archive mailbox per retention policy
```

### Separation of Duties (SoD)

**SoD Design Principles:**
```
1. Identify all business-critical transactions
2. For each transaction: identify create/approve/execute steps
3. Create/Approve must always be different people (minimum)
4. Define SoD matrix: conflicting role pairs
5. Enforce preventively in IGA access request workflow
6. Report violations detectivly in SIEM and IGA dashboard
7. For approved violations: document compensating control + review quarterly
```

**Common SoD Conflicts:**

| Domain | Conflict Pair | Risk |
|--------|-------------|------|
| Finance | Create PO + Approve PO | Fraudulent purchasing |
| Finance | Create Vendor + Approve Vendor | Fictitious vendor fraud |
| Finance | Record Expense + Approve Expense | Expense fraud |
| IT | Deploy Code + Approve Deployment | Unauthorized code release |
| IT | Create User + Assign Admin Rights | Privilege escalation |
| HR | Create Payroll + Process Payroll | Payroll fraud |
| Audit | System Access + Audit Own Access | Concealment |

### SCIM 2.0 Implementation

**RFC 7644 API Endpoints:**
```http
# List users
GET /scim/v2/Users
  ?filter=email eq "alice@corp.com"
  ?startIndex=1&count=100

# Create user
POST /scim/v2/Users
Content-Type: application/scim+json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "alice@corp.com",
  "name": {"givenName": "Alice", "familyName": "Smith"},
  "emails": [{"value": "alice@corp.com", "primary": true}],
  "active": true
}

# Update user (PATCH preferred over PUT)
PATCH /scim/v2/Users/{id}
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {"op": "replace", "path": "active", "value": false},
    {"op": "remove", "path": "roles[value eq "analyst"]"}
  ]
}

# Bulk operations
POST /scim/v2/Bulk
{
  "Operations": [
    {"method": "POST", "path": "/Users", "data": {...}},
    {"method": "PATCH", "path": "/Users/123", "data": {...}}
  ]
}
```

**SCIM Group Provisioning:**
```http
POST /scim/v2/Groups
{
  "displayName": "Security Analysts",
  "members": [
    {"value": "user-id-1", "display": "alice@corp.com"},
    {"value": "user-id-2", "display": "bob@corp.com"}
  ]
}
```

### Orphan Account Detection

```python
# Conceptual: correlate HR active employees vs IdP accounts
def find_orphans(hr_employees: set, idp_users: list) -> list:
    orphans = []
    for user in idp_users:
        if user['status'] == 'active':
            if user['employee_id'] not in hr_employees:
                orphans.append({
                    'username': user['login'],
                    'last_login': user['last_login'],
                    'reason': 'not in HR system'
                })
    return orphans

# KQL: Orphan account activity detection
# Find active logins from accounts not in HR feed (updated daily)
# SigninLogs
# | where TimeGenerated > ago(7d)
# | join kind=leftanti HRActiveEmployees on $left.UserPrincipalName==$right.Email
# | where ResultType == 0
# | summarize count() by UserPrincipalName, IPAddress
```

---
---

## 7. Zero Trust Identity

### NIST SP 800-207 — Zero Trust Architecture Principles

```
1. All data sources and computing services are considered resources
2. All communication is secured regardless of network location
3. Access to individual enterprise resources is granted per-session
4. Access to resources is determined by dynamic policy including:
   - Client identity + application/service + requesting asset state
   - May include other behavioral and environmental attributes
5. Enterprise monitors and measures integrity/security posture of all assets
6. Resource authentication and authorization is dynamic and strictly enforced
7. Enterprise collects data about asset state, traffic, and access patterns
   and uses it to improve security posture
```

### BeyondCorp Model (Google)

```
Traditional Model:  "Trust but verify" — VPN grants network access → implicit trust
BeyondCorp Model:   "Never trust, always verify"

Components:
  Device Inventory:     Cryptographic device identity; enrollment required
  User Identity:        IdP-based authentication; MFA required
  Access Proxy (IAP):   All app access via Identity-Aware Proxy
  Context Engine:       Evaluates device + user + context per request

Flow:
  User → IAP → Context Check → Policy Decision → App
                    ↓
           [device trust + user risk +
            geo + time + app sensitivity]

Result:   VPN eliminated; access granted per-application per-session
          Every request re-evaluated; no persistent network trust
```

### Conditional Access as Zero Trust Enforcement

**Entra ID Conditional Access — Full Policy Structure:**

```
Policy: "Require MFA and Compliant Device for Sensitive Apps"

Assignments:
  Users:          All users, Exclude: Break-glass accounts, Service accounts
  Cloud Apps:     Include: Microsoft 365, Salesforce, Workday
  Conditions:
    Sign-in risk: ≥ Medium
    Device platforms: Any
    Locations: All trusted locations excluded
    Client apps: All

Access Controls (Require ALL):
  ☑ Require multi-factor authentication
  ☑ Require device to be marked as compliant

Session Controls:
  Sign-in frequency: 4 hours
  Persistent browser session: Disabled
```

**Conditional Access Gap Analysis — What If Tool:**
```
Purpose:  Simulate policy evaluation for specific user/app/condition scenarios
          Identify gaps before deploying restrictive policies

Questions to answer:
  "What happens when alice@corp.com accesses Salesforce from Singapore at 2am?"
  "Which policies apply to external consultants accessing SharePoint?"
  "Is there any path to M365 without MFA?"

Entra portal: Azure AD → Security → Conditional Access → What If
```

**Named Locations Configuration:**
```json
{
  "displayName": "Corporate Network",
  "isTrusted": true,
  "ipRanges": [
    {"cidrAddress": "203.0.113.0/24"},
    {"cidrAddress": "198.51.100.0/24"}
  ]
}
```

### Identity Security Posture Management (ISPM) / ITDR

**Emerging Tools:**

| Tool | Focus | Key Capabilities |
|------|-------|----------------|
| **Silverfort** | Agentless MFA extension | MFA for legacy protocols (NTLM, Kerberos, RADIUS, WMI) |
| **Ermetic / Tenable CIEM** | Cloud identity risks | Unused permissions, privilege escalation paths, toxic combos |
| **CrowdStrike Falcon Identity** | Identity threat detection | AD + ITDR; real-time attack detection |
| **Varonis** | Data + identity | Data access governance; identity-based data exposure |
| **Oort (Cisco)** | Identity posture | SaaS identity risk, MFA gap detection |
| **Push Security** | Browser-based ISPM | SaaS discovery, shadow IT, identity risk in browser |

### Entra ID Protection — Risk Detections

| Detection | Category | Description |
|-----------|---------|-------------|
| **Leaked Credentials** | Offline | Credentials found in dark web/breach dumps |
| **Anonymous IP Address** | Real-time | Tor, VPN, known anonymizer |
| **Atypical Travel** | Offline | Auth from geographically impossible locations |
| **Malware-Linked IP** | Real-time | IP associated with botnet/malware C2 |
| **Unfamiliar Sign-in Properties** | Real-time | New device, location, or browser fingerprint |
| **Suspicious Inbox Rules** | Offline | Rules forwarding to external; BEC indicator |
| **Password Spray** | Offline | Low-and-slow pattern across many accounts |
| **Token Issuer Anomaly** | Real-time | SAML/OIDC token anomalies |
| **Admin Confirmed Compromised** | Manual | Security team marks account compromised |

**Risk-Based Policy Responses:**
```
Sign-in risk policy:
  Low risk    → Allow (log)
  Medium risk → Require MFA at sign-in
  High risk   → Block or require password change + MFA

User risk policy:
  Low risk    → Monitor
  Medium risk → Require secure password change
  High risk   → Block sign-in; require admin intervention
```

### Continuous Authentication Signals

```
Signal Type             Assessment Method                 Weight
─────────────────────────────────────────────────────────────────
Device Health           Compliance state (Intune MDM)      High
MFA Completed           Within session window              High
Location                Named location / country           Medium
Behavioral Biometrics   Typing cadence, mouse patterns     Medium
Network Context         Corporate IP, known VPN endpoint   Medium
Time of Day             Business hours vs. off-hours       Low
Impossible Travel       Velocity check between locations   High
Peer Group Behavior     Compared to role peer group        Medium
Session Duration        Unusually long or active session   Low
Resource Sensitivity    Classification of requested data   High

Continuous Access Evaluation (CAE):
  CAEP (Continuous Access Evaluation Protocol) — SSE standard
  IdP pushes revocation events to resource server in near-real-time
  Events: user disabled, password changed, MFA revoked, high risk
  Resource server terminates active sessions within seconds
  Entra ID + Exchange/SharePoint/Teams: CAE enabled by default
```

### Zero Trust Maturity Model (CISA)

```
Stage 1 – Traditional
  Implicit trust; VPN-based; perimeter security; manual identity lifecycle

Stage 2 – Initial
  MFA deployed; identity-aware proxy for some apps; MDM enrolled devices
  Some attribute-based policies; manual SoD controls

Stage 3 – Advanced
  Identity is perimeter; CA policies for all apps; FIDO2/passwordless
  Real-time risk signals; continuous session evaluation; automated JML
  Machine identity governance; cloud IAM least privilege enforced

Stage 4 – Optimal
  Fully automated identity orchestration; AI-driven access decisions
  Zero standing privilege; ITDR integration; all workload identity governed
  CAEP/SSE real-time revocation; behavioral baselines for all principals
```

---
---

## 8. Machine Identity & Workload Identity

### Machine Identity Management

**Certificate Lifecycle:**
```
Issue → Install → Monitor → Rotate → Revoke

ACME Protocol (RFC 8555):
  1. Client proves domain control (DNS-01, HTTP-01, TLS-ALPN-01 challenge)
  2. ACME server issues certificate
  3. Client installs and auto-renews (certbot, acme.sh)

Let's Encrypt:  Free; 90-day certs; auto-renewal required
ZeroSSL:        Free; 90-day certs; ACME compatible
Internal CA:    On-prem PKI (AD CS, EJBCA, Vault PKI) for internal services
```

**Certificate Sprawl Problem:**
```
Symptoms:
  - No central inventory of certificates
  - Certificates expire unexpectedly (service outages)
  - Certificates with 5-year lifespans
  - Unknown certificates on production systems
  - Same private key reused across systems

Solution Stack:
  Discovery:    Venafi, Keyfactor, Sectigo (agentless network scan + CA integration)
  Monitoring:   Alert 60/30/14/7 days before expiry
  Automation:   ACME renewal; Vault PKI; cert-manager (Kubernetes)
  Policy:       Max 1-year validity; no SHA-1; RSA 2048 minimum / P-256 preferred
```

**Venafi Enterprise Certificate Management:**
```
Trust Protection Platform:
  - Discovers all certificates (network scan, CA integration, cloud)
  - Policy enforcement: algorithm, key size, validity, SAN requirements
  - Auto-renewal workflows with approval
  - REST API: /vedsdk/certificates/ for programmatic management
  - Integration: HashiCorp Vault, Kubernetes cert-manager, CI/CD pipelines
```

### Service Account Governance

```
Inventory:      Document every service account with:
                  Purpose, owning application, owning team, creation date
                  Permissions granted, last password rotation, last login

Principles:
  1. One service account per application (no sharing)
  2. Minimum required permissions (least privilege)
  3. Disable interactive login where possible
  4. Enforce password rotation or migrate to managed identity
  5. Alert on interactive login for non-interactive accounts
  6. Disable accounts not used in 90 days (after investigation)

Managed Identities (Azure) / Instance Profiles (AWS):
  Eliminate static service account credentials entirely
  Token retrieved from IMDS; auto-rotated by platform
  Scope to specific resources; audit via cloud logs
```

### Workload Identity Federation

**GitHub Actions → AWS:**
```yaml
# GitHub Actions workflow with OIDC (no static credentials)
jobs:
  deploy:
    permissions:
      id-token: write   # Required for OIDC token
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/GitHubActionsDeployRole
          aws-region: us-east-1
          # No access keys needed — OIDC token exchanged for STS credentials
```

**AWS IAM Trust Policy for GitHub OIDC:**
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:MyOrg/MyRepo:ref:refs/heads/main"
      }
    }
  }]
}
```

**Azure Federated Credentials:**
```bash
az ad app federated-credential create   --id <app-object-id>   --parameters '{
    "name": "github-actions-prod",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:MyOrg/MyRepo:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

**GCP Workload Identity Federation:**
```bash
gcloud iam workload-identity-pools create github-pool   --location=global --display-name="GitHub Actions Pool"

gcloud iam workload-identity-pools providers create-oidc github-provider   --location=global --workload-identity-pool=github-pool   --issuer-uri="https://token.actions.githubusercontent.com"   --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository"

# Grant service account impersonation
gcloud iam service-accounts add-iam-policy-binding deploy-sa@project.iam.gserviceaccount.com   --role="roles/iam.workloadIdentityUser"   --member="principalSet://iam.googleapis.com/projects/.../locations/global/workloadIdentityPools/github-pool/attribute.repository/MyOrg/MyRepo"
```

### SPIFFE / SPIRE — Workload Identity

```
SPIFFE (Secure Production Identity Framework For Everyone):
  Standard for workload identity in distributed systems
  SVID (SPIFFE Verifiable Identity Document):
    X.509-SVID: Certificate with SPIFFE ID in SAN URI field
    JWT-SVID:   JWT token with SPIFFE ID as subject
  SPIFFE ID format: spiffe://trust-domain/path
  Example:         spiffe://prod.corp.com/ns/payments/sa/payment-service

SPIRE (SPIFFE Runtime Environment):
  SPIRE Server:  Root of trust; issues SVIDs; manages attestation
  SPIRE Agent:   Runs on each node; attests workloads; delivers SVIDs
  Workload API:  Unix domain socket; workloads fetch SVIDs automatically

Attestation Methods:
  Node:      AWS IID, GCP GCE metadata, TPM-based, x509 cert
  Workload:  Kubernetes pod metadata, Unix UID/GID, Docker container ID
```

### Secrets Rotation Automation

**AWS Secrets Manager:**
```python
# Lambda rotation function template
import boto3, json

def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    client = boto3.client('secretsmanager')

    if step == 'createSecret':
        # Generate new password
        new_secret = generate_password()
        client.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                SecretString=json.dumps({'password': new_secret}),
                                VersionStages=['AWSPENDING'])
    elif step == 'setSecret':
        # Apply new password to database
        pending = client.get_secret_value(SecretId=arn, VersionStage='AWSPENDING')
        update_database_password(json.loads(pending['SecretString'])['password'])
    elif step == 'testSecret':
        # Verify new password works
        test_database_connection(arn, 'AWSPENDING')
    elif step == 'finishSecret':
        # Promote AWSPENDING to AWSCURRENT
        client.update_secret_version_stage(SecretId=arn,
            VersionStage='AWSCURRENT', MoveToVersionId=token)
```

**Detecting Hardcoded Secrets in CI/CD:**
```yaml
# GitHub Actions — Secret Scanning with Gitleaks
- name: Scan for hardcoded secrets
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

# TruffleHog
- name: TruffleHog scan
  uses: trufflesecurity/trufflehog@main
  with:
    path: ./
    extra_args: --only-verified
```

### Service Mesh mTLS (Mutual TLS)

**Istio mTLS:**
```yaml
# Enforce strict mTLS across namespace
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # Reject non-mTLS traffic

# Fine-grained AuthorizationPolicy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/checkout-service"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/v1/charge"]
```

**Certificate Rotation in Mesh:**
```
Istio:   Citadel (istiod) issues workload certs; 24h TTL by default
         Automatic rotation before expiry
         SPIFFE SVIDs used as peer identity (mTLS CN)

Linkerd: Built-in certificate rotation; 24h leaf certs
         anchor.crt (root, long-lived) → issuer.crt → leaf (24h)
         linkerd-viz for certificate expiry monitoring
```

---
---

## 9. IAM Security Monitoring

### Threat Detection Use Cases

**1. Credential Stuffing**
```
Indicators:
  - High volume failed logins from distributed source IPs
  - Account-level: multiple failures then success (breakthrough)
  - User-agent: automated/scripted patterns
  - Geographic diversity of source IPs

KQL Detection (Entra ID):
  SigninLogs
  | where TimeGenerated > ago(1h)
  | where ResultType != 0
  | summarize FailedAttempts = count(),
              UniqueIPs = dcount(IPAddress),
              UserAgents = make_set(UserAgent)
    by UserPrincipalName
  | where FailedAttempts > 10 and UniqueIPs > 5
  | order by FailedAttempts desc

Mitigations: Smart lockout, CAPTCHA after N failures, IP-based rate limiting,
             MFA enforcement, breached password blocking
```

**2. Impossible Travel**
```
Logic:
  Successful auth from Location A, then successful auth from Location B
  within time T where physical travel is impossible (velocity > 900 km/h)

KQL:
  SigninLogs
  | where ResultType == 0
  | project UserPrincipalName, TimeGenerated, Location, IPAddress,
            Latitude=LocationDetails.geoCoordinates.latitude,
            Longitude=LocationDetails.geoCoordinates.longitude
  | sort by UserPrincipalName, TimeGenerated asc
  | extend PrevLat = prev(Latitude), PrevLon = prev(Longitude),
           PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
  | where PrevUser == UserPrincipalName
  | extend HoursDelta = datetime_diff('hour', TimeGenerated, PrevTime)
  | extend DistKm = geo_distance_2points(toreal(Longitude), toreal(Latitude),
                                         toreal(PrevLon), toreal(PrevLat)) / 1000
  | extend SpeedKmH = DistKm / max_of(HoursDelta, 0.083)  // min 5 min
  | where SpeedKmH > 900
  | project UserPrincipalName, TimeGenerated, Location, PrevTime,
            DistKm, SpeedKmH, IPAddress
```

**3. MFA Fatigue / Push Bombing**
```
Indicators:
  - High volume of MFA push requests to single user in short window
  - User receives 20+ pushes in 1 hour → eventually approves
  - Often combined with password spray (attacker has password)

SPL Detection (Splunk):
  index=okta sourcetype=okta:im2 eventType=system.push.send_factor_verify_push
  | stats count by actor.alternateId _time span=1h
  | where count > 10
  | eval alert="MFA Fatigue Possible: " + actor.alternateId

Mitigations:
  - Number matching (user must enter code shown at login)
  - Additional context (show app, location, device in push)
  - Velocity limiting (max 5 push attempts per 10 minutes)
  - Okta: FastPass (FIDO2) — no push; phishing resistant
```

**4. Service Account Interactive Login**
```
KQL:
  SigninLogs
  | where UserType == "ServicePrincipal" or
          UserPrincipalName has_any ("svc-", "sa-", "-svc", "_svc")
  | where ClientAppUsed !in ("Microsoft Graph", "Azure Active Directory PowerShell")
  | where AppDisplayName != "Service Account Expected App"
  | project TimeGenerated, UserPrincipalName, AppDisplayName,
            IPAddress, ResultType, ConditionalAccessStatus
  | where ResultType == 0
```

**5. Privilege Escalation Events**
```
KQL (Azure RBAC changes):
  AzureActivity
  | where OperationNameValue has_any ("roleAssignments/write", "roleDefinitions/write")
  | where ActivityStatusValue == "Success"
  | extend role_assigned = tostring(parse_json(Properties).requestbody)
  | project TimeGenerated, Caller, OperationNameValue,
            ResourceGroup, SubscriptionId, role_assigned
  | where Caller !in (known_privileged_admins)
```

**6. Dormant Account Sudden Activity**
```
Logic:
  Account with no sign-in in past 90 days suddenly authenticates
  High risk: termination evasion, compromised stale account

KQL:
  let dormant_users = SigninLogs
  | where TimeGenerated between (ago(90d)..ago(1d))
  | summarize LastLogin = max(TimeGenerated) by UserPrincipalName
  | where LastLogin < ago(90d);
  SigninLogs
  | where TimeGenerated > ago(1d)
  | where ResultType == 0
  | join kind=inner dormant_users on UserPrincipalName
  | project UserPrincipalName, TimeGenerated, IPAddress,
            Location, AppDisplayName, LastLogin
```

### UEBA for IAM

**Core UEBA Capabilities:**

| Capability | Description |
|-----------|-------------|
| **Behavioral Baseline** | ML model of normal behavior per user/entity over 30-90 days |
| **Peer Group Comparison** | Compare user to peers in same role/department/location |
| **Risk Score Accumulation** | Multiple low-risk signals combine into high-risk alert |
| **Entity Timeline** | Unified view of all events for a user across all data sources |
| **Anomaly Detection** | Statistical deviation from historical baseline |

**Exabeam / Securonix — Risk Signals:**
```
Session risk:     Login from new country (+30 points)
                  New device (+20 points)
                  Off-hours access to sensitive system (+25 points)
Activity risk:    Bulk download of files (+40 points)
                  Access to peer-rare application (+35 points)
                  Lateral movement indicators (+50 points)
Threshold:        Risk score > 90 → automated alert to SOC
                  Risk score > 75 → watchlist; enhanced logging
```

**Microsoft Sentinel UEBA:**
```kql
// Entity behavior anomaly for users
BehaviorAnalytics
| where TimeGenerated > ago(7d)
| where ActivityType == "LogonAttempt"
| where InvestigationPriority > 5
| project TimeGenerated, UserName, ActivityInsights,
          InvestigationPriority, SourceIPAddress, DeviceName
| order by InvestigationPriority desc
```

### IAM Audit Logging Requirements

**Events to Log (Mandatory):**

| Category | Events |
|---------|-------|
| **Authentication** | Success/failure for all auth methods, MFA success/failure, session creation/termination |
| **Authorization** | Access denied events, policy evaluation outcomes (for sensitive resources) |
| **Privileged Operations** | Role assignments, policy changes, permission grants/revocations |
| **Provisioning** | Account created/modified/disabled/deleted, group membership changes |
| **Credential Operations** | Password changes/resets, MFA enrollment/removal, API key creation/rotation |
| **Federation** | SAML assertions, OAuth token issuance, federation config changes |
| **Administrative** | Admin console access, configuration changes, export/bulk operations |

**Log Retention:**
```
SOC 2:      Retain audit logs for audit period + 1 year (typically 2 years)
PCI DSS:    Retain for 12 months; 3 months immediately available
HIPAA:      Retain for 6 years from creation or last use
NIST 800-53: Retain per AU-11 organizational requirement (typically 3 years)
ISO 27001:  Retain per documented policy (typically 1-3 years)
```

### Detection Engineering — IAM Query Examples

**Entra ID Conditional Access Failure (Blocked by Policy):**
```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ConditionalAccessStatus == "failure"
| extend ca_policies = parse_json(ConditionalAccessPolicies)
| mv-expand ca_policies
| extend policy_name = tostring(ca_policies.displayName)
| extend enforcement = tostring(ca_policies.enforcedGrantControls)
| summarize count() by UserPrincipalName, policy_name, IPAddress
| order by count_ desc
```

**OAuth Application Consent Granted:**
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Consent to application"
| extend app_name = tostring(TargetResources[0].displayName)
| extend granted_by = tostring(InitiatedBy.user.userPrincipalName)
| extend permissions = tostring(AdditionalDetails)
| project TimeGenerated, granted_by, app_name, permissions
| where permissions has "Mail.ReadWrite" or permissions has "Files.ReadWrite.All"
```

---
---

## 10. IAM Governance & Compliance

### Regulatory Requirements Mapping

**SOC 2 — Common Criteria 6 (Logical and Physical Access Controls):**
```
CC6.1:  Logical access security software, infrastructure, and architectures
        → MFA, RBAC, least privilege, access reviews
CC6.2:  Prior to issuing system credentials, user registration and authorization
        → Formal provisioning process, IGA platform, approvals
CC6.3:  Role-based access controls and privilege management
        → RBAC implementation, SoD, PAM
CC6.6:  Logical access security measures to protect against threats from outside
        → Conditional access, FIDO2, session controls
CC6.7:  Transmission of data to third parties requires authorization
        → OAuth scopes, data sharing agreements
CC6.8:  Unauthorized or malicious software prevented
        → Endpoint controls (related to identity)
```

**ISO 27001:2022 — Annex A.8 (Technological Controls) — Identity:**
```
A.8.2  Privileged access rights          → PAM, JIT, PIM
A.8.3  Information access restriction    → RBAC, least privilege
A.8.5  Secure authentication             → MFA, FIDO2, password policy
A.8.6  Capacity management              → (less identity-specific)
A.8.18 Use of privileged utility programs → Privileged access controls
A.8.35 Secure development lifecycle      → Service account governance in SDLC
```

**PCI DSS v4.0 — Requirements 7 & 8:**

| Requirement | Description | IAM Control |
|------------|-------------|------------|
| **7.1** | Access control system implemented | IGA, RBAC implementation |
| **7.2** | Least privilege access | Minimum necessary access |
| **7.3** | All access assigned to accounts, not shared | Unique user IDs mandatory |
| **8.2** | Unique IDs for all users | No shared accounts |
| **8.3** | Strong authentication for all users and admins | MFA required |
| **8.4** | MFA for non-console admin access | FIDO2/TOTP for admin |
| **8.5** | Secure individual non-consumer authentication | Service account controls |
| **8.6** | System/application accounts managed by policy | Service account governance |
| **8.7** | Database access controlled | PAM for database access |

**HIPAA — §164.312(a)(1) — Technical Safeguards:**
```
§164.312(a)(2)(i):  Unique user identification — assign unique name/number
§164.312(a)(2)(ii): Emergency access procedure — break-glass documented
§164.312(a)(2)(iii): Automatic logoff — session timeout required
§164.312(a)(2)(iv): Encryption/decryption — protect ePHI in transit/at rest
§164.312(b):         Audit controls — record/examine activity in systems with ePHI
§164.312(d):         Person or entity authentication — verify user identity
```

**NIST SP 800-53 — AC Control Family:**

| Control | Title | Implementation |
|---------|-------|---------------|
| AC-1 | Policy and Procedures | IAM policy documentation |
| AC-2 | Account Management | IGA platform; JML lifecycle |
| AC-3 | Access Enforcement | PEP enforcement; RBAC/ABAC |
| AC-5 | Separation of Duties | SoD matrix; IGA enforcement |
| AC-6 | Least Privilege | Minimal entitlements; JIT |
| AC-7 | Unsuccessful Login Attempts | Lockout/throttling controls |
| AC-11 | Session Lock | Screensaver + re-auth |
| AC-14 | Permitted Actions Without Identification | Define explicit exceptions |
| AC-17 | Remote Access | VPN/ZTNA/CA policies |
| AC-20 | Use of External Systems | BYOD policy; CA for unmanaged |
| AC-25 | Reference Monitor | PEP cannot be bypassed |

**GDPR — Article 25 (Data Protection by Design):**
```
Access Minimization:
  Only the data strictly necessary for the purpose should be accessible
  IAM implementation: attribute-level access control; field-level encryption

Privacy by Default:
  Maximum privacy settings by default
  Opt-in for data sharing, not opt-out

IAM relevance:
  - Role scoping to minimum necessary personal data fields
  - Purpose-based access control (ABAC with purpose attribute)
  - Access logging for personal data (required for data subject requests)
  - Automated response to access revocation on data subject erasure request
```

### IAM Key Performance Indicators

| KPI | Target | Frequency | Owner |
|-----|--------|-----------|-------|
| **Orphan Account Trend** | Decreasing; <2% of active | Monthly | IGA team |
| **Privileged Account Ratio** | <5% of workforce | Monthly | PAM team |
| **MFA Enrollment Rate** | >98% of users | Monthly | IAM team |
| **Certification Completion Rate** | >95% | Per campaign | IGA team |
| **Mean Time to Provision** | <4 hours for standard | Monthly | IGA team |
| **Mean Time to Deprovision** | <2 hours (involuntary) | Monthly | IGA team |
| **SoD Violation Count** | <10 unapproved | Monthly | GRC team |
| **Standing Privilege Reduction** | >80% YoY | Quarterly | PAM team |
| **Password Reset Volume** | Decreasing (MFA adoption) | Monthly | Help desk |
| **Conditional Access Block Rate** | Trending stable or down | Weekly | Identity team |
| **Identity Secure Score (Entra)** | >80% | Monthly | IAM team |
| **Service Account with Static Creds** | Decreasing toward 0 | Quarterly | Platform team |

### IAM Architecture Patterns

**Centralized vs Federated Identity:**
```
Centralized:
  Single IdP for all apps; all users in one directory
  Pro: Simple governance, single audit trail, unified MFA
  Con: Single point of failure, scaling challenges, merger/acquisition friction

Federated (Hub-and-Spoke):
  Central IdP (hub) federates with department/subsidiary IdPs (spokes)
  SAML/OIDC between organizational boundaries
  Pro: Autonomy at edges, acquisition integration, geographic compliance
  Con: Complex trust relationships, distributed governance

Identity Mesh (Microservices):
  SPIFFE/SPIRE or service mesh mTLS for service-to-service
  Each workload has a cryptographic identity
  Centralized policy (OPA/Styra) evaluates per-request

CIAM vs Workforce IAM:
  CIAM:      Customer Identity (B2C); scale millions; self-service registration;
             social login; progressive profiling; consent management
  Workforce: Employee Identity (B2E); HR-driven; compliance-heavy;
             device trust; full audit; SoD; PAM integration
  B2B:       Partner federation; org-based entitlements; ReBAC for multi-tenancy
```

### Emerging IAM Trends

**Decentralized Identity (W3C DID / Verifiable Credentials):**
```
DID (Decentralized Identifier):
  did:web:example.com / did:ion:EiC... / did:key:z6Mk...
  Resolved to DID Document (public keys, service endpoints)
  User controls their own identifier (no central registry)

Verifiable Credentials (VC):
  Issuer signs credential about Subject → Holder presents to Verifier
  JSON-LD format; selective disclosure with BBS+ signatures
  Use cases: digital driver's license, employee badge, educational credential

Status: Emerging — limited enterprise adoption; government-led (EU Digital Identity Wallet)
```

**CAEP — Continuous Access Evaluation Protocol:**
```
Problem:  OAuth access tokens valid for hours; revocation not immediate
Solution: CAEP allows IdPs to push revocation events to resource servers

Events:
  session.revoked          → Account disabled or force sign-out
  credential.change        → Password or MFA changed
  assurance.level.change   → Authentication downgraded
  device.compliance.change → Device became non-compliant
  token.claims.change      → Risk level increased

SSE (Shared Signals and Events) framework from OpenID Foundation
Implementations: Entra ID (CAE), Cisco Duo, Ping Identity
```

**Non-Human Identity (NHI) as Discipline:**
```
NHI encompasses:
  Service accounts, API keys, OAuth clients, certificates, secrets,
  workload identities, machine identities, RPA bots, AI agents

Discipline maturity:
  1. Inventory all NHI (harder than it sounds)
  2. Assign human owner to each NHI
  3. Govern lifecycle (creation approval, rotation, decommission)
  4. Detect NHI compromise (anomalous API usage patterns)
  5. Zero-standing NHI privilege (dynamic secrets everywhere)

Tools: Astrix Security, Entro, Aembit, Clutch Security
```

**AI-Assisted Access Reviews:**
```
Traditional:     Reviewer clicks "approve" 95% of the time (rubber stamp)
AI-assisted:
  - Peer group comparison: flag outliers vs role cohort
  - Usage analysis: highlight unused permissions (auto-revoke candidate)
  - Risk scoring: surface high-risk entitlements first
  - Recommendation engine: suggest approve/revoke with reasoning
  - Anomaly detection: flag accounts with unusual access patterns

Platforms: SailPoint AI, Saviynt, Omada, Oort, ConductorOne
```

### IAM Maturity Assessment Framework

| Dimension | Level 1 | Level 2 | Level 3 | Level 4 | Level 5 |
|-----------|---------|---------|---------|---------|---------|
| **People** | No dedicated IAM team | IAM role assigned part-time | Dedicated IAM team | IAM + IGA + PAM specialists | IAM CoE with automation engineers |
| **Process** | Ad-hoc, undocumented | Documented; partially followed | Standardized; enforced | Continuously improved | Automated; metrics-driven |
| **Technology** | Spreadsheets, manual | Basic IdP; some SSO | IGA + PAM + MFA | ZT enforcement; ITDR | AI-driven; fully automated |
| **Governance** | None | Annual audit only | Quarterly certifications | Risk-based continuous review | Real-time governance |
| **Compliance** | Reactive | Basic controls | Audit-ready | Proactive monitoring | Predictive risk management |

### Tool Evaluation Criteria (IGA RFP Template)

```
Category                    Weight  Evaluation Criteria
─────────────────────────────────────────────────────────────────
Directory Integration        15%   AD, Entra ID, LDAP; sync latency; scale
Application Connectors       15%   # pre-built connectors; SCIM support; custom
Access Certification         15%   Campaign types; automation; mobile UX; bulk action
Role Management             10%   Mining; composition; SoD enforcement; hierarchy
Joiner-Mover-Leaver         10%   HR system integration; automation depth; SLAs
Access Request & Workflow   10%   Self-service; approvals; re-certification on move
Reporting & Analytics       10%   Compliance reports; dashboards; data export
API & Integration           10%   REST API coverage; SIEM integration; ITSM
Vendor Viability             5%   Support SLA; roadmap; market position
Total Cost of Ownership      5%   License model; impl cost; ongoing admin burden

Scoring: 1-5 per criterion × weight → weighted total
Shortlist: top 3 vendors → proof of concept in lab environment
```

---

## Reference Architecture Diagram

```
                    ┌─────────────────────────────────┐
                    │         HR System (SoR)         │
                    └──────────────┬──────────────────┘
                                   │ JML Events (API/SFTP)
                    ┌──────────────▼──────────────────┐
                    │      IGA Platform (SailPoint/    │
                    │       Saviynt / One Identity)    │
                    │  Lifecycle │ Certifications │ SoD│
                    └──┬─────────┼────────────────┬───┘
                       │ SCIM    │ SCIM            │ SCIM
          ┌────────────▼──┐  ┌──▼──────────┐  ┌───▼──────────┐
          │  IdP / SSO    │  │  PAM Vault  │  │  Cloud IAM   │
          │  (Entra/Okta) │  │(CyberArk/   │  │(AWS/Azure/GCP│
          │  Conditional  │  │ Vault/BTPAM)│  │  PIM/IAM IC) │
          │  Access/CA    │  └─────────────┘  └──────────────┘
          └──────┬────────┘
                 │ SAML/OIDC/OAuth
    ┌────────────┼────────────────────────────────────┐
    ▼            ▼            ▼            ▼           ▼
  M365        Salesforce   ServiceNow   GitHub    Custom App
                                                  (OPA/PEP)
    │            │            │            │           │
    └────────────┴────────────┴────────────┴───────────┘
                              │ All logs
                    ┌─────────▼──────────┐
                    │   SIEM / UEBA      │
                    │  (Sentinel/Splunk/ │
                    │   Exabeam/Securonix│
                    │   ITDR integration)│
                    └────────────────────┘
```

---

## Quick Reference: IAM Standards & Specifications

| Standard | Body | URL |
|---------|------|-----|
| NIST SP 800-63B | NIST | csrc.nist.gov/publications/detail/sp/800-63b |
| NIST SP 800-207 | NIST | csrc.nist.gov/publications/detail/sp/800-207 |
| OAuth 2.1 | IETF | datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1 |
| OpenID Connect 1.0 | OpenID Foundation | openid.net/connect |
| SAML 2.0 | OASIS | docs.oasis-open.org/security/saml/v2.0 |
| FIDO2 / WebAuthn | FIDO Alliance / W3C | fidoalliance.org / w3.org/TR/webauthn-2 |
| SCIM 2.0 | IETF | RFC 7643/7644 |
| SPIFFE | CNCF | spiffe.io |
| W3C DID | W3C | w3.org/TR/did-core |
| Verifiable Credentials | W3C | w3.org/TR/vc-data-model |
| CAEP/SSE | OpenID Foundation | openid.net/wg/sharedsignals |
| XACML 3.0 | OASIS | docs.oasis-open.org/xacml/3.0 |
| PCI DSS v4.0 | PCI SSC | pcisecuritystandards.org |
| HIPAA Security Rule | HHS | hhs.gov/hipaa/for-professionals/security |
| ISO 27001:2022 | ISO | iso.org/standard/82875.html |

---

*Last updated: 2026-05-06 | TeamStarWolf Cybersecurity Reference Library*
