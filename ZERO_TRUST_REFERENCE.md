# Zero Trust Reference — Comprehensive Cybersecurity Guide

> **Version:** 1.0 | **Last Updated:** 2026-04-26 | **Maintained by:** TeamStarWolf

---

## Table of Contents

1. [Zero Trust Fundamentals](#1-zero-trust-fundamentals)
2. [Identity Pillar](#2-identity-pillar)
3. [Device Pillar](#3-device-pillar)
4. [Network Pillar](#4-network-pillar)
5. [Application and Workload Pillar](#5-application-and-workload-pillar)
6. [Data Pillar](#6-data-pillar)
7. [Teleport — Open-Source ZT Infrastructure Access](#7-teleport--open-source-zt-infrastructure-access)
8. [HashiCorp Boundary — Open-Source ZTNA](#8-hashicorp-boundary--open-source-ztna)
9. [Cloudflare Zero Trust](#9-cloudflare-zero-trust)
10. [ZTA Implementation Roadmap](#10-zta-implementation-roadmap)

---

## 1. Zero Trust Fundamentals

### 1.1 Historical Context and John Kindervag's Original Model

Zero Trust was coined by **John Kindervag** in 2010 while he was a principal analyst at Forrester Research. His foundational insight challenged the prevailing "castle-and-moat" security model, which assumed that everything inside the corporate network perimeter could be trusted by default.

Kindervag's original model rested on three core concepts:

1. **Ensure all resources are accessed securely regardless of location.** There is no trusted network — neither the internal LAN nor the cloud nor a VPN tunnel. Every connection must be treated as potentially hostile.
2. **Adopt a least-privilege strategy and strictly enforce access control.** Users and systems should receive only the minimum permissions required to perform their function, and those permissions should expire as soon as the task is complete.
3. **Inspect and log all traffic.** You cannot trust what you cannot see. All packets, sessions, and transactions must be recorded and analysed for anomalous behaviour.

The original Kindervag paper introduced the concept of a **"Protect Surface"** — the smallest possible grouping of data, assets, applications, and services (DAAS) that needs protection — in contrast to the traditional "attack surface reduction" mindset. By shrinking the protect surface to a fine-grained segment, organisations can apply extremely tight controls around exactly what matters.

Kindervag later described a five-step methodology for building a Zero Trust network:

| Step | Action |
|------|--------|
| 1 | Define the protect surface |
| 2 | Map the transaction flows to understand how data moves |
| 3 | Architect a Zero Trust environment around the protect surface |
| 4 | Create a Zero Trust policy |
| 5 | Monitor and maintain the Zero Trust environment |

### 1.2 NIST SP 800-207 Core Tenets

**NIST Special Publication 800-207**, published in August 2020, is the authoritative federal guidance for Zero Trust Architecture (ZTA). It defines Zero Trust as a collection of concepts and ideas designed to minimise uncertainty in enforcing accurate, least-privilege per-request access decisions in information systems and services.

NIST identifies **seven tenets** of Zero Trust:

1. **All data sources and computing services are considered resources.** A network may be composed of multiple enterprise-owned device classes and network enclaves. Personal devices that are allowed to access enterprise resources are also considered resources.

2. **All communication is secured regardless of network location.** Network location alone does not imply trust. Access requests from assets within the enterprise network perimeter must meet the same security requirements as requests from any other network.

3. **Access to individual enterprise resources is granted on a per-session basis.** Trust in the requester is evaluated before access is granted. Access should also be granted with the least privilege needed to complete the task.

4. **Access to resources is determined by dynamic policy.** Policy is the set of access rules based on attributes that an organisation assigns to a subject, data asset, or application. The observable state of client identity, application/service, and the requesting asset are evaluated — and may include other behavioural and environmental attributes.

5. **The enterprise monitors and measures the integrity and security posture of all owned and associated assets.** No asset is inherently trusted. The enterprise evaluates the security posture of the asset when evaluating a resource request.

6. **All resource authentication and authorisation are dynamic and strictly enforced before access is allowed.** This is a constant cycle of obtaining access, scanning and assessing threats, adapting, and continually re-evaluating trust in ongoing communication.

7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture.** Data is used to improve policy creation and enforcement.

**The three overarching principles** that practitioners distil from NIST 800-207:

| Principle | Meaning |
|-----------|---------|
| **Never Trust, Always Verify** | No implicit trust is granted to any user, device, or network segment |
| **Least Privilege Access** | Minimal access rights granted for the minimum duration required |
| **Assume Breach** | Design systems as if the attacker is already inside; limit blast radius |

**Explicit Verification** adds a fourth principle: every access request must be explicitly authenticated and authorised using all available data points including identity, location, device health, service or workload, data classification, and anomalies.

**Inspect All Traffic** rounds out the five commonly cited principles: east-west lateral traffic within a data centre or cloud environment must be inspected, not just north-south traffic crossing the perimeter firewall.

### 1.3 ZTA Logical Components

NIST 800-207 defines three core logical components that make up a ZTA control plane:

#### Policy Engine (PE)

The Policy Engine is the brain of the ZTA. It is responsible for the ultimate decision to grant, deny, or revoke access to a resource. The PE uses enterprise policy and input from external sources (CDM systems, threat intelligence, data access policies, PKI, ID management, SIEM, industry compliance) to make access decisions.

- Consumes signals from identity providers, device health attestation services, threat intelligence feeds, and activity logs
- Evaluates dynamic risk scores in real time
- Can operate in trust algorithm modes: Score-based, Singular Allowing, or Singular Denying
- Communicates decisions to the Policy Administrator

#### Policy Administrator (PA)

The Policy Administrator executes the decision made by the PE. It is responsible for establishing and/or shutting down communication paths between a subject and a resource.

- Generates authentication tokens or credentials for sessions
- Configures the PEP to allow or deny traffic
- May be tightly coupled with the PE in some implementations (combined PE/PA)
- Communicates with Policy Enforcement Points via a secure control plane channel

#### Policy Enforcement Point (PEP)

The Policy Enforcement Point is the system responsible for enabling, monitoring, and eventually terminating connections between a subject and an enterprise resource.

- Sits in the data plane between the user/device and the resource
- Forwards access requests to the PA and receives policies/tokens back
- Can be implemented as: inline gateway, agent on endpoint, reverse proxy, load balancer, API gateway, or firewall rule
- Must be able to terminate sessions dynamically if the PE/PA revokes access mid-session

```
ZTA Architecture Diagram:

CONTROL PLANE
  Policy Engine (Trust decision)
    <-> External Data Sources:
          Threat Intelligence | CDM/SIEM | PKI/CA | IdP (LDAP/SAML/OIDC) | Device Health
  Policy Administrator (Token/session mgmt)
    | (control channel)

DATA PLANE
  Subject (User / Device / Workload)
    --> Policy Enforcement Point (PEP)
          (Inline Gateway / Agent / Proxy)
      --> Enterprise Resource (App/API/Data/Infra)
```

### 1.4 ZTA Deployment Models

NIST 800-207 describes four primary deployment approaches:

#### Device Agent / Gateway Model

- A software agent is installed on all enterprise-managed devices
- The agent communicates device health posture to the PA and receives per-session credentials
- A gateway (PEP) sits in front of resources and validates those credentials
- **Advantage:** Strong device posture enforcement; session-level granularity
- **Limitation:** Requires managed device; BYOD scenarios are more complex

#### Enclave Gateway Model

- Resources are grouped into enclaves (micro-segments)
- A gateway/proxy acts as the PEP for each enclave rather than per-device agents
- Users authenticate to the gateway; the gateway mediates all access into the enclave
- **Advantage:** Suitable for legacy systems that cannot run agents
- **Limitation:** Enclave-level granularity is coarser than per-resource granularity

#### Resource Portal Model

- A single portal (web-based or thick client) serves as the PEP for all resources
- Users authenticate to the portal; the portal brokers access to backend resources
- Similar to a jump server or bastion, but with full ZTA policy enforcement
- **Advantage:** Simple user experience; works for unmanaged/BYOD devices
- **Limitation:** Portal itself becomes a high-value target; single point of failure if not HA

#### Device Application Sandbox Model

- A virtualised or containerised environment on the device isolates enterprise applications
- The sandbox enforces policy about what data can leave the secure container
- **Advantage:** Provides strong isolation even on untrusted devices
- **Limitation:** Complex to manage; performance overhead; user experience trade-offs

### 1.5 CISA Zero Trust Maturity Model

The **Cybersecurity and Infrastructure Security Agency (CISA)** published its **Zero Trust Maturity Model** (ZTMM) to help federal agencies and organisations assess their current state and plan progression. CISA defines **five pillars** and **four maturity stages**.

#### Five Pillars

| Pillar | Description |
|--------|-------------|
| **Identity** | Validates users, non-person entities (NPEs), and attributes to establish trust |
| **Device** | Validates device health, compliance, and configuration |
| **Network/Environment** | Isolates and segments networks; inspects and encrypts all traffic |
| **Application Workload** | Secures applications and APIs; enforces app-layer access control |
| **Data** | Classifies, labels, and controls access to data at rest and in transit |

Three cross-cutting capabilities support all pillars:
- **Visibility and Analytics** — continuous monitoring and threat detection
- **Automation and Orchestration** — automated policy enforcement and response
- **Governance** — policy management, compliance, and risk management

#### Four Maturity Stages

| Stage | Description |
|-------|-------------|
| **Traditional** | Manual configurations, static policies, siloed tools, implicit trust zones exist |
| **Initial** | Some ZT attributes beginning; MFA adopted in places; partial device inventory |
| **Advanced** | Dynamic policies in place; continuous monitoring; automated responses |
| **Optimal** | Fully automated, risk-adaptive policies; ML-driven anomaly detection; real-time policy tuning |

**CISA ZTMM Stage Progression Across Pillars:**

```
PILLAR     TRADITIONAL        INITIAL               ADVANCED              OPTIMAL
Identity   Passwords/no MFA   MFA for some users    Phishing-resistant    Continuous risk-
                                                    MFA; CAE in use       adaptive auth
Device     No inventory/MDM   MDM enrolled;         Compliance signals    Real-time posture;
                              basic checks          feed into policy      auto-remediation
Network    Flat network;      VLANs; basic ACLs     Micro-segmentation;  Dynamic segments;
           perimeter FW only                        encrypted east-west  ML-based anomaly
App        Perimeter access;  App-level auth;       Identity-aware       Continuous app
           all-or-nothing     some SSO              proxy for all apps   risk scoring
Data       Unclassified;      Basic labels;         DLP enforced;        Automated JIT
           no DLP             limited encryption    data-centric policy  data access; DSPM
```

---

## 2. Identity Pillar

### 2.1 Identity as the New Perimeter

In a Zero Trust architecture, **identity replaces the network perimeter** as the primary trust boundary. Because users work from anywhere — home networks, coffee shops, cloud environments, contractor laptops — network location is no longer a reliable proxy for trustworthiness. Instead, every access decision begins with the question: *Who (or what) is making this request, and can that identity be verified with sufficient confidence?*

The identity perimeter encompasses:
- **Human identities:** Employees, contractors, partners, customers
- **Non-person entities (NPEs):** Service accounts, application identities, CI/CD pipelines, automation scripts, IoT devices
- **Workload identities:** Microservices, containers, serverless functions, VMs

A mature identity perimeter relies on a **unified identity fabric** — a set of federated identity providers (IdPs), a consistent attribute schema, and centralised policy enforcement — rather than a patchwork of siloed directory services.

### 2.2 Conditional Access Policies

**Conditional Access (CA)** is the policy engine at the identity layer. It evaluates a set of signals before granting or denying access, and can enforce additional controls (step-up MFA, device enrolment, session restrictions) without blocking legitimate users entirely.

The four primary signal categories for Conditional Access:

| Signal | Examples |
|--------|---------|
| **User/Group Risk** | Sign-in risk score (leaked credentials, impossible travel), user risk score (aggregate risk over time) |
| **Device Compliance** | MDM-enrolled, Intune compliant, BitLocker enabled, antivirus up to date, OS version minimum |
| **Location** | Named locations (trusted IP ranges), country/region allow/deny lists, GPS location (mobile) |
| **Application Sensitivity** | High-sensitivity apps require stronger auth; low-sensitivity apps may allow browser-only sessions |

**Example Microsoft Entra Conditional Access Policy (JSON representation):**

```json
{
  "displayName": "Require MFA for High-Risk Sign-ins to Sensitive Apps",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeGroups": ["All Employees"],
      "excludeGroups": ["Break-Glass Accounts"]
    },
    "applications": {
      "includeApplications": ["SAP ERP", "Finance Portal", "HR System"]
    },
    "signInRiskLevels": ["high", "medium"],
    "devicePlatforms": { "includePlatforms": ["all"] },
    "locations": { "includeLocations": ["All"] }
  },
  "grantControls": {
    "operator": "AND",
    "builtInControls": ["mfa", "compliantDevice", "domainJoinedDevice"]
  },
  "sessionControls": {
    "signInFrequency": { "value": 1, "type": "hours" },
    "persistentBrowser": { "mode": "never" }
  }
}
```

**Policy design principles:**
- Start with **report-only mode** before enforcing; analyse the impact on sign-ins
- Use **named locations** to reduce friction for office networks while adding controls elsewhere
- Apply **session controls** (sign-in frequency, persistent browser) for sensitive apps
- Ensure **break-glass accounts** are excluded from CA policies and are monitored separately
- Layer policies: base policy (all users), elevated policy (sensitive apps), emergency policy (high-risk events)

### 2.3 MFA Enforcement — Phishing-Resistant Priority

**Multi-factor authentication (MFA)** is the single most impactful control an organisation can deploy. However, not all MFA is equal. Traditional SMS OTP and TOTP (authenticator app codes) are vulnerable to real-time phishing attacks (adversary-in-the-middle proxies). Modern ZTA mandates **phishing-resistant MFA** for privileged access and sensitive applications.

**MFA Method Hierarchy (most to least phishing-resistant):**

| Method | Phishing Resistant | Notes |
|--------|-------------------|-------|
| **FIDO2 / Passkeys (platform authenticator)** | Yes | Bound to device; TPM-backed private key; preferred for all users |
| **FIDO2 / Security Keys (hardware token)** | Yes | YubiKey, Google Titan; strongest assurance; required for privileged access |
| **Windows Hello for Business** | Yes | TPM-backed certificate; tied to device |
| **Certificate-Based Auth (CBA)** | Yes | Smart card or software certificate; widely used in government/military |
| **Microsoft Authenticator (number matching)** | Partial | Resistant to MFA fatigue when number matching is enabled |
| **TOTP (authenticator app)** | No | Vulnerable to AITM phishing (e.g., Evilginx2) |
| **SMS / Voice OTP** | No | SIM-swap attacks; SS7 vulnerabilities |
| **Email OTP** | No | Depends on email account security |

**FIDO2 Deployment Considerations:**
- Requires WebAuthn-capable browsers (all modern browsers support this)
- Platform authenticators (Touch ID, Face ID, Windows Hello) provide strong UX with no hardware cost
- Hardware security keys required for environments with shared workstations (kiosk mode)
- Attestation certificates from the authenticator allow organisations to verify authenticator make/model
- FIDO2 relies on **origin binding** — the credential is cryptographically bound to the relying party domain, making phishing impossible (credential will not work on a phishing site)

**Executive Order 14028 requirement:** Federal agencies must use phishing-resistant MFA for all users with access to federal information systems.

### 2.4 Continuous Access Evaluation (CAE)

**Continuous Access Evaluation** is a protocol that allows resource providers (applications) to receive near-real-time notifications of critical security events from the IdP, enabling session revocation without waiting for the OAuth access token to expire.

Traditional OAuth access tokens have a lifespan of 60-90 minutes, creating a window where a stolen token remains valid. CAE addresses this by:

1. **Critical event push from IdP:** When the IdP detects a password change, account disable, MFA method change, or high-risk event, it immediately notifies the resource provider
2. **Claims challenge:** The resource provider issues a claims challenge to the client, requiring re-authentication
3. **Location-based enforcement:** If the client IP changes to a non-compliant location, the resource provider can challenge the session
4. **Token lifetime extension for compliant clients:** CAE-capable clients can receive longer-lived tokens (up to 28 hours) because the IdP can revoke them in real time

**Azure AD / Microsoft Entra CAE:**
- Supported in Microsoft 365, Azure Resource Manager, and third-party apps via the CAE Shared Signals Framework
- Client must send the `xms_cc` claim in the token request to indicate CAE capability
- Resource provider must handle `401` with `WWW-Authenticate: Bearer claims=<base64-encoded-claim>` challenges

**Shared Signals and Events (SSE) / CAEP:**
- The OpenID Foundation's **Continuous Access Evaluation Profile (CAEP)** standardises how IdPs and resource providers exchange security events
- Events include: token claims change, session revoked, assurance level change, device compliance change
- Enables cross-vendor CAE (not just Microsoft-to-Microsoft)

### 2.5 Privileged Identity Management (PIM) — JIT/JEA

**Privileged Identity Management** manages the lifecycle of privileged access to ensure that elevated permissions are used only when needed, by authorised users, for a limited duration.

**Just-In-Time (JIT) Access:**
- Users have **eligible** privileged roles rather than **permanently assigned** ones
- When a user needs elevated access, they **activate** the role for a time-bounded window (e.g., 1-8 hours)
- Activation can require: MFA, business justification, manager approval, ticket number reference
- Access automatically expires; no manual deprovisioning required

**Just-Enough-Access (JEA):**
- Beyond time-limiting, JEA limits the **scope** of privileged access
- Instead of Global Administrator, a user is granted User Administrator only for a specific OU
- PowerShell JEA restricts privileged sessions to a defined set of cmdlets and parameters
- Reduces the blast radius of compromised privileged accounts

**Microsoft Entra PIM Configuration Example:**

```yaml
Role: Global Administrator
Eligible Assignment Duration: 12 months (then require re-review)
Max Activation Duration: 4 hours
On Activation Require:
  - MFA: true
  - Justification: true
  - Ticket Number: true
  - Approval Required: true
  - Approvers: [Security Team, IT Manager]
Notifications:
  - Admin notified on activation: true
  - Alert on permanent assignment: true
```

### 2.6 Service Identity and Workload Identity Federation

Modern applications are composed of many services that communicate with each other and with cloud APIs. These **non-human identities** are a significant attack surface if managed poorly (hardcoded secrets, long-lived API keys, shared service accounts).

**Workload Identity Federation (WIF)** allows workloads to authenticate using short-lived tokens issued by a trusted external IdP (such as GitHub Actions, Kubernetes, or GitLab) rather than long-lived secrets.

**Benefits:**
- No secrets stored in environment variables, CI/CD pipelines, or code
- Token lifetime is short (minutes); reduces exposure window
- Tokens are auditable and attributable to specific workloads

**Example: GitHub Actions authenticating to Azure without secrets:**

```yaml
jobs:
  deploy:
    permissions:
      id-token: write   # Required for OIDC token request
      contents: read
    steps:
      - uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          # No client secret needed -- uses OIDC federation
```

**Managed Identities** (Azure) and **Service Accounts with Workload Identity** (GKE) provide similar capability for workloads running in cloud environments — the cloud platform issues and rotates credentials automatically.

### 2.7 Certificate-Based Authentication for Devices

Certificate-Based Authentication provides strong device identity using X.509 certificates issued to managed devices. Unlike passwords, certificates:
- Cannot be phished (private key never leaves the device TPM)
- Are tied to a specific device (not just a user)
- Can be revoked centrally via CRL or OCSP
- Enable mutual TLS (mTLS) for device-to-service communication

**Certificate lifecycle in a ZTA:**
1. Device enrolled in MDM (e.g., Microsoft Intune, Jamf Pro)
2. MDM issues a SCEP or PKCS certificate request to the enterprise CA (NDES/ADCS or cloud CA)
3. Certificate installed in device TPM / secure keystore
4. Device presents certificate when accessing ZTA-protected resources
5. Certificate validity checked against CRL/OCSP at each access attempt
6. MDM revokes certificate on device unenrollment or compliance failure

### 2.8 Identity Governance

**Identity Governance** ensures that identities and their access rights are continuously reviewed, certified, and aligned with the principle of least privilege.

**Access Reviews:**
- Periodic campaigns requiring managers or resource owners to certify that users still need their access
- Automated provisioning/deprovisioning based on review outcomes
- Risk-based triggering: high-risk users reviewed more frequently

**Entitlement Management:**
- Defines access packages (bundles of group memberships, app roles, SharePoint sites)
- Users request access packages through a self-service portal
- Multi-stage approval workflows; automatic expiration; access reviews on active assignments

**Lifecycle Workflows:**
- Automate identity tasks on joiner/mover/leaver events (HR-driven provisioning)
- Joiners: automatically grant baseline access on hire date
- Movers: adjust access when roles change (remove old, grant new)
- Leavers: disable account, revoke sessions, transfer data on termination date

**Separation of Duties (SoD):**
- Incompatible role combinations detected and blocked (e.g., cannot be both AP clerk and AP approver)
- SoD policies enforced at entitlement management layer

---

## 3. Device Pillar

### 3.1 Device Trust Establishment

In Zero Trust, a **device** must prove its identity and health before it can participate in network communication with enterprise resources. Device trust is established through a combination of:

- **Device identity:** A certificate or managed credential that uniquely identifies the device
- **Device compliance:** A verified posture check confirming the device meets security policy requirements
- **Device attestation:** A cryptographic proof, ideally anchored in hardware (TPM), that the platform security state can be trusted

**Trust levels for device types:**

| Device Category | Trust Level | Access Scope |
|----------------|-------------|-------------|
| Corporate device, MDM-enrolled, compliant | High | Full enterprise resource access |
| Corporate device, MDM-enrolled, non-compliant | Medium | Limited access; remediation portal |
| Corporate device, not MDM-enrolled | Low | Restricted to public-facing resources |
| BYOD, MAM (app-level management) | Low-Medium | Approved apps only; no download to device storage |
| Unmanaged device | Untrusted | Web portal only; no native app; no file download |

### 3.2 MDM Enrollment and Compliance Policies

**Mobile Device Management (MDM)** is the foundational mechanism for establishing corporate control over endpoints.

**Enrollment methods:**
- **Windows Autopilot:** Zero-touch provisioning of new Windows devices; device pre-registered by OEM or IT; user signs in with corporate credentials and device is automatically configured
- **Apple Business Manager / School Manager:** DEP enrollment for macOS and iOS; automatic MDM enrollment on first boot
- **Android Enterprise:** Work Profile (BYOD) or Fully Managed (corporate) enrollment
- **Group Policy-based enrollment:** For existing domain-joined Windows machines

**Compliance Policy Components (Intune):**

| Check | Compliant State | Non-Compliant Action |
|-------|----------------|---------------------|
| OS minimum version | Windows 11 22H2+ | Mark non-compliant; notify user |
| BitLocker encryption | Enabled | Block access to Exchange/SharePoint |
| Secure Boot | Enabled | Mark non-compliant |
| Defender Antivirus | Enabled and updated | Alert IT; restrict access |
| Firewall | Enabled (all profiles) | Notify user |
| No jailbreak/root | Not jailbroken | Block immediately |
| Defender threat level | Secured or Low | Dynamic block on Medium/High/Severe |

### 3.3 Device Health Attestation — TPM-Based

**Trusted Platform Module (TPM)** chips provide the hardware root of trust for device attestation. A TPM is a dedicated security processor on the motherboard that:
- Generates and stores cryptographic keys
- Performs cryptographic operations (signing, sealing, unsealing)
- Records platform measurements in **Platform Configuration Registers (PCRs)** during boot

**TPM-Based Attestation Flow:**

```
1. Device boots -> UEFI firmware measures itself -> stores hash in PCR[0]
2. Boot loader measured -> stored in PCR[4]
3. OS loader measured -> stored in PCR[8]
4. Secure Boot state recorded -> PCR[7]
5. BitLocker key sealed against PCR values -> only unlocks if boot chain is unmodified
6. MDM agent requests attestation report
7. TPM signs a report of PCR values with its Attestation Identity Key (AIK)
8. Report sent to cloud attestation service (Microsoft Azure Attestation)
9. Attestation service verifies TPM signature and PCR values against known-good baselines
10. Attestation result returned to MDM -> compliance state updated
```

**Windows Health Attestation (WHA):**
- Uses the TPM to attest: Secure Boot state, Boot Manager revision, Safe Mode not active, ELAM (Early Launch Anti-Malware) loaded, BitLocker status, Code Integrity state
- Attestation report signed by TPM and verified by Microsoft Azure Attestation service
- Result fed into Intune compliance policy evaluation

**Secure Boot Verification:**
- Ensures only signed bootloaders execute during the boot process
- UEFI Secure Boot validates signatures against the Secure Boot database (db) and block list (dbx)
- TPM PCR[7] records the Secure Boot policy; any tampering changes the PCR value and breaks BitLocker

### 3.4 Device Compliance Policy — Example JSON

```json
{
  "compliancePolicyName": "ZeroTrust-Windows-Compliance-v2",
  "platform": "windows10",
  "settings": {
    "passwordRequired": true,
    "passwordMinimumLength": 12,
    "passwordRequiredType": "alphanumeric",
    "passwordMinutesOfInactivityBeforeLock": 5,
    "requireHealthyDeviceReport": true,
    "osMinimumVersion": "10.0.22621",
    "bitLockerEnabled": true,
    "secureBootEnabled": true,
    "codeIntegrityEnabled": true,
    "storageRequireEncryption": true,
    "activeFirewallRequired": true,
    "defenderEnabled": true,
    "defenderVersion": "4.18",
    "signatureOutOfDate": false,
    "rtpEnabled": true,
    "antivirusRequired": true,
    "antiSpywareRequired": true,
    "deviceThreatProtectionEnabled": true,
    "deviceThreatProtectionRequiredSecurityLevel": "low",
    "tpmRequired": true,
    "tpmMinimumVersion": "2.0"
  },
  "scheduledActionsForRule": [
    {
      "ruleName": "NonCompliantActions",
      "scheduledActionConfigurations": [
        {"actionType": "notification", "gracePeriodHours": 0},
        {"actionType": "block", "gracePeriodHours": 24},
        {"actionType": "retire", "gracePeriodHours": 336}
      ]
    }
  ]
}
```

### 3.5 BYOD vs. Corporate Device Trust Levels

**Corporate Devices** receive full MDM management and the highest trust level:
- Full disk encryption managed by IT (BitLocker / FileVault)
- Configuration profiles push security settings
- MDM can wipe device if lost or stolen
- Compliance certificate issued; presented to PEP for access

**BYOD Devices** receive Mobile Application Management (MAM) without full MDM:
- Corporate data isolated in managed app containers (Microsoft Intune App Protection Policies)
- Copy/paste restrictions between managed and unmanaged apps
- Remote wipe of corporate data only (not personal data)
- Cannot access resources requiring device-level compliance certificates
- Access limited to browser-based or MAM-enrolled app sessions

**BYOD Access Policy Design:**
```
IF device.enrollmentType == "MDM_Corporate"
  THEN allow: AllEnterpriseApps + FileSync + Email
ELSE IF device.enrollmentType == "MAM_BYOD"
  THEN allow: ApprovedMobileApps + WebApps; deny: FileSync; enforce: AppProtectionPolicies
ELSE
  THEN allow: WebPortalOnly; deny: Downloads; enforce: BrowserIsolation
```

### 3.6 EDR as Compliance Signal

**EDR platforms** (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne) provide continuous visibility into endpoint behaviour. In a ZTA, the EDR risk score feeds directly into the compliance policy as a real-time signal.

**EDR-to-ZTA Integration:**
- Microsoft Defender for Endpoint integrates natively with Intune; device risk level (Clean/Low/Medium/High/Severe) updates compliance state in near-real-time
- CrowdStrike Falcon integrates with Okta, Azure AD, and JAMF via APIs; Zero Trust Assessment (ZTA) score exported as an identity signal
- SentinelOne integrates with Okta via the Singularity XDR identity module

**Example: Intune + Defender for Endpoint Risk Integration:**
```
Defender Risk Level -> Intune Compliance State -> Conditional Access Outcome
Clean              -> Compliant                -> Full access granted
Low                -> Compliant                -> Full access granted
Medium             -> Non-compliant            -> Block access; prompt remediation
High               -> Non-compliant            -> Block access; auto-isolate device
Severe             -> Non-compliant            -> Block + alert SOC + quarantine
```

### 3.7 Hardware Security Requirements

Zero Trust mandates minimum hardware security capabilities for corporate-managed devices:

| Requirement | Standard | Purpose |
|------------|---------|---------|
| **TPM 2.0** | TCG TPM 2.0 Specification | Device identity attestation, key storage, measured boot |
| **Secure Boot (UEFI)** | UEFI Specification 2.3.1+ | Prevents unsigned boot code; protects boot chain integrity |
| **HVCI (Memory Integrity)** | Windows WDDM 2.7+ | Hypervisor-protected code integrity; prevents kernel exploits |
| **Kernel DMA Protection** | ACPI firmware requirement | Prevents DMA attacks from PCIe devices before OS loads |
| **Credential Guard** | Windows 10 Enterprise+ | Isolates LSASS in VTL1; prevents credential theft (pass-the-hash) |
| **Pluton Security Processor** | Microsoft Pluton (Surface, select OEMs) | TPM + CPU integration; eliminates bus attack surface |

**Windows 11 Zero Trust Hardware Requirements:**
- TPM 2.0 is mandatory for Windows 11 installation
- Secure Boot must be enabled
- UEFI (no legacy BIOS) required
- Virtualization-Based Security (VBS) enabled by default on compatible hardware

---

## 4. Network Pillar

### 4.1 Micro-Segmentation Strategies

**Micro-segmentation** divides the network into small, isolated zones with precise access controls between them. This replaces the flat network model where all internal hosts could communicate freely, eliminating the lateral movement paths that ransomware and APTs exploit.

**Host-Based Micro-Segmentation:**
- Firewall rules enforced at the OS kernel level on each host (Windows Firewall, Linux nftables/iptables)
- Policy managed centrally by a micro-segmentation platform (Illumio, Guardicore/Akamai, VMware NSX)
- Works regardless of network topology; covers cloud, on-prem, and hybrid equally
- **Advantage:** No network hardware changes needed; instant deployment
- **Limitation:** Requires agent on every workload; complex policy at scale

**Hypervisor-Based Micro-Segmentation:**
- Firewall rules enforced at the virtual switch (vSwitch) level between VMs
- VMware NSX-T Distributed Firewall, Hyper-V Distributed Switch
- Traffic never leaves the hypervisor to be inspected; zero latency overhead
- **Advantage:** Transparent to VMs; no agent required; east-west traffic controlled
- **Limitation:** Only applies to virtualised workloads; does not cover physical hosts or cloud-native

**SDN-Based Micro-Segmentation:**
- Software-Defined Networking controllers (Cisco ACI, Juniper Contrail, OpenStack Neutron) enforce segmentation policies
- Groups are defined by workload attributes (application, tier, environment) rather than IP addresses
- Dynamic group membership: VMs automatically inherit group policies based on tags/labels
- **Advantage:** Centrally managed; policy follows the workload
- **Limitation:** Requires SDN-capable network infrastructure; complex initial deployment

**Micro-Segmentation Design Principles:**
```
1. Map all flows first (passive observation for 30-90 days)
2. Define zones: Internet -> DMZ -> App Tier -> Data Tier -> Management
3. Apply default-deny between zones; create explicit allow rules for mapped flows
4. Start with monitoring mode (log but do not block); validate against mapped flows
5. Enforce deny-by-default; tune exceptions
6. Review flow maps quarterly; remove stale rules
```

### 4.2 Software-Defined Perimeter (SDP) vs. VPN Replacement

**Traditional VPN** problems in a ZTA context:
- Grants broad network-level access once connected (implicit trust zone)
- VPN concentrator is a high-value target (attack surface on public internet)
- No per-application or per-resource access control
- Performance bottleneck (backhauling traffic to corporate DC)
- No visibility into east-west traffic within VPN tunnel

**Software-Defined Perimeter (SDP)**, also called Zero Trust Network Access (ZTNA), addresses these:

| Feature | Traditional VPN | SDP/ZTNA |
|---------|----------------|---------|
| Access scope | Full network segment | Single application / resource |
| Trust model | Network-level implicit trust | Identity + device + context per session |
| Architecture | Perimeter-based concentrator | Distributed PEPs (cloud or on-prem) |
| Visibility | Limited (encrypted tunnel) | Full session logging and inspection |
| Performance | Backhaul to DC | Direct-to-app (optimal routing) |
| Scalability | Concentrator bottleneck | Elastic cloud-hosted PEPs |

**SDP Architecture (CSA SDP Spec):**
- **SDP Controller:** Acts as PE/PA; maintains the authorised host list
- **SDP Client:** Installed on user device; connects only to authorised servers
- **SDP Gateway (PEP):** Sits in front of resources; accepts connections only from authenticated SDP clients
- All communications initiated by the client use **single-packet authorisation (SPA)** — the gateway is dark (not discoverable) to unauthorised sources

### 4.3 Service Mesh for Workload-to-Workload (Istio mTLS)

**Service meshes** enforce Zero Trust between microservices running in Kubernetes or other container orchestration platforms.

**Istio** is the most widely deployed open-source service mesh. Its key ZTA features:

**Automatic mTLS:**
- Each service gets a SPIFFE-format X.509 certificate issued by Istio's Certificate Authority
- All service-to-service traffic is encrypted and mutually authenticated
- No application code changes required; the Envoy sidecar proxy handles crypto

**Istio PeerAuthentication Policy (strict mTLS):**

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
```

**Istio AuthorizationPolicy (Zero Trust allow-list):**

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payments-service-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: payments-service
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/order-service"
              - "cluster.local/ns/production/sa/checkout-service"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/api/v1/charge", "/api/v1/refund"]
```

This policy only allows the `order-service` and `checkout-service` service accounts to call POST on specific paths of the `payments-service`. All other sources are denied.

### 4.4 Network Access Control and DNS Filtering

**DNS filtering** is a critical ZTA network control that prevents data exfiltration, C2 communications, and access to malicious domains at the resolver level. All DNS queries must be inspected and filtered, regardless of the client network location.

**DNS Security Requirements:**
- All clients configured to use enterprise DNS resolvers (no public DNS bypass allowed)
- DNS traffic encrypted (DoH or DoT)
- Split DNS: internal names resolve internally; external queries filtered
- DNS security policies: block known malicious, newly registered, parked, phishing, C2 domains

**Cloudflare Gateway DNS Filtering Example:**
```yaml
dns_policy:
  name: "ZeroTrust-DNS-Policy"
  action: block
  traffic_categories:
    - malware
    - phishing
    - cryptomining
    - newly_registered_domains
    - command_and_control
  custom_block_domains:
    - "*.onion"
    - "*.bit"
  safe_search: enabled
  logging: all_queries
```

### 4.5 Encrypted Traffic Inspection

A common ZTA challenge: attackers use TLS encryption to hide malicious traffic from network inspection tools. **Encrypted traffic inspection (ETI)** decrypts, inspects, and re-encrypts traffic inline.

**ETI Architecture:**
```
Client -> [TLS session] -> Inspection Proxy -> [New TLS Session] -> Server
         (Proxy presents CA-signed cert)
                                    Decrypt & Inspect
                                    (DLP, malware, policy)
```

**ETI Deployment Considerations:**
- Deploy the inspection proxy CA certificate to all managed endpoints (via MDM profile)
- Exclude certificate-pinned applications (mobile banking apps, system updates) from inspection
- Exclude privacy-sensitive categories (financial, healthcare sites) per policy
- Maintain inspection at TLS 1.2 minimum; enforce TLS 1.3 where possible
- Log all inspected connections; retain for compliance

### 4.6 East-West Traffic Inspection

In a ZTA, **east-west traffic** (lateral communication between servers, services, containers within the same environment) receives the same scrutiny as north-south (user-to-resource) traffic.

**East-West Inspection Approaches:**

| Approach | Technology | Coverage |
|----------|-----------|---------|
| Service mesh | Istio/Linkerd sidecars | Container-to-container (Kubernetes) |
| Hypervisor FW | VMware NSX Distributed FW | VM-to-VM |
| Host-based FW | Illumio/Guardicore agent | Physical + VM + container |
| Internal load balancer | AWS Gateway LB + inspection VPC | Cloud workloads |

**Eliminating Flat Networks:**
```
BEFORE (Flat Network):
  All servers in 10.0.0.0/8 -> any-to-any communication
  Breach = full lateral movement to all assets

AFTER (ZT Segmented):
  10.10.1.0/24 - Web Tier    (only accepts 443 from LB)
  10.10.2.0/24 - App Tier    (only accepts specific ports from Web Tier SG)
  10.10.3.0/24 - DB Tier     (only accepts 5432/3306 from App Tier SG)
  10.10.4.0/24 - Management  (only accepts 22 from Bastion/PAM; RBAC enforced)
  All other traffic: default-deny
```

---

## 5. Application and Workload Pillar

### 5.1 Application-Layer Access Control — Identity-Aware Proxy

An **Identity-Aware Proxy (IAP)** sits in front of applications and enforces access control based on user identity and context — not network location. The application itself remains unexposed to the public internet; the proxy is the only entry point.

**IAP Traffic Flow:**
```
User -> IAP (PEP) -> [Verify: Identity + Device + Context + Policy]
                 -> [Pass] -> Backend Application (no public IP)
                 -> [Fail] -> 403 / Redirect to auth
```

**Key IAP Capabilities:**
- Validates authentication token (OIDC JWT) from IdP on every request
- Enforces device compliance by checking device certificate or MDM state
- Rewrites request headers to include verified user identity (for backend logging/audit)
- Strips all other headers that could be used to spoof identity
- Supports per-application and per-path granular policies
- Handles session management; re-challenges on inactivity or risk threshold crossing

### 5.2 Google BeyondCorp Reference Implementation

**BeyondCorp** is Google's internal Zero Trust implementation, published through a series of research papers (2014-2018). It is the most influential real-world ZTA deployment and directly inspired the modern ZTNA market.

**BeyondCorp Core Components:**

| Component | Function |
|-----------|---------|
| **Device Inventory Service** | Maintains database of all devices; tracks certificates, MDM state, OS version |
| **User/Group Database** | Directory of identities and group memberships |
| **Device Certificate Authority** | Issues certificates to enrolled devices; basis for device identity |
| **Trust Inferrer** | Evaluates device and user attributes; assigns trust tier |
| **Access Control Engine** | Policy engine evaluating identity, device, and request attributes |
| **Access Proxy (GAP)** | Global access proxy — the PEP for all Google internal applications |
| **Resource Tiers** | Applications classified by sensitivity; mapped to required trust tiers |

**BeyondCorp Trust Tiers:**

```
Tier 0: Highly sensitive (corp.google.com infra)
  Requires: Google-issued device + phishing-resistant MFA + specific network
Tier 1: Sensitive (internal tools, code repos)
  Requires: Google-issued device + MFA
Tier 2: General (most internal apps)
  Requires: Managed device + user auth
Tier 3: Low sensitivity (public-ish)
  Requires: User auth only
```

**Key BeyondCorp Lessons:**
1. Moving the access control from the VPN to the application layer took 6 years at Google
2. Device inventory accuracy is critical — stale data breaks access
3. User experience must be seamless; friction causes shadow IT
4. Start with low-sensitivity applications to build confidence before migrating critical apps

### 5.3 Cloudflare Access — cloudflared Tunnel Configuration

Cloudflare Access is a commercial IAP/ZTNA product built on Cloudflare's global edge network.

**cloudflared tunnel configuration:**

```yaml
tunnel: <TUNNEL-UUID>
credentials-file: /etc/cloudflared/<TUNNEL-UUID>.json

ingress:
  - hostname: internal-app.example.com
    service: http://localhost:8080
    originRequest:
      noTLSVerify: false
      connectTimeout: 30s

  - hostname: ssh-bastion.example.com
    service: ssh://localhost:22

  - hostname: k8s.example.com
    service: https://localhost:6443
    originRequest:
      noTLSVerify: true

  - service: http_status:404
```

**Cloudflare Access Policy (via API):**

```json
{
  "name": "Internal App Access Policy",
  "decision": "allow",
  "include": [
    { "email_domain": {"domain": "company.com"} }
  ],
  "require": [
    { "device_posture": {"integration_uid": "intune-integration-id"} },
    { "auth_method": {"auth_method": "mfa"} }
  ],
  "exclude": [
    { "email": {"email": "contractor@partner.com"} }
  ]
}
```

### 5.4 Application Inventory and Sensitivity Classification

Before applying ZTA controls, every application must be inventoried and classified by sensitivity:

| Classification | Definition | Required Controls |
|---------------|-----------|-----------------|
| **Critical** | PII, financial data, health records, IP | Phishing-resistant MFA + compliant device + JIT access + full audit logging |
| **Sensitive** | Internal tools, code repos, HR data | MFA + device compliance check + session limits |
| **Internal** | General intranet, wikis, collaboration | Standard MFA + basic auth |
| **Public** | Marketing sites, public APIs | Rate limiting + WAF + DDoS protection |

### 5.5 API Security in ZTA — mTLS + JWT + Rate Limiting

APIs are a primary attack surface in modern applications. ZTA principles applied to API security:

**JWT (JSON Web Token) Authorization:**
```json
{
  "sub": "user@company.com",
  "scope": ["read:reports", "write:data"],
  "aud": "api.company.com",
  "iss": "https://auth.company.com",
  "exp": 1714000000,
  "iat": 1713996400,
  "jti": "unique-token-id-for-replay-prevention"
}
```

**API Gateway ZTA Policy (Kong / NGINX / AWS API Gateway):**
```yaml
services:
  - name: payments-api
    url: http://payments-service:8080
    plugins:
      - name: mtls-auth
        config:
          ca_certificates: ["corp-root-ca-uuid"]
      - name: jwt
        config:
          key_claim_name: iss
          claims_to_verify: ["exp", "nbf"]
      - name: rate-limiting
        config:
          minute: 100
          hour: 5000
          policy: redis
```

### 5.6 Workload Identity — SPIFFE/SPIRE Standard

**SPIFFE (Secure Production Identity Framework for Everyone)** is a CNCF standard that defines how workloads identify themselves in dynamic, heterogeneous infrastructure.

**SPIFFE Identity Format:**
```
spiffe://<trust-domain>/<workload-identifier>
Example: spiffe://company.com/ns/production/sa/payments-service
```

**SPIRE (SPIFFE Runtime Environment)** is the reference implementation:

```yaml
server:
  bind_address: "0.0.0.0"
  bind_port: "8081"
  trust_domain: "company.com"
  data_dir: "/opt/spire/data/server"
  ca_ttl: "168h"
  default_svid_ttl: "1h"
```

**SVID (SPIFFE Verifiable Identity Document):**
- X.509-SVID: X.509 certificate with SPIFFE URI in the SAN field; used for mTLS
- JWT-SVID: JWT token with SPIFFE URI as the `sub` claim; used for HTTP bearer auth
- TTL typically 1 hour; SPIRE agent automatically rotates before expiry

### 5.7 Container and Serverless Workload Identity

**Kubernetes Service Account Tokens:**
- Bound service account tokens (projected volumes) with audience and expiry claims
- Token bound to pod lifecycle; auto-rotated by kubelet
- Used with Workload Identity Federation to authenticate to cloud IAM

**AWS ECS / Lambda IAM Roles:**
- Task IAM Role for ECS: each task gets temporary credentials from EC2 Instance Metadata
- Lambda Execution Role: IAM role assumed by the function; no long-lived credentials
- Permission boundaries restrict what roles can grant to prevent privilege escalation

**Google Cloud Workload Identity:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-service
  namespace: production
  annotations:
    iam.gke.io/gcp-service-account: payments-sa@project-id.iam.gserviceaccount.com
```

---

## 6. Data Pillar

### 6.1 Data Classification Driving Access Decisions

**Data classification** is the foundation of the data pillar — you cannot protect what you have not classified. Classification must be accurate, consistent, and actionable.

**Standard Classification Taxonomy:**

| Level | Label | Examples | Controls |
|-------|-------|---------|---------|
| 4 | **Highly Confidential** | PII, PHI, PCI data, trade secrets, M&A plans | Encrypt at rest + in transit; MFA + JIT access; DLP block all egress; full audit log |
| 3 | **Confidential** | Internal financial data, HR records, source code | Encrypt; MFA required; DLP restrict egress; audit log reads |
| 2 | **Internal** | Internal communications, policies, meeting notes | Auth required; basic DLP; log bulk downloads |
| 1 | **Public** | Press releases, marketing materials | No special controls beyond integrity protection |

**Automated Classification Signals:**
- **Content inspection:** Pattern matching for PII (SSN, credit card numbers), PHI, credentials
- **Context inspection:** File location (HR SharePoint, Finance folder), application of origin
- **User context:** Who created/last modified the file
- **ML-based classification:** Trainable classifiers (Microsoft Purview, Google Cloud DLP)

### 6.2 Data-Centric Security — Encrypt + Tag + Control

**Data-centric security** ensures that protection travels with the data regardless of where it moves.

**Three pillars of data-centric security:**

**1. Encrypt:**
- Data encrypted at rest (AES-256) and in transit (TLS 1.2+)
- Key management centralised (Azure Key Vault, AWS KMS, HashiCorp Vault)
- Customer-managed keys (CMK) for the highest sensitivity tiers
- Envelope encryption: data encrypted with a data encryption key (DEK); DEK encrypted with key encryption key (KEK) in HSM

**2. Tag:**
- Sensitivity labels applied to files, emails, and containers
- Labels are persistent metadata; survive download, email, and copy operations
- Labels visible to users (footer, watermark) and machine-readable (for DLP policy enforcement)

**3. Control:**
- Access control enforced by the label
- Information protection policies restrict: printing, forwarding, copy-paste, screenshots
- Rights Management Service (RMS/AIP) embeds policy in the document itself

**Microsoft Purview Information Protection Label Configuration:**

```json
{
  "labelName": "Highly Confidential - Finance",
  "sensitivity": 4,
  "protectionSettings": {
    "encryptContent": true,
    "allowedUsers": ["finance-team@company.com"],
    "permissions": {
      "view": true,
      "edit": false,
      "print": false,
      "forward": false,
      "copy": false
    },
    "offlineAccessDays": 3
  },
  "markings": {
    "header": "HIGHLY CONFIDENTIAL - FINANCE",
    "footer": "Company Confidential — Do Not Distribute",
    "watermark": "CONFIDENTIAL — {UserName} — {CurrentDate}"
  }
}
```

### 6.3 DLP Integration with ZTA Policy Enforcement

**Data Loss Prevention (DLP)** prevents sensitive data from leaving authorised boundaries through policy-based inspection and blocking.

**DLP Enforcement Points in ZTA:**

| Enforcement Point | What It Inspects | Actions |
|-----------------|----------------|---------|
| **Endpoint DLP** | File operations on device (copy to USB, print, upload to browser) | Block, warn, audit |
| **Email DLP** | Email body and attachments leaving corporate mail | Block, encrypt, quarantine, notify |
| **Cloud App DLP (CASB)** | Files uploaded to SaaS apps (SharePoint, Dropbox, Salesforce) | Block, quarantine, alert |
| **Network DLP** | Traffic at network egress point | Block data containing sensitive patterns |
| **IAP/Proxy DLP** | HTTP(S) requests through corporate proxy | Block upload of classified content |

**Example DLP Policy — Credit Card Number Blocking:**

```yaml
dlp_policy:
  name: "Block PCI Data Exfiltration"
  detection:
    data_types:
      - type: "CREDIT_CARD_NUMBER"
        likelihood: HIGH
        minimum_count: 1
  scope:
    - email_outbound
    - file_upload_browser
    - cloud_storage_upload
    - usb_copy
  action:
    block: true
    notify_user: true
    notify_admin: true
    quarantine: true
    audit_log: true
  exceptions:
    - users: ["pci-compliance-team@company.com"]
      require_justification: true
```

### 6.4 Information Protection Labels

**Microsoft Purview Information Protection:**
- Labels defined in Microsoft Purview compliance portal
- Published to users via label policies (assigned to user/group scope)
- Applied automatically by auto-labelling policies or manually by users
- Labels enforced in: Office apps, Teams, SharePoint, Exchange, third-party apps (via SDK)
- **Unified Labelling Platform** extends labels to non-Microsoft environments

**Google Cloud DLP:**
- Data discovery across BigQuery, Cloud Storage, Datastore
- 150+ built-in info types (PII, credentials, financial data, medical records)
- De-identification: redaction, masking, tokenisation, generalisation, date shifting
- Inspection results feed into Cloud Security Command Center for ZTA policy updates

### 6.5 Just-in-Time Data Access for Sensitive Datasets

**JIT data access** applies the same time-bounded, approval-gated model from PIM to data access:
- DBA does not have standing read access to production customer database
- When needed, DBA requests access via approval workflow (15-minute to 4-hour window)
- Access granted; all queries logged with the JIT session ID
- Access automatically revoked when the window expires
- All activity reviewed in post-access audit

**Implementation options:**
- HashiCorp Vault Dynamic Secrets (generates temporary DB credentials with TTL)
- AWS IAM Identity Center with session policies
- CyberArk Conjur / Delinea Secret Server for PAM-based JIT DB access

### 6.6 Data Activity Monitoring and DSPM

**Data Activity Monitoring (DAM)** provides real-time visibility into who is accessing what data, when, from where, and how — enabling detection of data theft, insider threats, and compliance violations.

**Key DAM Metrics to Monitor:**
- Bulk download events (user downloads >100 files in a session)
- Access outside business hours from unusual locations
- Access to data far outside the user's normal access pattern (peer group analysis)
- Privilege escalation followed by immediate data access
- Access by recently terminated users (stale access)

**Data Security Posture Management (DSPM)** provides continuous visibility into:
- **Where** sensitive data lives (discovered, not assumed)
- **Who** has access to it (effective permissions, not just policy-stated)
- **How** it is protected (encryption, labels, access controls)
- **What is the risk** (misconfigured permissions, over-privileged access, unencrypted sensitive data)

**DSPM vendors:** Cyera, Normalyze, Laminar (Rubrik), Dig Security (Palo Alto Networks), Sentra, Microsoft Purview Data Map

**DSPM capabilities:**
```
1. Data Discovery: Scan S3 buckets, Azure Blobs, GCS, databases, SaaS apps
2. Data Classification: Identify PII, PCI, PHI, IP in discovered data stores
3. Access Analysis: Map who can access data (direct + inherited permissions)
4. Risk Prioritisation: Score data stores by sensitivity x exposure x protection gap
5. Remediation Guidance: Recommended actions to reduce risk
6. Continuous Monitoring: Alert on new sensitive data stores, permission changes
```

### 6.7 Rights Management for Documents Outside Corporate Boundary

**Azure Information Protection (AIP) / Microsoft Purview RMS:**
- Encrypted document contains embedded policy (allowed users, permissions, expiry)
- When recipient opens the document, their client calls the RMS cloud service to validate access
- RMS can revoke access to already-distributed documents
- Audit log captures every open attempt

**Use Cases:**
- Share financial projections with investment bank — set expiry 30 days, no print, no copy
- Share contract with outside counsel — allow edit, no forward outside domain
- Share sensitive report with regulator — allow view only, no download to disk

---

## 7. Teleport — Open-Source ZT Infrastructure Access

### 7.1 Overview

**Teleport** (by Gravitational/Teleport Inc.) is an open-source infrastructure access platform implementing Zero Trust principles for servers, databases, Kubernetes clusters, and web applications. It replaces traditional VPN + bastion host architectures with certificate-based, identity-aware, and fully audited access.

**GitHub Repository:** https://github.com/gravitational/teleport

**Key Design Principles:**
- No long-lived credentials (no SSH keys, no static passwords, no shared service accounts)
- All sessions recorded and replayable
- Every access event is logged in a tamper-resistant audit log
- Single platform for all infrastructure access types
- Works across on-premises, cloud, and hybrid environments

### 7.2 Core Components

| Component | Role |
|-----------|------|
| **Auth Server** | Certificate Authority; issues short-lived certificates; stores audit logs; enforces RBAC |
| **Proxy Service** | Public-facing entry point (PEP); exposes Web UI and `tsh` client endpoint |
| **Node/Agent (SSH)** | Installed on SSH servers; accepts only Teleport-issued certificates |
| **App Service** | Exposes internal web applications via IAP; injects user identity headers |
| **Database Access** | Proxies database connections; issues short-lived DB certs |
| **Kubernetes Access** | Proxies kubectl traffic; enforces K8s RBAC; records exec sessions |
| **Desktop Access** | RDP proxy with session recording |
| **Machine ID** | Service-to-service identity; issues renewable bot credentials for CI/CD |

### 7.3 Certificate-Based Access — No Long-Lived Credentials

**User SSH Access Flow:**
```
1. User runs: tsh login --proxy=teleport.company.com
2. Teleport Proxy redirects to IdP (Okta/Azure AD/GitHub)
3. User authenticates with MFA to IdP
4. IdP sends SAML/OIDC assertion to Teleport Auth Server
5. Auth Server validates assertion; checks RBAC role mapping
6. Auth Server issues short-lived SSH certificate (TTL: 8-12 hours by default)
7. Certificate stored in user's ~/.tsh directory
8. User runs: tsh ssh user@server-name
9. Proxy routes connection to correct Node via reverse tunnel
10. Node validates certificate (issued by trusted Auth Server CA)
11. Session begins; recorded by Auth Server; BPF events captured
```

**Certificate vs. Long-Lived SSH Key:**

| Property | Static SSH Key | Teleport Certificate |
|----------|---------------|---------------------|
| TTL | Forever (until manually revoked) | 8-12 hours (configurable) |
| Revocation | Manual; requires updating authorized_keys everywhere | Cert TTL expiry; or CRL-based revocation |
| Auditing | SSH logs (if enabled) | Full session recording + structured audit log |
| MFA at login | No | Yes (SAML/OIDC + optional per-session MFA) |
| Scope | All servers with the key | Only servers where user RBAC role allows |

### 7.4 RBAC Policies

```yaml
kind: role
version: v5
metadata:
  name: devops-engineer
spec:
  allow:
    node_labels:
      environment: ["staging", "production"]
      team: ["devops"]
    logins: ["ec2-user", "ubuntu"]

    kubernetes_groups: ["system:masters"]
    kubernetes_labels:
      environment: ["staging"]

    db_labels:
      environment: ["staging"]
    db_names: ["*"]
    db_users: ["readonly", "app_user"]

    app_labels:
      environment: ["staging", "production"]

  deny:
    db_names: ["prod_financial_db"]
    db_users: ["admin", "root", "postgres"]

  options:
    max_session_ttl: 8h
    require_session_mfa: "hardware_key"
    enhanced_recording:
      enabled: true
      capture_command_events: true
      capture_network_events: true
    forward_agent: false
    port_forwarding: false
    disconnect_expired_cert: true
```

### 7.5 Session Recording and Audit Log

**Session Recording:**
- Every SSH session is recorded and stored in the Auth Server (or S3/GCS/Azure Blob)
- Recordings are encrypted and tamper-evident (SHA-256 checksums per chunk)
- Playable via `tsh play <session-id>` or Web UI
- Structured events within recordings: command executed, file transferred, network connection opened

**BPF-Based Enhanced Session Recording:**
- Uses Linux eBPF to capture system calls within recorded sessions
- Cannot be defeated by SSH tricks (tty detachment, background processes)
- Captures: exec events (every command + arguments), network events, file events

**Audit Log (structured JSON):**
```json
{
  "event": "session.command",
  "time": "2026-04-26T14:32:01.123Z",
  "user": "alice@company.com",
  "login": "ec2-user",
  "server_hostname": "prod-web-01.internal",
  "command": "sudo systemctl restart nginx",
  "argv": ["systemctl", "restart", "nginx"],
  "path": "/usr/bin/sudo",
  "return_code": 0,
  "pid": 1234
}
```

### 7.6 Teleport Machine ID for Service Accounts

**Machine ID** solves the service account credential problem in CI/CD and automation:

```yaml
kind: bot
version: v1
metadata:
  name: github-actions-bot
spec:
  roles: ["deploy-bot"]
  traits:
    logins: ["deploy"]
```

```yaml
output_dir: /var/lib/teleport/bot
auth_server: teleport.company.com:443
onboarding:
  join_method: github
  github:
    enterprise_slug: ""
destinations:
  - directory: /var/lib/teleport/bot
    roles: ["deploy-bot"]
    app:
      name: "internal-deploy-api"
```

### 7.7 Database Access

Teleport Database Access provides ZT-compliant access to databases:

**Supported Databases:** PostgreSQL, MySQL, MariaDB, MongoDB, Redis, CockroachDB, Cassandra, Elasticsearch, DynamoDB, Redshift, Cloud SQL, Azure SQL, RDS, Aurora

**Database Access Configuration:**

```yaml
db_service:
  enabled: true
  databases:
    - name: "prod-postgres"
      description: "Production PostgreSQL Database"
      protocol: "postgres"
      uri: "prod-postgres.cluster.local:5432"
      tls:
        mode: verify-full
      static_labels:
        environment: "production"
        team: "data-platform"
```

**User Access Flow:**
```
1. tsh db login prod-postgres --db-user=analyst --db-name=reporting
2. Teleport issues short-lived PostgreSQL client certificate (TTL: 1 hour)
3. tsh db connect prod-postgres (or psql with cert params)
4. Teleport Proxy proxies connection; validates cert; logs all queries
5. Database receives connection from trusted Teleport proxy; no direct user access
```

### 7.8 Kubernetes Access

```bash
tsh kube login production-cluster
kubectl get pods -n production   # Logged; session recorded if exec used
kubectl exec -it pod-name -- /bin/bash   # Full session recording
tsh kube ls   # List available clusters
```

```yaml
kubernetes_service:
  enabled: true
  kube_cluster_name: "production-cluster"
  kubeconfig_file: "/var/lib/teleport/kubeconfig"
```

---

## 8. HashiCorp Boundary — Open-Source ZTNA

### 8.1 Overview

**HashiCorp Boundary** is an open-source Zero Trust Network Access (ZTNA) platform that provides identity-based access to hosts and services without requiring network-level access (VPN). It integrates natively with HashiCorp Vault for dynamic credential injection.

**GitHub Repository:** https://github.com/hashicorp/boundary

**Core Concept:** Boundary abstracts infrastructure topology from users. Instead of connecting to an IP address and port, users connect to a named **target** (e.g., "Production Web Servers"). Boundary resolves the target to the correct backend and brokers the connection.

### 8.2 Architecture

**Controllers:**
- The brains of Boundary; manage identity, policy, targets, and credentials
- Expose the API and Web UI; store state in a PostgreSQL database
- Stateless; can be scaled horizontally

**Workers:**
- Data plane components that proxy actual user connections
- Deployed in the network zone where the targets live
- Connect to Controllers over HTTPS; receive session tokens
- Workers do not need inbound connectivity from the internet

**Targets:**
- Named references to specific hosts/services (SSH server, RDP host, K8s API, database)
- Associated with a host catalog (static IPs or dynamic — AWS EC2, Azure VM, Consul)
- Configured with allowed ports and protocols
- Linked to credential libraries (Vault dynamic secrets) or credential stores

### 8.3 Identity Brokering — OIDC / LDAP

**OIDC Authentication (Okta, Azure AD, Google, GitHub):**

```hcl
resource "boundary_auth_method_oidc" "okta" {
  scope_id          = boundary_scope_org.company.id
  name              = "Okta OIDC"
  issuer            = "https://company.okta.com"
  client_id         = var.okta_client_id
  client_secret     = var.okta_client_secret
  signing_algorithms = ["RS256"]
  api_url_prefix    = "https://boundary.company.com"
  is_primary_for_scope = true
  claims_scopes = ["openid", "email", "profile", "groups"]
}

resource "boundary_managed_group_oidc" "devops_team" {
  auth_method_id = boundary_auth_method_oidc.okta.id
  name           = "DevOps Team"
  filter         = ""devops" in "/token/groups""
}
```

**LDAP Authentication:**

```hcl
resource "boundary_auth_method_ldap" "corp_ldap" {
  scope_id    = boundary_scope_org.company.id
  name        = "Corporate Active Directory"
  urls        = ["ldaps://dc01.company.com:636", "ldaps://dc02.company.com:636"]
  user_dn     = "OU=Users,DC=company,DC=com"
  user_attr   = "sAMAccountName"
  group_dn    = "OU=Groups,DC=company,DC=com"
  bind_dn     = "CN=boundary-svc,OU=ServiceAccounts,DC=company,DC=com"
  bind_password = var.ldap_bind_password
}
```

### 8.4 Dynamic Credentials via Vault Integration

**Vault + Boundary Credential Injection:**

```hcl
resource "boundary_credential_library_vault_ssh_certificate" "ssh_cert" {
  name                = "SSH Certificate Issuer"
  credential_store_id = boundary_credential_store_vault.main.id
  path                = "ssh/sign/devops-role"
  username            = "ec2-user"
  key_type            = "ecdsa"
  key_bits            = 521
  ttl                 = "3600"
}

resource "boundary_credential_library_vault" "db_creds" {
  name                = "Postgres Dynamic Credentials"
  credential_store_id = boundary_credential_store_vault.main.id
  path                = "database/creds/readonly-role"
  http_method         = "GET"
  credential_type     = "username_password"
}
```

**How credential injection works:**
1. User requests a session to the "Production Database" target
2. Boundary checks RBAC: is this user allowed to connect to this target?
3. Boundary calls Vault to generate dynamic credentials (unique username + 1-hour password)
4. Boundary injects credentials into the session (user never sees them)
5. User's psql client connects through Boundary proxy, automatically authenticated
6. Session ends; Vault revokes the dynamic credentials

### 8.5 Targets Configuration

```hcl
resource "boundary_target" "prod_web_servers" {
  type                     = "ssh"
  name                     = "Production Web Servers"
  description              = "Access to production nginx servers"
  scope_id                 = boundary_scope_project.production.id
  session_connection_limit = 3
  session_max_seconds      = 3600
  default_port             = 22

  host_source_ids = [
    boundary_host_set_static.web_servers.id
  ]

  injected_application_credential_source_ids = [
    boundary_credential_library_vault_ssh_certificate.ssh_cert.id
  ]

  enable_session_recording = true
  storage_bucket_id        = boundary_storage_bucket.session_recordings.id
}

resource "boundary_target" "windows_servers" {
  type                     = "tcp"
  name                     = "Windows Administration Servers"
  scope_id                 = boundary_scope_project.production.id
  default_port             = 3389
  session_max_seconds      = 7200

  host_source_ids = [
    boundary_host_set_static.windows_hosts.id
  ]

  brokered_credential_source_ids = [
    boundary_credential_store_static.windows_admin_creds.id
  ]
}
```

### 8.6 Boundary RBAC

```hcl
resource "boundary_role" "devops_production_access" {
  name        = "DevOps Production Access"
  scope_id    = boundary_scope_project.production.id

  principal_ids = [
    boundary_managed_group_oidc.devops_team.id
  ]

  grant_strings = [
    "id=*;type=target;actions=list,read,authorize-session",
    "id=*;type=session;actions=list,read,cancel:self",
    "id=*;type=host;actions=list,read",
    "id=*;type=credential-library;actions=list,read"
  ]
}
```

### 8.7 HCP Boundary vs. Self-Managed

| Aspect | Self-Managed Boundary | HCP Boundary |
|--------|----------------------|----------------------------------------|
| Controller management | You manage Postgres + controllers | HashiCorp manages hosted controllers |
| Cost | OSS (free) + infrastructure cost | Per user/month subscription |
| Updates | Manual | Managed by HashiCorp |
| Scale | You manage scaling | Auto-scaled |
| Compliance | You control data residency | HashiCorp SOC 2 Type II |
| Best for | Large enterprises; strict data residency | Mid-market; fast time to value |

### 8.8 Terraform Provider for Boundary

Boundary has a full Terraform provider (`hashicorp/boundary`) enabling infrastructure-as-code management:

```hcl
terraform {
  required_providers {
    boundary = {
      source  = "hashicorp/boundary"
      version = "~> 1.1"
    }
  }
}

provider "boundary" {
  addr             = "https://boundary.company.com"
  auth_method_id   = "ampw_1234567890"
  password_auth_method_login_name = var.boundary_admin_user
  password_auth_method_password   = var.boundary_admin_password
}
```

---

## 9. Cloudflare Zero Trust

### 9.1 Cloudflare Zero Trust Platform Overview

Cloudflare Zero Trust (formerly Cloudflare for Teams) is a cloud-native **SASE (Secure Access Service Edge)** platform built on Cloudflare's global anycast network (300+ PoPs worldwide).

**Platform Components:**

| Component | Function |
|-----------|---------|
| **Cloudflare Access** | Identity-aware proxy (IAP); replaces VPN for application access |
| **Cloudflare Tunnel (cloudflared)** | Outbound-only connector; exposes internal services without opening firewall ports |
| **WARP Client** | Device agent; tunnels all device traffic through Cloudflare network |
| **Gateway** | DNS, HTTP, and network filtering; threat intelligence; DLP |
| **Browser Isolation** | Remote browser for untrusted content; pixel-pushed rendering |
| **CASB** | SaaS security posture management; discovers and secures SaaS apps |
| **DLP** | Data patterns; prevent sensitive data exfiltration through Gateway |
| **Magic WAN** | IPsec/GRE connectivity for branch offices and data centres |
| **Magic Firewall** | Cloud-delivered network firewall for all Magic WAN-connected traffic |

### 9.2 Cloudflare Access — Identity-Aware Proxy

**How Cloudflare Access Works:**
```
1. User navigates to internal-app.company.com
2. Request hits Cloudflare edge (anycast routing; nearest PoP)
3. Cloudflare checks: does this request have a valid Access JWT?
4. No: redirect user to configured IdP login page
5. User authenticates; IdP returns OIDC token to Cloudflare
6. Cloudflare validates token; checks Access Policy (identity + device + location)
7. If allowed: issues Cloudflare Access JWT; forwards request to origin via cloudflared tunnel
8. Origin receives request with CF-Access-Authenticated-User-Email header
9. If denied: 403 response
```

**Cloudflare Access Policy:**

```json
{
  "name": "Engineering Internal Tools",
  "decision": "allow",
  "include": [
    { "group": {"id": "engineering-group-id"} }
  ],
  "require": [
    { "device_posture": {"integration_uid": "warp-client-integration-id"} },
    { "auth_method": {"auth_method": "mfa"} }
  ],
  "exclude": [
    { "service_token": {"token_id": "monitoring-bot-token-id"} }
  ],
  "session_duration": "8h"
}
```

### 9.3 Cloudflare Tunnel — cloudflared

Cloudflare Tunnel creates outbound-only encrypted tunnels from the origin server to Cloudflare's edge. No inbound firewall ports need to be opened.

**Setup Process:**

```bash
# Install cloudflared
curl -L --output cloudflared.deb   https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
dpkg -i cloudflared.deb

# Authenticate to Cloudflare
cloudflared tunnel login

# Create a named tunnel
cloudflared tunnel create my-internal-app-tunnel

# Route DNS through tunnel
cloudflared tunnel route dns my-internal-app-tunnel internal-app.company.com

# Run as systemd service
cloudflared service install
systemctl start cloudflared && systemctl enable cloudflared
```

**Tunnel Redundancy:** Run multiple `cloudflared` instances (on different hosts) for the same tunnel UUID — Cloudflare automatically load-balances and provides failover.

### 9.4 WARP Client — Device Agent

The **WARP client** is a device agent that tunnels all device traffic through Cloudflare's network, applying Gateway policies to all traffic.

**WARP Modes:**

| Mode | What it does |
|------|-------------|
| **WARP** | Encrypts all device traffic; routes through Cloudflare for performance |
| **Gateway with WARP** | Encrypts all traffic + applies Gateway filtering (DNS + HTTP policies) |
| **Proxy** | HTTP proxy mode; applies filtering without tunnelling all traffic |

**WARP Client Device Posture Checks:**

```json
{
  "device_posture_checks": [
    {"type": "warp", "enabled": true},
    {
      "type": "os_version",
      "input": {"version": "11.0", "operator": ">="}
    },
    {
      "type": "disk_encryption",
      "input": {"requireAll": true}
    }
  ]
}
```

### 9.5 Cloudflare Gateway — DNS / HTTP / Network Filtering

**DNS Filtering:**

```yaml
dns_policy:
  name: "Block Malicious + High-Risk Categories"
  action: block
  security_categories:
    - malware
    - phishing
    - cryptomining
    - command_and_control
    - newly_registered_domains
  override_host: "blocked.company.com"
```

**HTTP Filtering:**

```yaml
http_policy:
  name: "Block Unsanctioned File Sharing"
  action: block
  conditions:
    application:
      in_list: ["Dropbox", "WeTransfer", "Google Drive Personal"]
  exclude:
    email:
      domain: "company.com"
```

**DLP via Gateway:**

```json
{
  "name": "Block Credit Card Uploads",
  "action": "block",
  "traffic": {
    "http": {
      "request_direction": "egress"
    }
  },
  "dlp_profiles": ["credit-card-numbers-profile-id"]
}
```

### 9.6 Browser Isolation

Cloudflare's **Remote Browser Isolation (RBI)** renders web pages in a cloud-hosted browser; only a pixel-pushed display is sent to the user's device.

**Use Cases:**
- Employees accessing untrusted external sites (reduce endpoint compromise risk)
- Third-party contractors accessing internal apps from unmanaged devices (BYOD isolation)
- Prevent malware downloads; prevent clipboard exfiltration from isolated tabs

**Isolation Policy:**
```yaml
isolation_policy:
  name: "Isolate External Sites for Contractors"
  conditions:
    group: ["contractors-group-id"]
    url_category:
      not_in: ["corporate-approved-list"]
  action: isolate
  isolation_settings:
    disable_copy_paste: true
    disable_printing: true
    disable_download: true
    disable_keyboard: false
```

### 9.7 Free Tier vs. Enterprise Capabilities

| Feature | Free Tier | Enterprise |
|---------|----------|-----------|
| Access — max users | 50 | Unlimited |
| Gateway DNS filtering | Yes | Yes |
| Gateway HTTP filtering | No | Yes |
| Browser Isolation | No | Yes (add-on) |
| DLP | No | Yes |
| CASB | No | Yes |
| Magic WAN | No | Yes |
| WARP client — device posture | Limited | Full |
| Session recording | No | Yes |
| Log retention | 24 hours | Configurable (up to 1 year) |
| Log integration (SIEM) | No | Yes (Logpush to Splunk/Datadog/S3) |

**Free tier is ideal for:** Small teams (<50 users) that want Cloudflare Access for a few internal apps and basic Gateway DNS filtering.

### 9.8 Cloudflare One — SASE Platform

**Cloudflare One** is the umbrella brand for Cloudflare's SASE offering, converging:
- **SSE (Security Service Edge):** Access + Gateway + RBI + DLP + CASB
- **SD-WAN (via Magic WAN):** Branch connectivity to Cloudflare backbone
- **Network Services:** Magic Firewall, Magic Transit (DDoS protection + transit)

**Cloudflare One Architecture:**
```
CLOUDFLARE GLOBAL NETWORK (300+ PoPs worldwide)

  [Access (IAP/ZTNA)] [Gateway (SWG/FW/DLP)] [Browser Isolation (RBI)]
  [Magic WAN (SD-WAN)] [Magic Firewall (NGFW)] [CASB/DLP (SaaS Security)]

Connectivity methods:
  - WARP Client (Users/Devices)
  - cloudflared Tunnel (Origins)
  - Magic WAN Connector (Branches)
```

---

## 10. ZTA Implementation Roadmap

### 10.1 Phased Migration Strategy

Implementing Zero Trust is a multi-year journey. A phased approach reduces risk, allows course-correction, and demonstrates value early.

#### Phase 1 — Foundation: Inventory + Identity + MFA (Months 1-6)

**Objectives:** Know what you have; enforce MFA everywhere; centralise identity

**Key Activities:**
| Activity | Tool/Standard |
|---------|-------------|
| Complete device inventory | CMDB + MDM discovery + network scanning |
| Complete application inventory | CASB shadow IT discovery + AD app registrations |
| Deploy enterprise SSO | Okta / Azure AD / Ping Identity |
| Enforce MFA for all users | Entra CA / Okta Adaptive MFA |
| Implement phishing-resistant MFA for admins | FIDO2 hardware keys (YubiKey) |
| Enable SIEM + basic alerting | Microsoft Sentinel / Splunk / Elastic |
| Deploy EDR on all endpoints | Defender for Endpoint / CrowdStrike |
| Document current network topology | Identify flat network zones |

**Success Criteria:** 100% MFA adoption; complete device and app inventory; SSO for all critical apps

#### Phase 2 — Device Trust + Conditional Access (Months 4-12)

**Objectives:** Establish device trust; connect device compliance to access decisions; begin ZTNA pilot

**Key Activities:**
| Activity | Tool/Standard |
|---------|-------------|
| Deploy MDM and enroll all devices | Microsoft Intune / Jamf Pro / VMware Workspace ONE |
| Define and deploy compliance policies | Intune Compliance + Defender for Endpoint risk integration |
| Deploy Conditional Access policies (report-only first) | Entra Conditional Access |
| Enforce device compliance as access condition | CA policy: require compliant device for sensitive apps |
| Pilot ZTNA for remote access | Cloudflare Access / Zscaler Private Access / Teleport |
| Enable Certificate-Based Authentication for devices | ADCS + NDES + Intune SCEP profile |
| Implement PIM for privileged accounts | Entra PIM / CyberArk |

**Success Criteria:** 90%+ device MDM enrollment; CA policies in enforcement mode; VPN eliminated for pilot group

#### Phase 3 — Micro-Segmentation + Network ZT (Months 10-24)

**Objectives:** Eliminate flat network zones; enforce micro-segmentation; deploy service mesh

**Key Activities:**
| Activity | Tool/Standard |
|---------|-------------|
| Map all network flows (passive observation) | Network flow tools: Illumio, Guardicore, AWS VPC Flow Logs |
| Define segmentation zones and policies | Firewall segmentation design |
| Deploy host-based micro-segmentation (pilot) | Illumio Core / Akamai Guardicore |
| Enforce segmentation for Crown Jewel applications | Network ACLs + host FW + NSX |
| Deploy Istio service mesh in Kubernetes clusters | Istio with strict mTLS mode |
| Implement DNS filtering for all traffic | Cloudflare Gateway / Cisco Umbrella |
| Enable encrypted traffic inspection | Proxy with TLS inspection |
| Eliminate all hub-and-spoke VPN tunnels | Migrate to ZTNA / SD-WAN |

**Success Criteria:** No flat /8 or /16 segments for critical apps; east-west traffic inspected; DNS filtering active

#### Phase 4 — Continuous Monitoring + Automation (Months 18-36)

**Objectives:** Implement continuous posture monitoring; automate policy enforcement

**Key Activities:**
| Activity | Tool/Standard |
|---------|-------------|
| Deploy UEBA for insider threat detection | Microsoft Sentinel UEBA / Securonix / Exabeam |
| Implement SOAR for automated response | Sentinel Playbooks / Splunk SOAR / Palo Alto XSOAR |
| Enable Continuous Access Evaluation (CAE) | Microsoft Entra CAE + CAEP for third-party apps |
| Deploy DSPM for data discovery | Cyera / Normalyze / Microsoft Purview Data Map |
| Implement access reviews and entitlement management | Entra Identity Governance / SailPoint |
| Automate device remediation | Intune compliance actions + CA |
| Integrate threat intelligence into policy engine | MISP + STIX/TAXII feeds into SIEM + FW policy |
| Deploy Boundary / Teleport for infrastructure access | Replace all bastion hosts / jump servers |

**Success Criteria:** MTTD < 1 hour; automated playbooks handling 50%+ of alerts; access reviews completed quarterly

#### Phase 5 — Mature ZTA with ML-Driven Policy (Months 30-60)

**Objectives:** Achieve CISA ZTMM Optimal rating; implement ML-driven risk scoring

**Key Activities:**
| Activity | Tool/Standard |
|---------|-------------|
| Deploy ML-based risk scoring | Azure AD Identity Protection / Okta ThreatInsight |
| Implement adaptive authentication | Risk-based CA policies |
| Automate policy lifecycle | IGA platform + SOAR |
| Achieve CISA ZTMM Optimal rating | CISA assessment worksheet |
| Deploy quantum-safe cryptography roadmap | NIST PQC standards (ML-KEM, ML-DSA) |
| Publish internal ZT metrics dashboard | PowerBI / Grafana — ZT scorecard |

### 10.2 CISA ZTA Pillars Assessment Worksheet

```
PILLAR: IDENTITY
Current State: [Traditional / Initial / Advanced / Optimal]
  MFA Coverage: ___% of users enrolled; ___% using phishing-resistant MFA
  SSO Coverage: ___% of apps integrated with enterprise IdP
  PIM Deployed: [Yes / No / Partial]
  Access Reviews: [Not running / Annual / Semi-annual / Quarterly / Continuous]
  CAE Enabled: [Yes / No]
  Workload Identity: [None / Partial / Full SPIFFE/WIF deployment]

PILLAR: DEVICE
Current State: [Traditional / Initial / Advanced / Optimal]
  MDM Enrollment: ___% of corporate devices enrolled
  Compliance Policy: [None / Basic / Comprehensive with EDR signal]
  Device Attestation: [None / Software / TPM-based hardware]
  CBA Deployed: [Yes / No]
  BYOD Policy: [None / MAM / Full MDM required]
  Hardware Requirements Enforced: [TPM 2.0 / Secure Boot / HVCI]

PILLAR: NETWORK
Current State: [Traditional / Initial / Advanced / Optimal]
  Flat Network Zones Remaining: ___ (target: 0)
  Micro-Segmentation: [None / VLANs / Host-based / Full SDN/NSX]
  VPN Replacement: [None / Piloted / 50%+ / 100% ZTNA]
  DNS Filtering: [None / Basic / Full coverage with TI feeds]
  East-West Inspection: [None / Partial / Full]
  Service Mesh: [None / Deployed in dev / Production enforced mTLS]

PILLAR: APPLICATION
Current State: [Traditional / Initial / Advanced / Optimal]
  App Inventory: [None / Partial / Complete with classification]
  IAP Coverage: ___% of internal apps behind IAP
  API Security: [None / WAF only / mTLS + JWT + rate limiting]
  Workload Identity: [None / Partial / SPIFFE/SPIRE deployed]
  Container Security: [None / Basic / Policy-enforced; image signing]

PILLAR: DATA
Current State: [Traditional / Initial / Advanced / Optimal]
  Data Classification: [None / Manual / Auto-classification deployed]
  DLP Coverage: [None / Email only / Endpoint + Cloud + Network]
  Sensitivity Labels: [None / Manual / Auto-labelling policies]
  DSPM: [None / Deployed / Active with risk scoring]
  JIT Data Access: [None / For DBAs only / Broad deployment]
  Rights Management: [None / Pilot / All Confidential+ docs]
```

### 10.3 ZTA Maturity Metrics

| Metric | Target | Measurement Source |
|--------|--------|-------------------|
| MFA adoption rate | 100% | IdP sign-in reports |
| Phishing-resistant MFA coverage | 100% admin / 50%+ all users | Entra MFA methods report |
| Device MDM enrollment | 95%+ | Intune device compliance report |
| Device compliance rate | 90%+ | Intune compliance dashboard |
| % apps behind IAP/ZTNA | 80%+ critical apps | Application inventory |
| VPN sessions (decreasing to 0) | 0 | VPN gateway logs |
| Time to revoke compromised account | < 5 minutes | IR runbook; drill results |
| Lateral movement detection time | < 1 hour | SIEM/XDR detection rules |
| Privileged access without JIT | 0% | PIM assignment reports |
| Data classification coverage | 90%+ sensitive data stores | DSPM report |
| Access review completion rate | 95%+ | IGA platform report |
| Stale access (orphaned accounts) | < 1% | IGA identity lifecycle |

### 10.4 Common ZTA Pitfalls and How to Avoid Them

**Pitfall 1: Token Theft Still Works**

Stealing a valid OAuth access token bypasses identity and device verification. Attackers use Adversary-in-the-Middle (AiTM) phishing (e.g., Evilginx) to harvest tokens.

*Mitigations:*
- Enable Continuous Access Evaluation (real-time token revocation)
- Enforce token binding (PoP — Proof of Possession tokens)
- Use phishing-resistant MFA (FIDO2) to prevent the initial credential theft
- Monitor for impossible travel and sign-in anomalies

**Pitfall 2: Over-Relying on Identity Alone**

Identity verification without device trust and network segmentation leaves organisations vulnerable to attacks from infected devices that have valid credentials.

*Mitigations:*
- Always combine identity + device compliance in Conditional Access policies
- Require device health attestation (TPM-based) for high-sensitivity access
- Monitor device risk signals (EDR) as a real-time compliance input

**Pitfall 3: Service Account Blind Spots**

Service accounts often have excessive, permanent privileges and are excluded from MFA policies.

*Mitigations:*
- Inventory all service accounts; apply least privilege
- Migrate to Workload Identity Federation or managed identities (no long-lived secrets)
- Apply Conditional Access to service accounts (restrict to named locations/IPs)
- Monitor service account activity with UEBA

**Pitfall 4: ZTA Without Visibility**

Implementing ZT controls without comprehensive logging means you cannot detect policy violations or measure effectiveness.

*Mitigations:*
- Centralise all ZT control plane logs in a SIEM (every PE/PA decision should be logged)
- Enable detailed audit logging for all identity, device, network, app, and data events
- Build a ZT metrics dashboard reviewed weekly

**Pitfall 5: Legacy Applications That Cannot Participate**

Many legacy apps cannot support SAML/OIDC, certificates, or modern auth protocols.

*Mitigations:*
- Use an application proxy/IAP to add authentication in front of legacy apps
- Isolate legacy apps in dedicated network segments with tight access controls
- Plan migration or sunset of legacy apps as part of the ZT roadmap

### 10.5 Executive Order 14028 — ZTA Requirements for Federal Agencies

**Executive Order 14028** ("Improving the Nation's Cybersecurity"), signed May 12, 2021, mandated Zero Trust Architecture for all U.S. federal civilian executive branch (FCEB) agencies.

**Key Timelines and Requirements:**

| Requirement | Deadline (from EO) | Status (as of 2026) |
|------------|-------------------|---------------------|
| Develop ZTA plan | 60 days | Completed |
| Deploy phishing-resistant MFA | 180 days | Substantially complete across FCEB |
| Encryption in transit for all federal systems | 180 days | In progress |
| EDR on all federal endpoints | 180 days | Completed |
| Log retention: 12-30 months | 12 months | Required |
| Adopt SBOM for all software | 1 year | In progress |
| Cloud migration with ZTA enforcement | 2 years | In progress |

**OMB Memorandum M-22-09** ("Moving the U.S. Government Toward Zero Trust Cybersecurity Principles") set specific ZTA targets:
- By end of FY2024: 100% of users using phishing-resistant MFA
- By end of FY2024: All FCEB networks encrypted in transit
- By end of FY2024: Agencies participating in CISA CDM programme

**NIST Cybersecurity Framework (CSF) 2.0 alignment with ZTA:**
- **Govern:** ZT policy management, risk strategy, compliance
- **Identify:** Asset inventory, data classification, risk assessment
- **Protect:** MFA, device compliance, micro-segmentation, data protection
- **Detect:** Continuous monitoring, EDR, UEBA, SIEM
- **Respond:** SOAR playbooks, incident response plans
- **Recover:** Backup, DR, ZT enforcement during recovery

### 10.6 ZTA Vendor Landscape

| Vendor | Product | ZT Pillar Focus | Key Differentiator |
|--------|---------|----------------|-------------------|
| **Zscaler** | ZPA + ZIA | Network + App | Largest security cloud; proxy-based inline inspection |
| **Palo Alto Networks** | Prisma Access + Prisma Cloud | Network + App + Cloud | NGFW heritage; AI-powered threat prevention |
| **Cloudflare** | Cloudflare One | Network + App | Fastest global anycast network; competitive free tier |
| **Microsoft** | Entra ID + Defender + Intune + Sentinel | Identity + Device + Data | Deepest Office 365 integration; E5 bundle economics |
| **Cisco** | Duo (MFA) + Umbrella (DNS) + SSE | Identity + Network | Largest enterprise footprint |
| **Okta** | Identity Cloud + Workforce Identity | Identity | IdP market leader; best SSO/MFA ecosystem |
| **CrowdStrike** | Falcon Identity + Zero Trust Assessment | Identity + Device | XDR + identity combined; best EDR; behavioral AI |
| **Illumio** | Illumio Core | Network (micro-seg) | Best-in-class micro-segmentation |
| **Teleport** | Teleport Community/Enterprise | Infrastructure access | Open-source; certificate-based; best for DevOps/SRE |
| **HashiCorp (IBM)** | Vault + Boundary | Data + Infrastructure | Secrets management + ZTNA; Terraform integration |
| **Google** | BeyondCorp Enterprise + Chronicle | Identity + App + SIEM | Native ZTA for GCP |
| **SentinelOne** | Singularity Platform | Device | AI-based EDR/XDR; autonomous response |

---

## Quick Reference: ZTA Decision Matrix

```
ACCESS DECISION LOGIC:

IF  user.identity.verified == TRUE
AND user.mfa.method == "phishing_resistant"
AND device.compliance.state == "compliant"
AND device.health_attestation == "pass"
AND device.edr_risk_level IN ["clean", "low"]
AND request.location IN user.allowed_locations
AND resource.sensitivity <= user.clearance_level
AND time.current IN session.valid_window
THEN: GRANT ACCESS (log all parameters)

ELSE IF user.risk_score > threshold_high:
  BLOCK + ALERT SOC + REQUIRE RE-AUTH WITH STEP-UP MFA

ELSE IF device.compliance.state == "non_compliant":
  REDIRECT TO REMEDIATION PORTAL + RESTRICT TO READ-ONLY

ELSE IF location NOT IN allowed_locations:
  REQUIRE ADDITIONAL MFA + LOG ANOMALY

ELSE:
  DENY + LOG REASON
```

---

## References and Further Reading

| Resource | Location |
|----------|---------|
| NIST SP 800-207 Zero Trust Architecture | https://doi.org/10.6028/NIST.SP.800-207 |
| CISA Zero Trust Maturity Model v2 | https://www.cisa.gov/zero-trust-maturity-model |
| Google BeyondCorp Papers | https://research.google/pubs/?area=security-privacy-and-abuse-prevention |
| SPIFFE/SPIRE Documentation | https://spiffe.io/docs/ |
| Teleport Documentation | https://goteleport.com/docs/ |
| HashiCorp Boundary Documentation | https://developer.hashicorp.com/boundary/docs |
| Cloudflare Zero Trust Documentation | https://developers.cloudflare.com/cloudflare-one/ |
| OMB M-22-09 Federal ZTA Strategy | https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf |
| Executive Order 14028 | https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity |
| Istio Security Documentation | https://istio.io/latest/docs/concepts/security/ |
| FIDO2 / WebAuthn Specification | https://www.w3.org/TR/webauthn-3/ |
| OpenID CAEP Specification | https://openid.net/wg/sharedsignals/ |
| NIST CSF 2.0 | https://www.nist.gov/cyberframework |
| SLSA Supply Chain Security Framework | https://slsa.dev/ |

---

*This reference is maintained as part of the TeamStarWolf cybersecurity library. For contributions or corrections, open a pull request.*
