# Zero Trust Architecture Reference

> **Scope**: Comprehensive reference covering NIST SP 800-207, CISA ZTMM v2.0, all five ZT pillars, implementation roadmap, vendor landscape, and metrics. Mapped to NIST 800-53 AC/IA/SC families, EO 14028, and CISA Zero Trust guidance.

---

## Table of Contents

1. [Zero Trust Fundamentals](#zero-trust-fundamentals)
2. [NIST SP 800-207 — Zero Trust Architecture](#nist-sp-800-207--zero-trust-architecture)
3. [CISA Zero Trust Maturity Model (ZTMM v2.0)](#cisa-zero-trust-maturity-model-ztmm-v20)
4. [Identity Pillar](#identity-pillar)
5. [Devices Pillar](#devices-pillar)
6. [Networks Pillar](#networks-pillar)
7. [Applications & Workloads Pillar](#applications--workloads-pillar)
8. [Data Pillar](#data-pillar)
9. [ZT Implementation Roadmap](#zt-implementation-roadmap)
10. [ZT Vendors & Tools](#zt-vendors--tools)
11. [ZT Metrics & KPIs](#zt-metrics--kpis)
12. [Regulatory & Framework Mapping](#regulatory--framework-mapping)

---

## Zero Trust Fundamentals

### Core Tenets

| Tenet | Description |
|-------|-------------|
| **Never trust, always verify** | No implicit trust is granted to any asset or user based solely on physical or network location |
| **Assume breach** | Minimize blast radius; segment access; verify end-to-end encryption; use analytics to gain visibility |
| **Least-privilege access** | Limit user access with just-in-time (JIT) and just-enough-access (JEA), risk-based adaptive policies, and data protection |
| **Explicit verification** | Always authenticate and authorize based on all available data points: identity, location, device health, service/workload, data classification, anomalies |

### Why Perimeter Security Fails

Traditional "castle-and-moat" security assumed that everything inside the network perimeter was trustworthy. Several trends invalidated this model:

- **Remote work & cloud adoption**: Employees, contractors, and workloads now operate entirely outside the traditional perimeter.
- **BYOD & unmanaged devices**: Personal and partner devices connect to corporate resources without management controls.
- **Lateral movement**: Once attackers breach the perimeter, flat networks allow unrestricted east-west movement to reach crown-jewel assets.
- **Supply chain compromise**: Trusted vendors and update mechanisms become attack vectors.

**Case Studies:**

| Incident | Perimeter Failure | ZT Mitigation |
|----------|-------------------|---------------|
| **SolarWinds (2020)** | Trusted software update mechanism delivered malware; flat network enabled lateral movement to email, source code, and US government systems | Code signing verification, micro-segmentation, anomalous authentication detection, privileged access workstations |
| **Colonial Pipeline (2021)** | VPN credential compromise (no MFA) provided network-level access to OT environment | Phishing-resistant MFA (FIDO2), network segmentation between IT and OT, conditional access requiring device compliance |
| **Uber (2022)** | MFA fatigue attack bypassed push-based MFA; social engineering provided admin credentials | FIDO2/WebAuthn (non-fatigueable), number matching MFA, privileged access management with JIT elevation |

### ZT vs Traditional Network Security

| Dimension | Traditional Perimeter | Zero Trust |
|-----------|----------------------|------------|
| **Trust model** | Implicit trust inside perimeter | Explicit verification for every request |
| **Network access** | VPN = full network access | Least-privilege per-application access |
| **Authentication** | Single sign-on at perimeter | Continuous, risk-based re-authentication |
| **Device posture** | Assumed compliant if on-network | Real-time device health attestation |
| **Lateral movement** | Unrestricted east-west | Micro-segmentation blocks lateral movement |
| **Encryption** | Perimeter decrypt/inspect | End-to-end mTLS; inspect at workload level |
| **Visibility** | Network perimeter logs | Full packet/session telemetry across all pillars |
| **Breach response** | Alert when perimeter breached | Assume breach; detect, contain, respond |

---

## NIST SP 800-207 — Zero Trust Architecture

### Seven Tenets of ZTA (NIST 800-207 §2.1)

1. All data sources and computing services are considered **resources**.
2. All communication is secured **regardless of network location** — network location alone does not grant implicit trust.
3. Access to individual enterprise resources is granted **on a per-session basis**.
4. Access to resources is determined by **dynamic policy** including observable state of client identity, application, and requesting asset — and may include behavioral and environmental attributes.
5. The enterprise monitors and measures the **integrity and security posture of all owned and associated assets**.
6. All resource authentication and authorization are **dynamic and strictly enforced** before access is allowed.
7. The enterprise collects as much information as possible about the **current state of assets, network infrastructure, and communications** and uses it to improve security posture.

### Three ZTA Approaches

| Approach | Description | Best For |
|----------|-------------|----------|
| **Enhanced Identity Governance** | Identity becomes the primary perimeter; strong IdP with risk-based access decisions | Cloud-first, SaaS-heavy organizations |
| **Micro-Segmentation** | Divide network into small segments; apply per-workload policy at software or network layer | Data-center-heavy, legacy application environments |
| **Network Infrastructure / SDP** | Software-Defined Perimeter creates encrypted overlay; resources invisible until authenticated | Remote workforce, multi-cloud, contractor access |

### ZTA Logical Components

```
                        ┌────────────────────────────────────┐
                        │         Control Plane              │
  [CDM System]          │  ┌──────────────┐                  │
  [Threat Intel]   ───► │  │ Policy Engine│◄─── [IDAP/LDAP]  │
  [Activity Logs]  ───► │  │    (PE)      │◄─── [PKI]        │
  [ABAC Policy DB] ───► │  └──────┬───────┘◄─── [SIEM]      │
                        │         │                          │
                        │  ┌──────▼───────┐                  │
                        │  │   Policy     │                  │
                        │  │Administrator │                  │
                        │  │    (PA)      │                  │
                        │  └──────┬───────┘                  │
                        └─────────┼──────────────────────────┘
                                  │ (command channel)
                        ┌─────────▼──────────────────────────┐
                        │         Data Plane                 │
  Subject ─────────────►│  Policy Enforcement Point (PEP)   │──► Enterprise Resource
  (with device)         │                                    │
                        └────────────────────────────────────┘
```

**Policy Engine (PE)**: Grants, denies, or revokes access to resources. The brain of ZTA — evaluates trust algorithm using all available inputs.

**Policy Administrator (PA)**: Communicates with PEP to establish or terminate communication paths. Executes PE decisions.

**Policy Enforcement Point (PEP)**: Enables, monitors, and terminates connections between subject and resource. Can be split (client-side agent + resource-side gateway).

### Trust Algorithm Inputs

| Input Source | Data Provided | NIST 800-53 Control |
|-------------|---------------|---------------------|
| **CDM System** | Device health, patch status, MDM enrollment, EDR status | CM-6, CM-7, SI-2 |
| **Industry Threat Intelligence** | Known bad IPs/domains, IOCs, TTP signatures | RA-3, SI-5 |
| **Activity Logs / SIEM** | Historical access patterns, anomaly baseline | AU-2, AU-12, SI-4 |
| **Database of Access Policies** | ABAC/RBAC policy definitions, resource sensitivity | AC-2, AC-3, AC-6 |
| **PKI** | Certificate validity, revocation status (OCSP/CRL) | IA-5, SC-17 |
| **ID Management System** | Identity attributes, group membership, risk score | IA-2, IA-8, AC-2 |

### Deployment Scenarios

| Scenario | Description |
|----------|-------------|
| ZTA using Enhanced Identity Governance | IdP is source of truth; device compliance fed back to IdP; Conditional Access enforces per-request |
| ZTA using Micro-Segmentation | Host-based or network-based micro-segments; PEP at workload boundary |
| ZTA using Network Infrastructure and SDP | SDP controller = PA; IH = client-side PEP; AH = resource-side PEP |
| ZTA for Workforce | Focus on remote employee/contractor access replacing VPN |
| ZTA for Devices | IoT, OT, unmanaged device access through device proxy/gateway |

### Threats to ZTA

| Threat | Description | Mitigations |
|--------|-------------|-------------|
| **Subversion of ZTA decision process** | Insider threat or APT manipulates PE/PA to grant unauthorized access | Integrity monitoring, multi-party PE decisions, audit of policy changes |
| **DoS on PE/PA** | Flooding control plane renders ZTA unavailable | Redundant PE/PA, rate limiting, HA deployment |
| **Stolen credentials** | Valid credentials bypass trust algorithm if device/behavior not checked | MFA, device compliance, behavioral analytics, CAE |
| **Visible PEPs** | PEPs can be targeted for exploitation or circumvention | PEP hardening, network-invisible resources (SDP/dark cloud) |
| **Network-based attacks on ZTA components** | Lateral movement to compromise CDM, SIEM feeds | Separate admin network, privileged access workstations for ZTA management |

---

## CISA Zero Trust Maturity Model (ZTMM v2.0)

### Five Pillars Overview

| Pillar | Focus | Key Technologies |
|--------|-------|-----------------|
| **Identity** | Who is accessing | IdP, MFA, PAM, federation |
| **Devices** | What is accessing | MDM, EDR, device compliance, hardware attestation |
| **Networks** | How access is routed | Micro-segmentation, ZTNA, SDP, DNS security |
| **Applications & Workloads** | What is being accessed | App proxy, API gateway, service mesh, CASB |
| **Data** | What data is accessed | DLP, classification, encryption, rights management |

### Four Maturity Stages

| Stage | Description | Characteristics |
|-------|-------------|-----------------|
| **Traditional** | Starting point; legacy perimeter-based | Implicit trust, static policies, manual processes |
| **Initial** | ZT adoption beginning | Some MFA, basic device management, some segmentation |
| **Advanced** | Significant ZT implementation | Dynamic risk-based access, automated enforcement, broad telemetry |
| **Optimal** | Full ZT; self-healing and adaptive | Fully automated, behavior-based, continuous optimization |

### Maturity per Pillar

**Identity Pillar Maturity:**

| Stage | Characteristics |
|-------|----------------|
| Traditional | Username/password; static role assignments; no MFA |
| Initial | MFA deployed (SMS/push); basic SSO; manual provisioning |
| Advanced | Phishing-resistant MFA; risk-based Conditional Access; automated lifecycle; JIT privileged access |
| Optimal | Passwordless; continuous risk evaluation; AI-driven anomaly detection; automated remediation |

**Devices Pillar Maturity:**

| Stage | Characteristics |
|-------|----------------|
| Traditional | No device inventory; no compliance enforcement; corporate and BYOD undifferentiated |
| Initial | MDM enrollment for corporate devices; basic compliance policy; manual device approval |
| Advanced | Automated compliance enforcement; EDR integrated with IdP; hardware attestation; BYOD MAM |
| Optimal | Real-time device health signals feed access decisions; automated quarantine; zero-touch provisioning |

**Networks Pillar Maturity:**

| Stage | Characteristics |
|-------|----------------|
| Traditional | Flat network; perimeter firewall; VPN for remote access |
| Initial | VLAN segmentation; basic firewall rules; MFA for VPN |
| Advanced | Application-level micro-segmentation; ZTNA pilot; DNS filtering |
| Optimal | Full ZTNA replacing VPN; automated policy; service mesh mTLS; east-west inspection |

**Applications & Workloads Pillar Maturity:**

| Stage | Characteristics |
|-------|----------------|
| Traditional | On-prem apps; no API security; no workload identity |
| Initial | CASB for SaaS visibility; basic OAuth governance; app proxy for some apps |
| Advanced | All apps via ZTNA/proxy; mTLS between services; SPIFFE workload identity; SLSA L2+ |
| Optimal | Automated policy; full API gateway control; service mesh everywhere; SLSA L4 |

**Data Pillar Maturity:**

| Stage | Characteristics |
|-------|----------------|
| Traditional | No classification; perimeter DLP only; no encryption at rest for most data |
| Initial | Manual classification; basic DLP policies; encryption for regulated data |
| Advanced | Automated classification; endpoint + cloud DLP; Azure Information Protection; BYOK |
| Optimal | AI-driven classification; persistent encryption; automated DLP remediation; data lineage |

### Cross-Cutting Capabilities

| Capability | Description |
|-----------|-------------|
| **Visibility & Analytics** | SIEM, UEBA, XDR telemetry across all pillars; behavioral baseline; anomaly detection |
| **Automation & Orchestration** | SOAR-driven response; automated policy enforcement; self-healing access controls |
| **Governance** | Policy lifecycle management; ZT steering committee; continuous compliance reporting |

---

## Identity Pillar

### Identity as the New Perimeter

In Zero Trust, identity is the control plane. Every access request — regardless of network location — must be authenticated, authorized, and continuously evaluated. The IdP becomes the Policy Engine's primary input source.

### MFA Hierarchy (Phishing Resistance)

| Level | Method | Phishing Resistant | Notes |
|-------|--------|-------------------|-------|
| **Highest** | FIDO2/WebAuthn (hardware security key) | Yes | Cryptographically bound to origin; no secret transmitted |
| **High** | Windows Hello for Business | Yes | TPM-backed; biometric or PIN; device-bound |
| **High** | Certificate-based authentication (CBA) | Yes | PIV/CAC; smart card; requires PKI infrastructure |
| **Medium** | TOTP/HOTP (authenticator app) | No | Can be phished via real-time relay; better than push |
| **Medium** | Push notification with number matching | Partially | Number matching reduces fatigue attacks |
| **Low** | Push notification (approve/deny) | No | Vulnerable to MFA fatigue/push bombing |
| **Lowest** | SMS OTP | No | SIM-swapping, SS7 attacks; avoid for privileged access |

**EO 14028 and CISA guidance require phishing-resistant MFA (FIDO2/CBA) for federal systems.**

### Continuous Authentication & Risk Signals

| Signal | Description | Risk Weight |
|--------|-------------|-------------|
| Device health score | MDM compliance, EDR status, patch level | High |
| Location anomaly | Impossible travel, unfamiliar country, sanctioned location | High |
| Behavioral baseline | Typing patterns, access time, resource patterns (UEBA) | Medium |
| Time-of-day | Access outside normal working hours | Medium |
| Network risk | Tor exit node, known malicious IP, anonymous proxy | High |
| Identity risk score | IdP-assigned risk based on sign-in history | High |

### Passwordless Authentication

| Method | Technology | Trust Root | Use Case |
|--------|-----------|------------|----------|
| FIDO2 security key | WebAuthn + CTAP2 | Hardware key | High-assurance, privileged accounts |
| Windows Hello for Business | TPM + biometric/PIN | Device TPM | Windows endpoints, hybrid environments |
| Certificate-based auth | X.509 + smart card | PKI/CA | PIV, government, regulated industries |
| Passkeys (synced) | WebAuthn + cloud sync | Platform trust | Consumer-grade, general workforce |

### Privileged Identity Management

**Key controls for privileged access in ZT:**

- **JIT Access**: Privileges elevated only when needed, for bounded time (e.g., 1-hour window)
- **JEA (Just Enough Access)**: Only the specific permissions needed for the task — no standing admin rights
- **Approval Workflows**: Manager or peer approval required for sensitive elevation
- **Privileged Access Workstations (PAWs)**: Dedicated hardened devices for admin tasks only
- **Session Recording**: All privileged sessions recorded for audit; real-time monitoring for anomalies
- **Credential Vaulting**: Shared admin passwords stored in PAM vault; checked out per session

**Microsoft Entra PIM flow:**
```
User requests elevation → Approval (manager/peer) → Time-bounded role assignment
→ MFA re-authentication required → Session monitored → Auto-expire
```

### Identity Federation

| Protocol | Use Case | ZT Considerations |
|----------|----------|-------------------|
| **SAML 2.0** | Enterprise SSO, legacy apps | Ensure assertion signing; short assertion lifetime |
| **OIDC** | Modern web/mobile apps | Use authorization code + PKCE; validate `aud` claim |
| **OAuth 2.0** | API authorization | Client credentials for M2M; PKCE for public clients |
| **WS-Federation** | Microsoft/ADFS legacy | Migration path to OIDC preferred for ZT |

**OAuth 2.0 Authorization Code + PKCE (Zero Trust recommended flow):**
```
Client → code_verifier + code_challenge (S256) → Authorization endpoint
Auth endpoint → authorization_code → Client
Client → code + code_verifier → Token endpoint
Token endpoint verifies challenge → issues access_token (short-lived) + refresh_token
```

### Entra ID Conditional Access

**Policy structure:**

| Element | Options |
|---------|---------|
| **Users/Groups** | Specific users, groups, roles, guests |
| **Cloud apps** | All apps, specific SaaS, app registration |
| **Conditions** | Sign-in risk, user risk, device platform, location, client apps |
| **Controls** | Require MFA, require compliant device, require hybrid join, block |

**Key Conditional Access policies for ZT:**

1. **Require phishing-resistant MFA for all users**: Conditions = All apps; Control = Require authentication strength (phishing-resistant)
2. **Block legacy authentication**: Conditions = Client apps (Exchange ActiveSync, Other clients); Control = Block
3. **Require device compliance for M365**: Conditions = Office 365; Control = Require compliant device
4. **Named location blocking**: Conditions = Location = All except trusted countries; Control = Block or require MFA
5. **High-risk sign-in remediation**: Conditions = Sign-in risk = High; Control = Require MFA + password change

**Continuous Access Evaluation (CAE)**: Near-real-time revocation of access tokens when:
- User account disabled or deleted
- Password changed
- MFA revoked
- Token issued from non-compliant location
- IP address change detected (for CAE-capable clients)

---

## Devices Pillar

### Device Identity and Health Attestation

Every device accessing enterprise resources must have a verifiable identity and demonstrated compliance posture.

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Device identity** | Entra ID device registration, Intune enrollment, device certificate | Cryptographic device identity |
| **Compliance policy** | Intune compliance policy | Defines minimum health bar |
| **Health attestation** | Windows Health Attestation Service, TPM | Verifies boot integrity |
| **EDR signal** | CrowdStrike, SentinelOne, Defender for Endpoint risk score | Runtime threat status |

**Intune compliance policy elements (Windows example):**
- BitLocker encryption required
- Secure Boot enabled
- Code Integrity enabled (HVCI)
- Minimum OS version enforced
- No jailbreak/root detected
- Antivirus enabled and up to date
- Firewall enabled
- Threat agent at or below configured risk level (EDR integration)

### Endpoint Detection and Response (EDR) in ZT

EDR is a required component of ZT device health. The EDR platform must:
1. Provide a real-time device risk score to the IdP/CA engine
2. Automatically quarantine compromised devices (triggering CAE token revocation)
3. Feed telemetry to SIEM/XDR for correlation with identity and network events

**EDR → IdP integration pattern:**
```
Device behavior anomaly detected → EDR risk score elevated
→ Signal sent to IdP (via Microsoft Defender for Endpoint + Intune, or CrowdStrike Falcon + Okta)
→ Conditional Access evaluates new risk score
→ Access revoked or step-up MFA required
→ User prompted to remediate device
```

### BYOD vs Corporate-Managed Devices

| Dimension | Corporate Managed (MDM) | BYOD (MAM) |
|-----------|------------------------|-----------|
| **Management scope** | Full device management | App-level management only |
| **Data isolation** | Device encryption, wipe | Selective app wipe |
| **Compliance enforcement** | Full compliance policy | App protection policy |
| **Access level** | Full enterprise access | Limited to approved apps/data |
| **User privacy** | Low (employer visibility) | High (personal data protected) |
| **Technology** | Intune MDM, Jamf | Intune MAM, Intune App Protection Policies |

### Hardware Attestation

| Technology | Purpose | Platform |
|-----------|---------|---------|
| **TPM 2.0** | Cryptographic attestation of boot state, key storage | Windows, Linux |
| **Secure Boot** | Verifies bootloader signature chain against UEFI DB | UEFI platforms |
| **HVCI (Memory Integrity)** | Kernel code integrity; blocks unsigned kernel drivers | Windows 10/11 |
| **Apple T2/Secure Enclave** | Boot integrity, encrypted storage, biometric data isolation | macOS, iOS |
| **Android Verified Boot** | Boot chain verification | Android |
| **Windows Autopilot** | Cloud-driven device provisioning without imaging | Windows 10/11 |
| **Apple Business Manager** | Zero-touch DEP enrollment | macOS, iOS, iPadOS |

### Patch Compliance as Access Gate

ZT requires patch compliance to be enforced as an access control, not just a hygiene metric.

**Policy design:**
- Devices with critical/high severity unpatched CVEs (>30 days): **Block** or **limit to remediation network**
- Devices missing OS updates (>60 days): **Require MFA + alert user**
- Grace period (7-14 days) for newly released patches: **Allow but log**
- Emergency patches (actively exploited): **48-hour compliance window**

---

## Networks Pillar

### Micro-Segmentation Approaches

| Approach | Technology Examples | Granularity | Complexity |
|----------|--------------------|-----------|-----------|
| **Host-based** | Illumio Core, Guardicore (Akamai), Windows Firewall with Advanced Security | Per-workload, per-process | Medium |
| **Hypervisor-based** | VMware NSX, AWS Security Groups | Per-VM | Low-medium |
| **Network-based** | Cisco ACI, Juniper Contrail | Per-segment/VLAN | Medium-high |
| **Service mesh** | Istio, Linkerd, Consul Connect | Per-service, per-pod | High (K8s environments) |

**Micro-segmentation design principles:**
1. Identify and classify all workloads (crown jewels first)
2. Map application dependencies (what talks to what)
3. Define allowed flows; deny everything else (allowlist model)
4. Start with monitoring mode; enforce incrementally
5. Never allow flat east-west access between security zones

### Software-Defined Perimeter (SDP) / ZTNA

**SDP Architecture:**
```
Initiating Host (IH) → Single Packet Authorization (SPA) → Accepting Host (AH)
IH authenticated → Mutual TLS tunnel established → Access to protected Controller (CH)
CH validates policy → Resource access granted (resource remains dark/invisible to unauthenticated hosts)
```

**ZTNA vs VPN Comparison:**

| Dimension | Traditional VPN | ZTNA |
|-----------|----------------|------|
| **Network access** | Full network segment | Per-application, per-session |
| **Resource visibility** | All resources visible once connected | Resources invisible until authorized |
| **Trust model** | Trust the pipe | Trust the request (identity + device + context) |
| **Lateral movement** | Possible — full network access | Blocked — app-level tunnels only |
| **Performance** | Backhauled through corporate gateway | Direct-to-app (cloud-native) or gateway optimized |
| **User experience** | Client VPN; noticeable latency | Transparent proxy or lightweight agent |
| **Split tunneling** | Risk if enabled | Inherent — only app traffic tunneled |

### ZTNA Vendor Landscape

| Vendor | Product | Deployment Model | Key Differentiator |
|--------|---------|-----------------|-------------------|
| **Zscaler** | Zscaler Private Access (ZPA) | Cloud-native (proxy) | Largest cloud backbone; inline inspection |
| **Palo Alto** | Prisma Access | Cloud-delivered SASE | Integrated NGFW policy; SD-WAN |
| **Cloudflare** | Cloudflare Access (Zero Trust) | Cloud-native | Anycast performance; email security integration |
| **Netskope** | Netskope Private Access | Cloud-native | Strong DLP integration; data-centric |
| **Cisco** | Cisco Secure Access (formerly Duo) | Cloud + on-prem hybrid | Duo MFA integration; network segmentation |
| **Microsoft** | Entra Private Access | Cloud-native (preview) | Deep Entra ID integration; Conditional Access |

### DNS Security in ZT

| Technique | Purpose | Products |
|-----------|---------|---------|
| **DNS over HTTPS (DoH)** | Encrypted DNS queries; prevents eavesdropping | Cloudflare 1.1.1.1, NextDNS |
| **DNS over TLS (DoT)** | Encrypted DNS at transport layer | BIND 9.17+, Unbound |
| **DNS filtering** | Block malicious domains, C2, phishing | Cisco Umbrella, Cloudflare Gateway, Quad9 |
| **Split-horizon DNS** | Internal names resolve internally; external via public DNS | Windows DNS, BIND views |
| **DNSSEC** | Cryptographic validation of DNS responses | Registry/registrar support required |

### East-West Traffic Inspection

In ZT, lateral (east-west) traffic between workloads requires inspection, not just perimeter filtering.

**Approaches:**
- **Service Mesh mTLS**: All service-to-service traffic encrypted and authenticated via short-lived X.509 certs (Istio, Linkerd)
- **Network Traffic Analysis (NTA)**: Behavioral analytics on east-west flows (Darktrace, ExtraHop, Vectra AI)
- **Micro-segment policy logging**: Log all denied flows for anomaly detection
- **Deception technology**: Deploy honeypots in microsegments; lateral movement triggers immediate alert

---

## Applications & Workloads Pillar

### Application Access Control (ZTNA App-Level)

ZT application access is granted per-application, per-session — never at the network layer.

**Access decision inputs:**
- User identity + risk score
- Device compliance status
- Application sensitivity classification
- Session context (location, time, client)
- Historical access pattern baseline

### API Gateway Security

| Control | Implementation | Standard |
|---------|---------------|---------|
| **OAuth 2.0 token validation** | Validate `iss`, `aud`, `exp`, `scope` claims | RFC 6749, RFC 7519 |
| **Rate limiting** | Per-client, per-endpoint request throttling | OWASP API Security |
| **mTLS between services** | Client certificate required for API consumers | RFC 8705 |
| **API key rotation** | Short-lived API keys; automated rotation | NIST 800-57 |
| **Input validation** | Schema validation; injection prevention | OWASP API Top 10 |
| **Logging & monitoring** | All API calls logged with identity context | NIST 800-53 AU-12 |

### Service Mesh — Istio Configuration Examples

**mTLS enforcement (PeerAuthentication):**
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # STRICT = mTLS required; PERMISSIVE = allow plain-text (migration only)
```

**Authorization Policy (allow only checkout service to call payments):**
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payments-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: payments
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/checkout"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/api/v1/charge"]
```

### Workload Identity — SPIFFE/SPIRE

**SPIFFE (Secure Production Identity Framework For Everyone):**

- Defines a standard for workload identity: **SPIFFE Verifiable Identity Document (SVID)**
- SVIDs are X.509 certificates or JWT tokens encoding the **SPIFFE ID** (URI: `spiffe://trust-domain/workload-id`)
- Short-lived certs (hours, not years); automated rotation via SPIRE agent

**SPIRE architecture:**
```
SPIRE Server (trust anchor) → issues SVIDs
SPIRE Agent (on each node) → attests workload identity via node attestor (e.g., AWS Instance Identity, k8s PSAT)
Workload (pod/process) → receives SVID via SPIFFE Workload API (Unix domain socket)
```

### CI/CD Pipeline Security (ZT for DevOps)

| Control | Description | SLSA Level |
|---------|-------------|-----------|
| **Source provenance** | All code changes via authenticated, reviewed PRs | SLSA 1 |
| **Build service** | Builds run on dedicated, ephemeral build infrastructure | SLSA 2 |
| **Artifact attestation** | Signed build provenance attached to every artifact | SLSA 2-3 |
| **Hermetic builds** | No external network access during build; reproducible | SLSA 4 |
| **Two-party review** | No single person can approve and merge own code | SLSA 4 |
| **Policy enforcement** | OPA/Gatekeeper enforces attestation at deploy time | SLSA 3-4 |

### SaaS Security (CASB Integration)

| CASB Function | Description | Products |
|--------------|-------------|---------|
| **Shadow IT discovery** | Identify unsanctioned SaaS usage | Microsoft Defender for Cloud Apps, Netskope |
| **OAuth app governance** | Inventory and revoke risky OAuth app consents | Entra ID App Governance, Okta |
| **Session controls** | Real-time session inspection; prevent download to unmanaged devices | MCAS session policy, Zscaler |
| **DLP in SaaS** | Prevent sensitive data upload to unsanctioned apps | Netskope, Forcepoint |
| **Anomaly detection** | Unusual download volume, after-hours access | Microsoft Defender for Cloud Apps |

---

## Data Pillar

### Data Classification Framework

**Lifecycle:**
```
Discover → Classify → Label → Protect → Monitor → Review
```

| Classification Level | Description | Example Data | Controls |
|---------------------|-------------|-------------|---------|
| **Public** | Intentionally public | Marketing materials, press releases | None required |
| **Internal** | Internal use; no regulated data | Internal policies, org charts | Basic access control |
| **Confidential** | Business-sensitive; limited distribution | Financial forecasts, contracts, source code | Encryption, DLP, access logging |
| **Restricted / Secret** | Regulated or highly sensitive | PII, PHI, PCI data, trade secrets | Strict access control, encryption, DLP, audit |

### Microsoft Purview Information Protection

| Feature | Description |
|---------|-------------|
| **Sensitivity labels** | Persistent metadata applied to documents and emails; drive encryption and DLP |
| **Auto-labeling** | ML-based content inspection; apply labels without user action |
| **Mandatory labeling** | Users must classify before saving or sending |
| **DLP policies** | Block sharing of labeled/sensitive content based on policy |
| **Unified audit log** | All label changes, DLP policy matches, access events logged |

### Data-Centric Security Controls

| Layer | Control | Technology |
|-------|---------|-----------|
| **Encryption at rest** | AES-256; BYOK/HYOK for highest sensitivity | Azure Disk Encryption, SQL TDE, S3 SSE-KMS |
| **Encryption in transit** | TLS 1.2+ minimum; TLS 1.3 preferred; mTLS for service-to-service | NIST SP 800-52 |
| **Key management** | HSM-backed key management; key rotation policy; access logging | Azure Key Vault Premium, AWS KMS, HashiCorp Vault |
| **Tokenization** | Replace sensitive data (PAN, SSN) with non-sensitive token | PCI DSS scope reduction |
| **Data masking** | Dynamic masking for non-production environments | Azure SQL Dynamic Data Masking |

### Data Loss Prevention

| DLP Layer | What It Covers | Policy Example |
|-----------|---------------|---------------|
| **Endpoint DLP** | Files on devices; USB transfers; print | Block copy of "Confidential" labeled file to USB |
| **Network DLP** | Data leaving network perimeter | Block PCI data upload to non-approved cloud |
| **Cloud DLP** | Data in SaaS and IaaS | Alert on SSN in public SharePoint site |
| **Email DLP** | Sensitive content in email/attachments | Block send of health records externally |

### Rights Management (AIP / MSIP)

Azure Information Protection (AIP) applies **persistent encryption** that travels with the document:
- Encryption enforced even if file is exfiltrated outside corporate environment
- Access rights (view, edit, print, copy, forward) defined at label level
- Revoke access server-side; encryption key request denied to all clients
- Audit log of every open, edit, and failed access attempt

---

## ZT Implementation Roadmap

### Phase 0: Maturity Assessment (Week 1-2)

1. Map current capabilities to CISA ZTMM stages per pillar
2. Identify crown-jewel assets and highest-risk access paths
3. Document all identity sources (AD, Entra ID, local accounts, service accounts)
4. Inventory all devices (managed, BYOD, IoT, OT)
5. Map network topology and identify flat zones
6. Document all data stores and classification status
7. Generate gap analysis report with prioritized remediation

### Phase 1: Quick Wins (Days 0-30)

| Action | Pillar | Impact |
|--------|--------|--------|
| Enable MFA for all users (start with push+number matching, target FIDO2) | Identity | High |
| Block legacy authentication protocols | Identity | High |
| Enable unified audit logging (Entra ID, M365, cloud platforms) | All pillars | High |
| Deploy EDR to all endpoints | Devices | High |
| Inventory all service accounts and eliminate unnecessary ones | Identity | Medium |
| Enable SSPR to reduce help desk load | Identity | Medium |
| Enable Entra ID Identity Protection (sign-in + user risk policies) | Identity | High |
| Configure named location Conditional Access | Identity/Network | Medium |

### Phase 2: Short-Term (Days 30-90)

| Action | Pillar | Impact |
|--------|--------|--------|
| Deploy ZTNA pilot for highest-risk remote access use case | Network | High |
| Implement PAWs for all Tier 0/1 administrators | Identity/Devices | High |
| Enable Intune MDM for all corporate Windows/macOS devices | Devices | High |
| Micro-segment crown-jewel applications from rest of network | Network | High |
| Deploy CASB for SaaS visibility and OAuth app governance | Applications | Medium |
| Implement PIM for all privileged roles (Azure, AD, M365) | Identity | High |
| Configure device compliance policies; enforce via Conditional Access | Devices | High |
| Pilot data classification with sensitivity labels on M365 | Data | Medium |

### Phase 3: Medium-Term (Days 90-180)

| Action | Pillar | Impact |
|--------|--------|--------|
| Enable Continuous Access Evaluation (CAE) | Identity/Network | High |
| Enforce device compliance for all application access | Devices | High |
| Roll out sensitivity labels + auto-labeling organization-wide | Data | High |
| Deploy endpoint DLP for "Restricted" labeled content | Data | High |
| Expand micro-segmentation to all application tiers | Network | High |
| Implement SPIFFE/SPIRE or equivalent for workload identity | Applications | Medium |
| Migrate all service-to-service communication to mTLS | Applications | Medium |
| Deploy NTA/UEBA for east-west traffic analysis | Network | Medium |

### Phase 4: Long-Term (Days 180+)

| Action | Pillar | Impact |
|--------|--------|--------|
| Complete ZTNA rollout; decommission legacy VPN | Network | High |
| Achieve phishing-resistant MFA for 100% of users | Identity | High |
| Fully automated policy enforcement via SOAR | All | High |
| Adaptive access maturity: real-time behavior-based access decisions | Identity | High |
| SLSA Level 3+ for all production software builds | Applications | Medium |
| Full data lifecycle management with automated retention/deletion | Data | Medium |
| ZT for OT/IoT: device proxies, network segmentation, monitoring | Devices/Network | High |

---

## ZT Vendors & Tools

### Comprehensive Vendor Matrix

| Pillar | Vendor | Product | Key Capability | Deployment Model |
|--------|--------|---------|---------------|-----------------|
| **Identity** | Microsoft | Entra ID (Azure AD) | Conditional Access, PIM, Identity Protection, CAE | Cloud (SaaS) |
| **Identity** | Okta | Okta Identity Cloud | Universal Directory, Adaptive MFA, Lifecycle Mgmt | Cloud (SaaS) |
| **Identity** | Ping Identity | PingOne, PingFederate | Federation, SSO, adaptive MFA | Cloud or on-prem |
| **Identity** | CyberArk | Privilege Cloud, EPM | PAM, credential vault, JIT access, session recording | Cloud or on-prem |
| **Identity** | BeyondTrust | Privileged Remote Access | Privileged access management, session control | Cloud or on-prem |
| **Identity** | Beyond Identity | Beyond Identity Platform | Phishing-resistant, passwordless, device trust | Cloud (SaaS) |
| **Devices** | Microsoft | Intune (Endpoint Manager) | MDM, MAM, compliance policy, app protection | Cloud (SaaS) |
| **Devices** | Jamf | Jamf Pro, Jamf Protect | macOS/iOS MDM, compliance, EDR | Cloud or on-prem |
| **Devices** | CrowdStrike | Falcon | EDR, XDR, device health signal to IdP | Cloud (SaaS) |
| **Devices** | SentinelOne | Singularity Platform | EDR, XDR, autonomous response | Cloud (SaaS) |
| **Devices** | Microsoft | Defender for Endpoint | EDR, Intune integration, device risk score | Cloud (SaaS) |
| **Network** | Zscaler | ZPA, ZIA | ZTNA, SWG, CASB, SASE | Cloud (SaaS) |
| **Network** | Palo Alto | Prisma Access, NGFW | SASE, ZTNA, ML-powered NGFW | Cloud or on-prem |
| **Network** | Cloudflare | Cloudflare One | ZTNA, SWG, CASB, email security | Cloud (SaaS) |
| **Network** | Cisco | Secure Access, Umbrella | ZTNA, DNS security, SASE | Cloud or hybrid |
| **Network** | Illumio | Illumio Core | Host-based micro-segmentation | Agent-based |
| **Network** | Akamai | Guardicore | Micro-segmentation, ransomware prevention | Agent-based |
| **Applications** | Istio | Istio Service Mesh | mTLS, authorization policies, traffic management | Open source (K8s) |
| **Applications** | HashiCorp | Vault | Secrets management, PKI, encryption as a service | Open source/Cloud |
| **Applications** | SPIFFE | SPIRE | Workload identity, SVID issuance, cert rotation | Open source |
| **Applications** | Google | Apigee | API gateway, OAuth, rate limiting, analytics | Cloud (SaaS/GCP) |
| **Applications** | Microsoft | Defender for Cloud Apps | CASB, shadow IT, session controls, DLP | Cloud (SaaS) |
| **Data** | Microsoft | Purview (MIP + DLP) | Classification, labeling, DLP, compliance | Cloud (SaaS) |
| **Data** | Forcepoint | DLP, DSPM | Endpoint + network + cloud DLP | Cloud or on-prem |
| **Data** | Digital Guardian | DLP Platform | Endpoint DLP, data classification, insider threat | Cloud or on-prem |
| **Data** | Varonis | Data Security Platform | Data discovery, classification, UEBA, access governance | Cloud or on-prem |
| **Data** | BigID | BigID Platform | Data discovery, PII/PI identification, remediation | Cloud (SaaS) |

---

## ZT Metrics & KPIs

### Identity KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| MFA enrollment rate | 100% of users | IdP report: users with MFA registered / total users |
| Phishing-resistant MFA adoption | >80% of users | IdP report: FIDO2/CBA registrations / total |
| Privileged account coverage in PAM | 100% of privileged accounts | PAM vault: managed accounts / known privileged accounts |
| JIT access usage rate | >90% of privileged sessions | PIM report: JIT activations vs standing assignments |
| Passwordless adoption rate | Progressive; target 50% Year 1 | IdP: passwordless authentications / total |

### Device KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Device compliance rate | >95% managed devices | Intune compliance report |
| EDR coverage | 100% of managed endpoints | EDR console: enrolled / total managed devices |
| Unmanaged device access attempts blocked | Decreasing trend | CA policy logs: blocked non-compliant sign-ins |
| Mean time to patch critical CVEs | <72 hours | Patch management report |
| Devices with hardware attestation (TPM+Secure Boot) | >90% | Intune hardware attestation report |

### Network KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| ZTNA coverage (% of apps via ZTNA vs VPN) | Progressive; target 100% | ZTNA gateway: apps onboarded / total apps |
| Micro-segmentation coverage | >80% of crown-jewel workloads | Segmentation platform: enforced policies / total workloads |
| East-west denied flows | Baseline + track anomalies | NTA/firewall logs: denied east-west connections |
| Lateral movement incidents | Decreasing year-over-year | SIEM: lateral movement detections |

### Applications & Data KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Applications using mTLS | >90% of internal service-to-service | Service mesh telemetry |
| Data classification coverage | >90% of sensitive data stores | Purview: classified files / total sensitive files |
| DLP policy violations | Decreasing trend; <5% false positive rate | DLP policy match report |
| Privileged session monitoring coverage | 100% of admin sessions | PAM: recorded sessions / total privileged sessions |
| Micro-segment policy violations | Decreasing trend | Segmentation logs: policy violations |

### Executive / Board Metrics

| Metric | Frequency | Audience |
|--------|-----------|---------|
| ZT maturity score per pillar (CISA ZTMM stage) | Quarterly | CISO, Board |
| MFA coverage | Monthly | CISO |
| Unpatched critical CVE count | Weekly | Security team |
| Privileged access policy exceptions | Monthly | CISO |
| Mean time to detect (MTTD) lateral movement | Monthly | Security team |
| Data breach cost risk reduction (from ZT controls) | Annually | Board, CFO |

---

## Regulatory & Framework Mapping

### NIST SP 800-53 Control Family Mapping

| ZT Pillar | NIST 800-53 Families | Key Controls |
|-----------|---------------------|-------------|
| **Identity** | AC (Access Control), IA (Identification & Authentication) | AC-2, AC-3, AC-6, AC-17; IA-2, IA-3, IA-5, IA-8 |
| **Devices** | CM (Configuration Mgmt), SI (System Integrity), RA (Risk Assessment) | CM-2, CM-6, CM-7, CM-8; SI-2, SI-3, SI-7; RA-5 |
| **Networks** | SC (System Communications), CA (Assessment) | SC-7, SC-8, SC-10, SC-17, SC-20; CA-3, CA-9 |
| **Applications** | SA (System & Services Acquisition), SI | SA-10, SA-11, SA-15; SI-7, SI-10 |
| **Data** | MP (Media Protection), SC, AU | MP-2, MP-4, MP-6; SC-12, SC-13, SC-28; AU-9 |
| **Cross-cutting** | AU (Audit), IR (Incident Response), PL (Planning) | AU-2, AU-6, AU-12; IR-4, IR-5, IR-6; PL-8 |

### EO 14028 Requirements (Improving the Nation's Cybersecurity)

| EO 14028 Requirement | ZT Implementation |
|--------------------|-------------------|
| Agencies shall advance toward ZTA | CISA ZTMM as maturity framework |
| Phishing-resistant MFA required | FIDO2/WebAuthn or CBA for all federal users |
| Encryption of data in transit and at rest | TLS 1.2+ everywhere; AES-256 at rest |
| EDR deployment across federal enterprise | EDR with telemetry to SOC |
| Improved detection of cybersecurity incidents | SIEM/SOAR; threat hunting capability |
| Log retention for NCPS/CDM | 20-month retention minimum (CISA guidance) |

### CISA Zero Trust Guidance Alignment

| CISA Publication | Key Guidance | ZT Pillar |
|-----------------|-------------|----------|
| CISA ZTMM v2.0 | Five-pillar maturity model | All |
| CISA ZT Principles | Never trust, always verify; assume breach; least privilege | All |
| CISA SCuBA (M365) | Hardening guidance for M365 ZT deployment | Identity, Applications |
| CISA Known Exploited Vulnerabilities (KEV) | Mandatory patching within 2 weeks | Devices |
| CISA Binding Operational Directives (BODs) | BOD 22-01 (KEV), BOD 25-01 (M365 SCuBA) | Devices, Applications |

---

## Quick Reference Checklists

### ZT Readiness Checklist (Minimum Viable ZT)

- [ ] MFA enabled for 100% of users
- [ ] Legacy authentication blocked
- [ ] EDR deployed to all managed endpoints
- [ ] Device compliance policy enforced via Conditional Access
- [ ] Privileged accounts managed via PAM/PIM with JIT
- [ ] Audit logging enabled for all identity, device, and application events
- [ ] Data classification in place for sensitive data stores
- [ ] Network segmentation separating crown-jewel assets
- [ ] ZTNA deployed for at least one high-risk access use case
- [ ] Incident response plan updated to reflect ZT architecture

### Key NIST 800-207 References

- Section 2: ZTA tenets and logical architecture
- Section 3: ZTA network component variations
- Section 4: Deployment scenarios
- Section 5: Threats to ZTA
- Appendix D: ZTA and existing NIST frameworks

---

*References: NIST SP 800-207 (2020), CISA Zero Trust Maturity Model v2.0 (2023), EO 14028 (2021), NIST SP 800-53 Rev 5, CISA SCuBA M365 Secure Configuration Baselines, OWASP API Security Top 10, SLSA Framework v1.0, SPIFFE/SPIRE project (CNCF), Istio security documentation.*

*Last updated: 2026-04-21*
