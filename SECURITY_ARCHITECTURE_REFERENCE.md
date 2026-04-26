# Security Architecture Reference

A comprehensive reference for security architects, covering frameworks, design
patterns, cloud security, application security, identity, operations, and
resilience architecture. Intended as a practitioner's handbook for designing
and reviewing security architectures across modern enterprise environments.

---

## Table of Contents

1. [Security Architecture Fundamentals](#1-security-architecture-fundamentals)
2. [Zero Trust Architecture](#2-zero-trust-architecture)
3. [Network Security Architecture](#3-network-security-architecture)
4. [Cloud Security Architecture](#4-cloud-security-architecture)
5. [Application Security Architecture](#5-application-security-architecture)
6. [Data Security Architecture](#6-data-security-architecture)
7. [Identity Architecture](#7-identity-architecture)
8. [Security Operations Architecture](#8-security-operations-architecture)
9. [Resilience Architecture](#9-resilience-architecture)
10. [Architecture Review Process](#10-architecture-review-process)

---

## 1. Security Architecture Fundamentals

### 1.1 Defense-in-Depth Model

Defense-in-depth (DiD) is the practice of layering security controls so that
the failure of one control does not expose the entire system. Each layer
reduces the attack surface that a threat actor must traverse.

```
┌─────────────────────────────────────────────────────────┐
│                    PERIMETER LAYER                      │
│  Firewalls · DDoS Protection · WAF · Email Gateway      │
│  ┌───────────────────────────────────────────────────┐  │
│  │                 NETWORK LAYER                     │  │
│  │  IDS/IPS · VLAN Segmentation · NAC · SD-WAN       │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │               HOST LAYER                   │  │  │
│  │  │  EDR · HIDS · OS Hardening · Patch Mgmt     │  │  │
│  │  │  ┌───────────────────────────────────────┐  │  │  │
│  │  │  │          APPLICATION LAYER           │  │  │  │
│  │  │  │  SAST/DAST · WAF · RASP · MFA         │  │  │  │
│  │  │  │  ┌─────────────────────────────────┐  │  │  │  │
│  │  │  │  │          DATA LAYER            │  │  │  │  │
│  │  │  │  │  Encryption · DLP · DAM · IRM   │  │  │  │  │
│  │  │  │  └─────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**Layer Responsibilities:**

| Layer | Primary Controls | Example Technologies |
|---|---|---|
| Perimeter | Block external threats before network entry | Palo Alto NGFW, Cloudflare DDoS, Proofpoint |
| Network | Segment traffic; detect lateral movement | Cisco ISE, Zeek, Darktrace, Illumio |
| Host | Prevent and detect host-level compromise | CrowdStrike Falcon, Tanium, CIS benchmarks |
| Application | Secure code and runtime behavior | Veracode, Contrast RASP, Akamai WAF |
| Data | Protect data regardless of context | Varonis, Informatica DSPM, AWS KMS, HSMs |

The layers are not purely sequential. An attacker who bypasses the perimeter
still faces network, host, application, and data controls. The goal is to
raise the cost of successful exploitation to an economically prohibitive level.

### 1.2 Security Architecture Frameworks

#### SABSA (Sherwood Applied Business Security Architecture)

SABSA is a risk-driven enterprise security architecture framework. It uses a
layered matrix (the SABSA matrix) adapted from the Zachman Framework for
enterprise architecture, applying it to security concerns.

**SABSA Matrix Layers:**

| Layer | Perspective | What it answers |
|---|---|---|
| Contextual | Business | What are the business risks and drivers? |
| Conceptual | Architect | What are the security concepts and principles? |
| Logical | Designer | What are the security services and policies? |
| Physical | Builder | What are the technology mechanisms? |
| Component | Tradesman | What are the products and tools? |
| Operational | Facilities Manager | How is the architecture managed day-to-day? |

Each cell of the matrix is further divided across six attributes: Assets,
Motivation, Process, People, Location, and Time. SABSA is particularly
well-suited for large enterprise and government programs requiring rigorous
traceability from business risk to security control.

**SABSA Architecture Process:**
1. Establish business context and risk appetite (Contextual)
2. Define security principles and conceptual architecture (Conceptual)
3. Design security services and information flows (Logical)
4. Map to technology platforms and protocols (Physical)
5. Select specific products and configurations (Component)
6. Define operational procedures and governance (Operational)

#### TOGAF Security (The Open Group Architecture Framework)

TOGAF provides a generic enterprise architecture method (ADM — Architecture
Development Method) that can be extended with a security overlay.

**Security in the TOGAF ADM Phases:**

| ADM Phase | Security Activity |
|---|---|
| Preliminary | Define security principles, governance model |
| Phase A (Architecture Vision) | Identify security requirements from business goals |
| Phase B (Business Architecture) | Map business processes to security controls |
| Phase C (IS Architecture) | Data security architecture, application security patterns |
| Phase D (Technology Architecture) | Infrastructure security, network segmentation |
| Phase E (Opportunities & Solutions) | Security technology roadmap |
| Phase F (Migration Planning) | Security migration planning with risk assessment |
| Phase G (Implementation Governance) | Security compliance checkpoints |
| Phase H (Architecture Change Management) | Security impact assessments for changes |
| Requirements Management | Continuous security requirements tracing |

#### O-ESA (Open Enterprise Security Architecture)

The Open Group's O-ESA provides a framework for describing enterprise security
architectures using a consistent taxonomy. Key components:
- **Security Domain Model**: Defines trust domains and their boundaries
- **Security Services Taxonomy**: Authentication, authorization, audit, privacy, availability
- **Architecture Patterns Catalog**: Reusable security design patterns
- **Control Objectives Catalog**: Technology-neutral control objectives

### 1.3 Threat-Driven Architecture Design Process

A threat-driven approach starts with adversary capabilities and designs
controls that specifically address identified threats, rather than applying
generic checklists.

**Process Steps:**

```
1. ASSET IDENTIFICATION
   └─ Crown jewels · Business-critical data · Key infrastructure

2. THREAT LANDSCAPE ANALYSIS
   └─ MITRE ATT&CK · Threat intel feeds · Historical incidents
   └─ Adversary profiling (nation-state, cybercriminal, insider)

3. ATTACK SURFACE MAPPING
   └─ External attack surface · Internal lateral movement paths
   └─ Supply chain entry points · Human attack vectors

4. THREAT MODELING (STRIDE / PASTA / LINDDUN)
   └─ Spoofing · Tampering · Repudiation · Info Disclosure
   └─ Denial of Service · Elevation of Privilege

5. CONTROL SELECTION
   └─ Map controls to specific threat scenarios
   └─ Cost-benefit analysis per control
   └─ Residual risk acceptance

6. ARCHITECTURE DOCUMENTATION
   └─ Architecture Decision Records (ADRs)
   └─ Data Flow Diagrams with trust boundaries
   └─ Security control mapping table

7. VALIDATION
   └─ Red team exercise or penetration test
   └─ Architecture review board sign-off
   └─ Threat model refresh on significant changes
```

### 1.4 Security Requirements Derivation from Threat Models

Converting threat model output into actionable security requirements:

**STRIDE to Security Requirement Mapping:**

| STRIDE Category | Threat Example | Security Requirement |
|---|---|---|
| Spoofing | Attacker impersonates admin | REQ-AUTH-01: All admin actions require MFA |
| Tampering | Attacker modifies config file | REQ-INT-01: Config files must have integrity monitoring |
| Repudiation | User denies executing command | REQ-AUD-01: All privileged commands must be logged with non-repudiation |
| Information Disclosure | Data in transit intercepted | REQ-CONF-01: All data in transit encrypted with TLS 1.2+ |
| Denial of Service | API flooded with requests | REQ-AVAIL-01: Rate limiting applied at API gateway |
| Elevation of Privilege | User exploits misconfigured RBAC | REQ-AUTHZ-01: Least-privilege RBAC with quarterly review |

**Requirements Attributes:**

Each derived requirement should include:
- **Unique ID**: Traceable to source threat scenario
- **Statement**: Clear, testable requirement statement
- **Threat Source**: STRIDE category and specific threat scenario
- **Priority**: Critical / High / Medium / Low
- **Verification Method**: Test, inspection, or analysis
- **Owner**: System/component owner responsible for implementation

### 1.5 Architecture Decision Records (ADR) for Security

ADRs document the context, options considered, and rationale for significant
architectural decisions. Security ADRs are especially important for decisions
that affect the attack surface or control effectiveness.

**Security ADR Template:**

```markdown
# ADR-SEC-NNN: [Short Title]

## Status
Proposed | Accepted | Deprecated | Superseded by ADR-SEC-NNN

## Context
[Describe the problem or decision that needs to be made.
Include relevant threat context and business requirements.]

## Decision Drivers
- [Business driver 1]
- [Security requirement 1]
- [Compliance obligation 1]

## Considered Options
- Option A: [Brief description]
- Option B: [Brief description]
- Option C: [Brief description]

## Decision Outcome
Chosen option: [Option X], because [justification].

### Positive Consequences
- [Benefit 1]
- [Benefit 2]

### Negative Consequences / Risks
- [Risk 1 and mitigations]

## Pros and Cons of Options

### Option A
- Good: [argument]
- Bad: [argument]

### Option B
- Good: [argument]
- Bad: [argument]

## Links
- [Link to threat model]
- [Link to relevant standard or framework]
- [Link to related ADRs]
```

---

## 2. Zero Trust Architecture

### 2.1 NIST SP 800-207 Core Tenets

NIST SP 800-207 defines Zero Trust Architecture (ZTA) as a collection of
concepts and ideas designed to minimize uncertainty in enforcing accurate,
least privilege per-request access decisions. The seven tenets:

1. **All data sources and computing services are considered resources.**
   Personal devices, IoT, SaaS, and cloud services are all resources regardless
   of network location.

2. **All communication is secured regardless of network location.**
   Trust is not derived from being on the corporate network. TLS between all
   services, even internal.

3. **Access to individual enterprise resources is granted on a per-session basis.**
   Prior to granting access, trust is evaluated for each session, not assumed
   from previous sessions.

4. **Access to resources is determined by dynamic policy.**
   Policy includes observable client identity attributes, application/service,
   and the requesting asset's security posture.

5. **The enterprise monitors and measures the integrity and security posture of all assets.**
   Continuous monitoring of asset health — patch level, EDR status, MDM
   compliance, vulnerability scan results.

6. **All resource authentication and authorization is dynamic and strictly enforced before access is allowed.**
   Continuous re-evaluation. Anomalous behavior triggers step-up authentication
   or session termination.

7. **The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve its security posture.**
   Telemetry from all sources feeds the Policy Engine to refine access decisions.

### 2.2 ZTA Logical Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE                            │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────────────────────┐    │
│  │  Policy Engine  │◄───│     Policy Administrator        │    │
│  │  (PE)           │    │     (PA)                        │    │
│  │                 │    │  [Session token management]     │    │
│  │  Trust algo:    │    │  [Agent/agentless comms]        │    │
│  │  - Score-based  │    └─────────────────────────────────┘    │
│  │  - Allow-list   │              │ Policy decision             │
│  │  - Deny-list    │              ▼                             │
│  └─────────────────┘    ┌─────────────────────────────────┐    │
│         ▲               │  Policy Enforcement Point (PEP)  │    │
│         │ Telemetry     │  [Gateway · ZTNA proxy]         │    │
└─────────┼───────────────┴──────────────┬──────────────────┘    │
          │                              │                        │
DATA PLANE│                              │ Allowed/Denied traffic │
          │                              ▼                        │
  ┌───────┴──────────┐         ┌────────────────────┐           │
  │   Subject        │         │   Enterprise        │           │
  │   (User/Device/  │────────►│   Resource          │           │
  │    Workload)     │         │   (App/Data/Service) │           │
  └──────────────────┘         └────────────────────┘           │
                                                                  │
SUPPORTING SERVICES (feed PE):                                    │
  CDM System · Threat Intel · Activity Logs · IdP · PKI · SIEM   │
└─────────────────────────────────────────────────────────────────┘
```

**Policy Engine (PE)**: The brain. Evaluates all available signals and
computes a trust score. Makes allow/deny/step-up decisions. Implemented as:
- Cloud IdP with Conditional Access (Azure AD CA, Okta, Ping)
- PAM solution for privileged sessions
- API gateway with policy engine

**Policy Administrator (PA)**: Executes PE decisions. Establishes or shuts
down communication paths. Creates session tokens, configures PEP.

**Policy Enforcement Point (PEP)**: The data plane gatekeeper. Forwards
allowed sessions to resources; drops denied sessions. Implemented as:
- ZTNA gateway (Zscaler ZPA, Cloudflare Access, Prisma Access)
- Next-gen firewall with user identity integration
- API gateway (Kong, Apigee, AWS API Gateway)
- Container service mesh (Istio, Linkerd)

### 2.3 Identity Pillar

**Device Trust:**

| Trust Level | Requirements | Controls |
|---|---|---|
| High Trust | MDM enrolled, compliant, patched, managed EDR | Full resource access |
| Medium Trust | MDM enrolled, minor compliance gap | Limited access, step-up for sensitive resources |
| Low Trust | Unmanaged, unknown device | Read-only or isolated sandbox access |
| Untrusted | Non-compliant, compromised indicators | Access denied |

Device trust signals: MDM compliance state, OS version, patch level, EDR
agent health, disk encryption status, certificate presence.

**User Trust Factors:**

- Identity verification: Primary credential (password) + MFA factor
- Location context: Known geography vs. unusual country/ASN
- Behavioral baseline: Time of day, typical resources accessed, typing cadence
- Role-based access: Least-privilege RBAC/ABAC claims in identity token
- Risk score: IdP risk engine (AAD Identity Protection, Okta ThreatInsight)

**Workload Identity:**

Modern ZTA extends identity to non-human workloads:
- **SPIFFE/SPIRE**: Standard for workload identity in Kubernetes; issues
  X.509 SVIDs (SPIFFE Verifiable Identity Documents)
- **Service accounts**: Short-lived credentials (IRSA in AWS, Workload Identity
  in GCP) replacing static keys
- **mTLS**: Mutual TLS between microservices provides workload authentication

### 2.4 Network Micro-Segmentation with BeyondCorp Model

**Traditional Perimeter vs. BeyondCorp:**

```
TRADITIONAL:
Internet → [Firewall] → Corporate Network → Resources
           Trust: Low           Trust: High

BEYONDCORP:
Internet → [Identity-Aware Proxy] → Resources
           Trust: Based on identity + device context
           Network location: Irrelevant
```

**BeyondCorp Architecture Components:**

| Component | Function |
|---|---|
| Device Inventory | Tracks all managed/unmanaged devices with trust attributes |
| User/Group Database | Source of truth for identities, roles, group memberships |
| Device Certificate Authority | Issues certificates to managed devices for device authentication |
| Access Proxy | Internet-facing gateway; enforces access control based on device cert + user identity |
| Access Control Engine | Policy decision point; evaluates claims against ACLs |
| Single Sign-On (SSO) | Federated IdP for user authentication |
| Pipeline / Trust Engine | Continuously recalculates device trust; feeds Access Control Engine |

**Micro-segmentation Implementation:**

Software-defined micro-segmentation decouples network policy from physical
infrastructure using identity-based policies:

```yaml
# Example Illumio-style policy (illustrative)
ruleset:
  name: "Database Access Policy"
  scopes:
    - label: env=production
  rules:
    - consumers:
        - label: app=webserver
      providers:
        - label: app=database
      ingress_services:
        - port: 5432
          proto: tcp
    - consumers:
        - label: role=dba
      providers:
        - label: app=database
      ingress_services:
        - port: 5432
          proto: tcp
  default_rule: deny
```

### 2.5 Microsoft Zero Trust Maturity Model

Microsoft's ZTMM defines three stages of Zero Trust maturity across six pillars:

**Pillars:** Identity · Endpoints · Applications · Data · Infrastructure · Network

| Stage | Characteristics |
|---|---|
| **Traditional** | Static policies, perimeter-based trust, manual identity management, limited telemetry |
| **Advanced** | Risk-based conditional access, integrated telemetry, automated policy enforcement, JIT/JEA for privileged access |
| **Optimal** | Continuous validation, automated threat response, ML-driven anomaly detection, comprehensive coverage across all pillars |

**Identity Pillar Example:**

| Traditional | Advanced | Optimal |
|---|---|---|
| Username + password | MFA enforced | Passwordless MFA |
| Static role assignment | Conditional Access policies | AI-driven risk scoring |
| Manual access review | Quarterly access reviews | Continuous access evaluation |
| No device trust | MDM enrollment required | Device compliance as access condition |

### 2.6 Google BeyondCorp Implementation Details

Google's production BeyondCorp deployment (described in a series of papers
from 2014–2020) provides a blueprint for ZTA implementation at scale.

**Key Implementation Choices:**

1. **Device certificates**: Every managed device receives a certificate from
   the corporate CA. The certificate is the basis for device authentication at
   the access proxy. Certificate issuance is automated via the device enrollment
   pipeline.

2. **Device inventory service**: A near-real-time database of all devices with
   attributes: ownership (corporate/BYOD), OS, patch level, disk encryption,
   screen lock. The trust tier is computed from these attributes.

3. **Access proxy (BeyondCorp Enterprise / Identity-Aware Proxy)**: All
   application traffic passes through the IAP. The IAP validates:
   - User identity via SSO cookie (OAuth 2.0)
   - Device certificate (mTLS with the access proxy)
   - Access control list (ACL) for the requested resource

4. **No VPN**: Internal resources are not accessible from the corporate
   network without authentication. The internal network is treated as hostile.
   VPN was removed entirely for most workloads.

5. **Continuous pipeline**: Device and user attributes are continuously
   re-evaluated. Trust tier changes propagate to the access proxy within
   minutes, revoking access if trust drops.

### 2.7 Practical ZTA Migration Roadmap (5 Phases)

```
PHASE 1: INVENTORY & VISIBILITY (Months 1-3)
  ├─ Discover all users, devices, applications, and data flows
  ├─ Deploy MDM (Intune / JAMF) for device visibility
  ├─ Enable SSO for all applications
  ├─ Establish identity governance baseline
  └─ Deploy SIEM/UEBA for behavioral baseline

PHASE 2: IDENTITY HARDENING (Months 3-6)
  ├─ Enforce MFA for all users (start with privileged)
  ├─ Deploy Conditional Access policies (risk-based)
  ├─ Implement JIT/JEA for privileged access (PAM)
  ├─ Migrate to federated identity (SAML/OIDC for all apps)
  └─ Begin device compliance enforcement (block non-MDM enrolled)

PHASE 3: NETWORK SEGMENTATION (Months 6-12)
  ├─ Replace VPN with ZTNA solution for remote access
  ├─ Implement micro-segmentation for critical applications
  ├─ Deploy application-aware firewall policies
  ├─ Enable DNS security and split-horizon DNS
  └─ Instrument network traffic for anomaly detection

PHASE 4: APPLICATION INTEGRATION (Months 12-18)
  ├─ Implement service mesh (mTLS) for microservices
  ├─ Integrate all applications with IdP for OIDC/SAML
  ├─ Deploy API gateway with identity-based rate limiting
  ├─ Implement secrets management (Vault) for workload identity
  └─ Enable CSPM for cloud workload posture

PHASE 5: OPTIMIZE & AUTOMATE (Months 18-24+)
  ├─ Implement SOAR playbooks for automated access revocation
  ├─ Deploy ML-driven anomaly detection (UEBA)
  ├─ Continuous access evaluation (CAE) for real-time revocation
  ├─ Instrument all access decisions for KPI reporting
  └─ Annual ZT maturity assessment and roadmap refresh
```

### 2.8 ZTA Metrics and Success Indicators

| KPI | Definition | Target |
|---|---|---|
| MFA Adoption Rate | % of users with MFA enrolled | 100% |
| Privileged Session Recording Coverage | % of privileged sessions recorded | 100% |
| Device Compliance Rate | % of managed devices meeting policy | ≥95% |
| ZTNA Coverage | % of applications accessible only via ZTNA | ≥90% |
| Lateral Movement Dwell Time | Median time for lateral movement detection | <1 hour |
| Access Review Completion Rate | % of access certifications completed on time | ≥98% |
| Micro-segmentation Coverage | % of crown-jewel workloads with deny-by-default | 100% |
| Mean Time to Revoke (MTTR) | Average time from account compromise detection to revocation | <15 minutes |

---

## 3. Network Security Architecture

### 3.1 Traditional DMZ Design (Three-Tier)

The classic three-tier DMZ separates publicly accessible services from the
internal network using two firewall layers.

```
INTERNET
    │
    ▼
┌──────────────────────────────────┐
│   EXTERNAL FIREWALL (FW-EXT)     │
│   Rules: Allow 80/443 inbound    │
│   Block all else                 │
└──────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────┐
│            DMZ ZONE              │
│   Web servers · Reverse proxies  │
│   Mail gateways · DNS (auth)     │
│   VPN concentrators              │
└──────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────┐
│   INTERNAL FIREWALL (FW-INT)     │
│   Rules: Allow specific ports    │
│   from DMZ to internal only      │
└──────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────┐
│         INTERNAL NETWORK         │
│   App servers · Databases        │
│   Active Directory · File shares │
│   Internal services              │
└──────────────────────────────────┘
```

**Design Principles:**
- DMZ hosts should not initiate connections to the internal network
- Application server tier (if separate) sits between DMZ and database tier
- Firewall rules are whitelist-based; default deny
- Management traffic uses a dedicated out-of-band management network

### 3.2 Next-Gen Segmentation: Application-Layer Firewall Zones

Modern NGFW segmentation moves beyond IP/port to application identity:

```
ZONE STRUCTURE (Palo Alto example):

  internet-untrust         │  External internet
  ─────────────────────────┤
  dmz-web                  │  Public-facing web/API
  dmz-mail                 │  Email gateway
  ─────────────────────────┤
  corp-user                │  Employee endpoints
  corp-server              │  Internal application servers
  corp-database            │  Database servers
  ─────────────────────────┤
  mgmt                     │  OOB management network
  backup                   │  Backup infrastructure
  ─────────────────────────┤
  iot-quarantine           │  IoT/SCADA isolation zone
  guest-wifi               │  Guest network (internet only)
```

**App-ID Based Policy Example:**

```
Security Policy: Allow web application traffic
Source: corp-user
Destination: corp-server
Application: salesforce-base, office365-base, confluence
Service: application-default
Action: Allow, Log
Profile: strict-antivirus + url-filtering + threat-prevention
```

### 3.3 Hub-Spoke vs. Mesh Topologies for Enterprise WAN

**Hub-Spoke (Star) Topology:**

```
     Branch A
                       Branch B ——— HUB (Data Center / SD-WAN Hub)
          /
         /
     Branch C
```

- All branch-to-branch traffic transits the hub
- Security inspection centralized at hub
- MPLS or SD-WAN overlay
- Hub is a single point of failure (mitigated by redundant hubs)
- Latency added for branch-to-branch communication

**Mesh Topology:**

```
Branch A ————— Branch B
   \               /
    \             /
     Branch C ——— Branch D
```

- Direct branch-to-branch paths
- Lower latency for branch communications
- Harder to enforce centralized security inspection
- SD-WAN with cloud security stack (SASE) enables mesh with security

**Security Implications:**

| Topology | Inspection Point | Best For |
|---|---|---|
| Hub-Spoke | Centralized at hub | Compliance-heavy environments; centralized logging |
| Mesh/SASE | Distributed (cloud PoPs) | SaaS-heavy workloads; geographically distributed users |
| Hybrid | Hub for DC + SASE for SaaS | Most large enterprises transitioning to cloud |

### 3.4 SD-WAN Security Architecture

SD-WAN overlays security policy on multi-path WAN (MPLS + internet + LTE):

```
SASE (Secure Access Service Edge) Architecture:

Branch Office          Cloud Security Stack          Cloud/SaaS
┌─────────────┐       ┌────────────────────┐       ┌──────────┐
│ SD-WAN Edge │──────►│ SWG (Proxy)        │──────►│ M365     │
│   Device    │       │ CASB               │       │ Salesforce│
│             │       │ ZTNA               │       │ AWS/Azure │
│ User/IoT    │       │ FWaaS              │       └──────────┘
└─────────────┘       │ DLP                │
                      │ Threat Prevention  │
                      └────────────────────┘
```

**SD-WAN Security Controls:**

- **Encryption**: IPsec tunnels between edge devices; key rotation automated
- **Application-aware routing**: Critical apps (VoIP) take MPLS; best-effort takes internet
- **Zone-based firewall**: NGFW policies enforced at the edge
- **Cloud breakout**: SaaS traffic breaks out locally (not backhauled to DC)
- **Centralized management**: All policy changes via controller; no manual device config

### 3.5 DNS Security Architecture

DNS is exploited for C2, data exfiltration, and lateral movement. DNS security
operates at multiple layers:

**DNS Security Architecture Stack:**

```
User/Endpoint
    │  DNS query
    ▼
DNS Forwarder (resolving)
    │  RPZ check: Block known malicious domains
    ├─ Passive DNS logging → SIEM
    │
    ▼
DNS Security Platform (Cisco Umbrella / Infoblox / Protective DNS)
    │  Category filtering (malware, C2, phishing)
    │  DGA detection (entropy analysis)
    │  DNS tunneling detection (TXT query volume, subdomain length)
    │
    ▼
Authoritative DNS (signed zones)
    │  DNSSEC validation
    ▼
Root / TLD Resolvers
```

**DNS Security Controls:**

| Control | Description | Tool Examples |
|---|---|---|
| RPZ (Response Policy Zones) | Block/redirect malicious domain resolutions | BIND RPZ, Infoblox NIOS |
| DNSSEC | Cryptographic signing of DNS zones; validates authenticity | Cloudflare, AWS Route 53 |
| DNS over HTTPS (DoH) | Encrypts DNS queries to prevent interception | Cloudflare 1.1.1.1, NextDNS |
| DNS over TLS (DoT) | TLS channel for DNS queries (port 853) | Stubby, systemd-resolved |
| Passive DNS | Log all DNS queries for threat hunting | Zeek, Suricata, Umbrella |
| DGA Detection | Identify algorithmically generated domain queries | UEBA, Cisco Umbrella |
| Split-horizon DNS | Internal names resolve differently internally vs. externally | Any internal DNS server |

### 3.6 BGP Security (RPKI, Route Filtering, Peer Authentication)

**BGP Route Hijacking Threat:**
- Attacker announces more specific prefix to divert traffic
- Route leaks expose internal routing topology
- BGP session hijacking allows injecting malicious routes

**RPKI (Resource Public Key Infrastructure):**

```
RPKI Certificate Hierarchy:
  IANA Root CA
    └─ RIR CA (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
         └─ LIR CA (ISP)
              └─ End-entity CA (ASN holder)
                   └─ Route Origin Authorization (ROA)
                        Origin AS: 65001
                        Prefix: 203.0.113.0/24
                        Max length: /24
```

**BGP Security Controls:**

| Control | Description | Coverage |
|---|---|---|
| RPKI + ROV | Validate route origin against ROAs; drop invalid routes | Prevents origin hijacking |
| BGPsec | Cryptographic path validation (AS-PATH signing) | Prevents path manipulation |
| BGPTTL Security / GTSM | Require TTL=255 for eBGP; drops spoofed packets | Prevents remote injection |
| MD5 Session Authentication | TCP MD5 signature on BGP sessions | Prevents session hijacking |
| Prefix Filtering (IRR) | Filter prefixes against Internet Routing Registry | Reduces leak exposure |
| Max-prefix limits | Shut session if prefix count exceeds threshold | Limits leak impact |
| RTBH (Remote Triggered Black Hole) | Null-route attacked prefix upstream | DDoS mitigation |

### 3.7 DDoS Protection Architecture

**DDoS Protection Tiers:**

```
TIER 1: UPSTREAM / TRANSIT
  ISP scrubbing or anycast CDN (Cloudflare, Akamai, Fastly)
  Absorbs volumetric attacks (Tbps-scale)
  BGP-based diversion to scrubbing centers
  ↓
TIER 2: CLOUD / CDN LAYER
  Anycast distribution across 200+ PoPs
  L3/L4 filtering, rate limiting, SYN proxy
  WAF for L7 attacks (HTTP floods, Slowloris)
  ↓
TIER 3: NETWORK EDGE
  On-premise or cloud-based scrubbing appliance
  Netflow/sFlow-based detection
  Auto-mitigation rules (RTBH, FlowSpec)
  ↓
TIER 4: APPLICATION LAYER
  Rate limiting at load balancer / API gateway
  CAPTCHA / JS challenge for human verification
  Adaptive resource limits (connection table, bandwidth)
```

**Attack Type to Mitigation Mapping:**

| Attack Type | Example | Primary Mitigation |
|---|---|---|
| UDP Flood | DNS amplification, NTP reflection | Upstream scrubbing, BCP38 filtering |
| SYN Flood | SYN-ACK exhaustion | SYN cookies at edge |
| HTTP Flood | L7 volumetric GET flood | Rate limiting + CAPTCHA + WAF |
| Slow-rate (Slowloris) | Keep connections open with partial requests | Connection timeout tuning, reverse proxy |
| Reflection/Amplification | DNS/SSDP/Memcached | Source validation (BCP38), upstream filter |
| Application-layer (CC) | Credential stuffing, shopping cart abuse | Bot management, behavioral analysis |

### 3.8 Network Access Control (NAC): 802.1X, RADIUS, MAB

**802.1X Port-Based NAC Architecture:**

```
Supplicant          Authenticator          Authentication Server
(Endpoint)         (Switch/AP)             (RADIUS / NPS)
    │                    │                        │
    │──EAPOL Start───────►│                        │
    │◄─EAP-Request/Ident─│                        │
    │──EAP-Response/Ident►│                        │
    │                    │──RADIUS Access-Request─►│
    │                    │                         │ Certificate/Cred check
    │◄─EAP-Request/TLS───│◄─RADIUS Challenge───────│
    │──EAP-Response/TLS──►│──RADIUS Response───────►│
    │                    │◄─RADIUS Access-Accept───│
    │◄─EAP-Success────────│                        │
    │                    │ Port authorized          │
    │◄══════════════════ Network Access ═══════════►│
```

**NAC Enforcement Modes:**

| Mode | Description | Use Case |
|---|---|---|
| 802.1X EAP-TLS | Certificate-based; strongest auth | Managed workstations |
| 802.1X PEAP-MSCHAPv2 | Username/password over TLS tunnel | Older environments |
| MAB (MAC Auth Bypass) | Authenticate by MAC address | IoT, printers, cameras |
| Guest VLAN | Unauthenticated devices get internet-only VLAN | Guest/BYOD |
| Restricted VLAN | Failed auth gets remediation VLAN | Non-compliant devices |

**RADIUS Infrastructure:**

```
NAC Controller (Cisco ISE / Aruba ClearPass / FreeRADIUS)
  ├─ Receives RADIUS Access-Request from switches/APs
  ├─ Evaluates policy against:
  │    ├─ Active Directory (user/computer accounts)
  │    ├─ Certificate validation (OCSP/CRL)
  │    ├─ MDM compliance state (Intune integration)
  │    └─ Device profiling (DHCP fingerprint, OUI)
  └─ Returns RADIUS Access-Accept with:
       ├─ VLAN assignment (dynamic VLAN)
       ├─ ACL name (downloadable ACL)
       └─ dACL (downloadable ACL)
```

### 3.9 Firewall Rule Base Architecture Best Practices

**Rule Order Principles (Top-Down Evaluation):**

```
1. MANAGEMENT ACCESS RULES (first)
   └─ Admin access from OOB management network only

2. ESTABLISHED/RELATED TRAFFIC
   └─ Stateful inspection (auto-managed by stateful FW)

3. DENY KNOWN-BAD (early in rule base)
   └─ Known attacker IPs, Tor exit nodes, threat intel feeds

4. APPLICATION-SPECIFIC ALLOW RULES
   └─ Most specific rules first: host-to-host
   └─ Then: subnet-to-subnet
   └─ Then: zone-to-zone

5. ZONE-BASED DEFAULTS
   └─ Inter-zone allow/deny based on zone model

6. DENY ALL (last rule, always)
   └─ Catch-all deny with logging
```

**Rule Base Hygiene:**

| Practice | Description |
|---|---|
| Named objects | Use named host/network objects; never raw IPs in rules |
| Rule descriptions | Every rule has a business justification and ticket reference |
| Expiry dates | Temporary rules have an automated expiry |
| Regular review | Quarterly review; remove unused rules (hitcount = 0 > 90 days) |
| Shadowed rule detection | Automated detection of rules fully shadowed by earlier rules |
| Logging | Log all deny rules; log selectively for allow rules (PII considerations) |
| Change management | All rule changes via ticketed change process; peer review |

---

## 4. Cloud Security Architecture

### 4.1 AWS Well-Architected Security Pillar

The AWS Well-Architected Framework Security Pillar defines six best practice areas:

**Best Practice Area 1: Security Foundations**
- Separate workloads using AWS accounts (account = security boundary)
- Enable AWS Organizations for centralized governance
- Deploy AWS Control Tower for automated account vending
- Define and enforce SCPs (Service Control Policies)
- Enable CloudTrail in all regions; centralize to security account

**Best Practice Area 2: Identity and Access Management**
- Use IAM roles; never use long-term IAM user access keys for workloads
- Apply least privilege; regularly review and remove unused permissions
- Use AWS IAM Identity Center (SSO) for human access
- Enable MFA for root and all IAM users
- Use permission boundaries to delegate IAM administration safely

**Best Practice Area 3: Detection**
- Enable AWS Config for compliance evaluation
- Deploy GuardDuty in all accounts/regions
- Enable SecurityHub for aggregated findings
- Stream findings to centralized SIEM
- Enable VPC Flow Logs, DNS query logs, S3 access logs

**Best Practice Area 4: Infrastructure Protection**
- Use security groups as stateful host-based firewalls
- Deploy NACLs for subnet-level stateless filtering
- Use WAF for internet-facing applications
- Enable AWS Shield Advanced for DDoS protection
- Restrict SSH/RDP: use SSM Session Manager; no inbound 22/3389

**Best Practice Area 5: Data Protection**
- Classify data and apply controls based on sensitivity
- Encrypt all data at rest (KMS-managed keys); enforce via SCPs
- Enable S3 Block Public Access at organization level
- Use TLS for all in-transit data
- Deploy Macie for sensitive data discovery in S3

**Best Practice Area 6: Incident Response**
- Pre-stage IR tooling in accounts (forensic subnets, IR IAM roles)
- Practice incident response via game days
- Automate containment (Lambda-based isolation of compromised instances)
- Retain CloudTrail logs in immutable S3 bucket (Object Lock)
- Document IR runbooks for common AWS-specific scenarios

### 4.2 Multi-Account Strategy: Control Tower, Landing Zones, SCPs

**AWS Organization Structure:**

```
Management Account (root)
  ├─ Security OU
  │    ├─ Log Archive Account    (centralized CloudTrail/Config logs)
  │    └─ Security Tooling Account (GuardDuty master, SecurityHub master)
  │
  ├─ Infrastructure OU
  │    ├─ Network Account        (Transit Gateway, Direct Connect)
  │    └─ Shared Services Account (AD, DNS, patch management)
  │
  ├─ Workloads OU
  │    ├─ Production OU
  │    │    ├─ Prod Account A
  │    │    └─ Prod Account B
  │    └─ Non-Production OU
  │         ├─ Dev Account A
  │         └─ Staging Account A
  │
  └─ Sandbox OU
       └─ Individual sandbox accounts (developers)
```

**Key SCPs (Service Control Policies):**

```json
// Deny disabling GuardDuty
{
  "Sid": "DenyDisableGuardDuty",
  "Effect": "Deny",
  "Action": [
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
    "guardduty:StopMonitoringMembers",
    "guardduty:UpdateDetector"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"
    }
  }
}

// Deny creation of IAM users with console access
{
  "Sid": "DenyIAMUserCreation",
  "Effect": "Deny",
  "Action": "iam:CreateLoginProfile",
  "Resource": "*"
}

// Require encryption for S3
{
  "Sid": "DenyS3UnencryptedPutObject",
  "Effect": "Deny",
  "Action": "s3:PutObject",
  "Resource": "*",
  "Condition": {
    "StringNotEqualsIfExists": {
      "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
    }
  }
}
```

### 4.3 Azure Landing Zone Architecture

**Azure Management Group Hierarchy:**

```
Tenant Root Group
  ├─ Platform MG
  │    ├─ Management MG (Log Analytics, Automation, Defender)
  │    ├─ Connectivity MG (Hub vNet, ExpressRoute, Firewall)
  │    └─ Identity MG (AD DS domain controllers)
  │
  ├─ Landing Zones MG
  │    ├─ Corp MG (corporate workloads — connected to hub)
  │    │    ├─ Subscription: App-Prod-001
  │    │    └─ Subscription: App-Dev-001
  │    └─ Online MG (internet-facing workloads)
  │         └─ Subscription: Web-Prod-001
  │
  └─ Sandbox MG
       └─ Subscription: Dev-Sandbox-001
```

**Azure Security Baseline (per subscription):**
- Microsoft Defender for Cloud enabled (Standard tier)
- Azure Policy initiatives assigned (CIS, NIST 800-53, ISO 27001)
- Diagnostic settings enabled for all resource types → Log Analytics
- Azure Firewall deployed in hub vNet
- DDoS Standard enabled for production vNets
- Private Endpoints for PaaS services (Storage, SQL, Key Vault)
- Azure AD Conditional Access policies applied

### 4.4 GCP Resource Hierarchy Security Controls

```
Organization
  ├─ Folders (Business Unit / Environment)
  │    ├─ Production
  │    │    └─ Projects (dev units)
  │    └─ Development
  │         └─ Projects
  └─ Projects (direct)
```

**GCP Security Controls by Level:**

| Level | Controls Applied |
|---|---|
| Organization | Org policies (disable public IPs, require OS Login, restrict resource locations) |
| Folder | IAM role bindings, VPC Service Controls perimeters |
| Project | Service account management, API enablement, VPC, GKE config |
| Resource | IAM conditions, labels for DSPM, encryption keys |

**VPC Service Controls (data exfiltration prevention):**
```
Service Perimeter:
  Projects inside perimeter: [prod-data, prod-analytics]
  Protected services: bigquery.googleapis.com, storage.googleapis.com
  Access levels: corporate-network (IP range), managed-device (device policy)
  Ingress/Egress rules: explicit allowlist for cross-perimeter flows
```

### 4.5 Cloud Network Security: VPC Design, Transit Gateway, PrivateLink

**AWS VPC Security Architecture:**

```
VPC (10.0.0.0/16)
  ├─ Public Subnets (10.0.0.0/24, 10.0.1.0/24)  — AZ-a, AZ-b
  │    ├─ NAT Gateway (for outbound from private subnets)
  │    ├─ ALB (internet-facing)
  │    └─ Bastion (deprecated; use SSM Session Manager)
  │
  ├─ Private App Subnets (10.0.10.0/24, 10.0.11.0/24)
  │    ├─ EC2 Auto Scaling Group (application tier)
  │    └─ ECS Fargate tasks
  │
  └─ Private DB Subnets (10.0.20.0/24, 10.0.21.0/24)
       └─ RDS Multi-AZ (isolated subnet, no internet route)
```

**Transit Gateway (TGW) Hub-and-Spoke:**

```
Transit Gateway
  ├─ VPC Attachment: Network-Account (Firewall VPC)
  ├─ VPC Attachment: Prod-App-Account
  ├─ VPC Attachment: Prod-Data-Account
  ├─ VPN Attachment: On-premises (IPsec)
  └─ Direct Connect Gateway Attachment

Route Tables:
  Spoke VPCs → Default route 0.0.0.0/0 via TGW → Firewall VPC (inspection)
  Firewall VPC → Routes distributed to spokes after inspection
```

**AWS PrivateLink:**
- Exposes service in provider VPC via Network Load Balancer
- Consumer VPC creates VPC Endpoint; traffic stays on AWS backbone
- No VPC peering required; no route propagation; no firewall holes needed
- Eliminates data exfiltration risk via internet; prevents SSRF to metadata

### 4.6 CSPM and CWPP Placement in Architecture

```
CSPM (Cloud Security Posture Management):
  ├─ Reads cloud provider APIs (no agent required)
  ├─ Evaluates resource configurations against security benchmarks
  ├─ Detects misconfigurations: public S3, open SGs, unencrypted volumes
  ├─ Tools: Wiz, Orca, Prisma Cloud, AWS SecurityHub, Azure Defender for Cloud
  └─ Placement: Management/Security account; API-level access to all accounts

CWPP (Cloud Workload Protection Platform):
  ├─ Agent or eBPF-based; deployed on VMs, containers, serverless
  ├─ Runtime threat detection: process execution, network connections
  ├─ Vulnerability scanning: OS and application packages
  ├─ Tools: CrowdStrike Falcon Cloud, Sysdig Secure, Aqua, Lacework
  └─ Placement: All compute workloads via agent or DaemonSet

CNAPP = CSPM + CWPP + CIEM (Cloud Infrastructure Entitlement Management)
  └─ Unified view: posture + runtime + identity risk
```

### 4.7 Cloud-Native Security Services Mapping

| Security Domain | AWS | Azure | GCP |
|---|---|---|---|
| Threat detection | GuardDuty | Defender for Cloud | Chronicle / Security Command Center |
| CSPM / posture | Security Hub + Config | Defender CSPM | Security Command Center |
| Vulnerability mgmt | Inspector | Defender for Servers | Security Command Center |
| Sensitive data discovery | Macie | Purview | DLP API / Sensitive Data Protection |
| Identity risk | IAM Access Analyzer | Entra ID Protection | Cloud IAM recommender |
| WAF | WAF + Shield | Front Door WAF | Cloud Armor |
| Secrets management | Secrets Manager / SSM | Key Vault | Secret Manager |
| SIEM integration | Security Hub → SIEM | Sentinel | Chronicle SIEM |
| CASB | N/A (partner) | Defender for Cloud Apps | N/A (partner) |

### 4.8 Hybrid Cloud Connectivity Security

| Connectivity Type | Protocol | Security Controls | Use Case |
|---|---|---|---|
| AWS Direct Connect | Dedicated fiber; Layer 2 | MACsec (link encryption), BGP MD5, Private VIF | High-bandwidth; low-latency DC-to-cloud |
| Azure ExpressRoute | Private peering | MACsec, BGP MD5, route filters | Enterprise DC to Azure |
| GCP Cloud Interconnect | Dedicated/Partner | MACsec, BGP MD5 | GCP connectivity |
| Site-to-Site VPN | IPsec IKEv2 | AES-256-GCM, Perfect Forward Secrecy | Backup path; lower cost |
| SD-WAN overlay | IPsec over internet | Zero-trust segmentation, SASE | Branch-to-cloud |

---

## 5. Application Security Architecture

### 5.1 Secure SDLC Integration Points

```
REQUIREMENTS
  └─ Security requirements derived from threat model
  └─ Abuse cases alongside use cases
  └─ Privacy impact assessment
       │
       ▼
DESIGN / THREAT MODELING
  └─ STRIDE/PASTA threat model
  └─ Data Flow Diagram review
  └─ Architecture review (SARB)
  └─ Security ADRs documented
       │
       ▼
DEVELOPMENT
  └─ SAST: Static analysis in IDE (SonarLint) + CI gate (Semgrep, Checkmarx)
  └─ SCA: Dependency scanning (Snyk, Dependabot, OWASP Dependency-Check)
  └─ Secrets detection: Pre-commit hooks (git-secrets, gitleaks, Trufflehog)
  └─ IaC scanning: Checkov, tfsec, KICS for Terraform/CF/Kubernetes
       │
       ▼
BUILD / CI
  └─ Container image scanning (Trivy, Grype, Anchore)
  └─ SBOM generation (Syft, Cyclone DX)
  └─ SAST quality gate (fail build if critical findings)
  └─ License compliance check
       │
       ▼
TEST
  └─ DAST: ZAP/Burp automated scan against staging environment
  └─ IAST: Runtime instrumentation during integration tests
  └─ API security testing (OWASP API Top 10 checks)
  └─ Penetration test (pre-release for major versions)
       │
       ▼
DEPLOY
  └─ Deployment approval gate (signed artifacts)
  └─ Infrastructure hardening validated (CIS benchmarks)
  └─ WAF rules updated for new endpoints
  └─ Feature flags for gradual rollout
       │
       ▼
OPERATE
  └─ RASP: Runtime application self-protection
  └─ WAF: Block OWASP Top 10 attacks
  └─ Anomaly detection: UEBA + API gateway metrics
  └─ Vulnerability management: Re-scan on new CVEs
  └─ Bug bounty / responsible disclosure program
```

### 5.2 API Gateway Security Patterns

**API Gateway Security Architecture:**

```
Client
  │
  ▼
API Gateway (Kong / AWS API GW / Apigee)
  ├─ TLS Termination (mutual TLS for service-to-service)
  ├─ Authentication:
  │    ├─ JWT validation (verify signature, expiry, claims)
  │    ├─ API key management
  │    └─ OAuth 2.0 token introspection
  ├─ Authorization:
  │    ├─ Scope-based access (OAuth scopes)
  │    └─ OPA policy evaluation
  ├─ Rate Limiting:
  │    ├─ Per-consumer rate limits
  │    ├─ Global rate limits per endpoint
  │    └─ Token bucket algorithm
  ├─ Input Validation:
  │    ├─ Request size limits
  │    ├─ Schema validation (OpenAPI spec)
  │    └─ Content-type enforcement
  ├─ WAF Integration (OWASP Top 10 rules)
  └─ Observability:
       ├─ Access logs → SIEM
       ├─ Metrics → APM (Datadog/Dynatrace)
       └─ Distributed tracing (OpenTelemetry)
```

**mTLS Configuration (Nginx example):**

```nginx
server {
    listen 443 ssl;
    ssl_certificate      /etc/ssl/server.crt;
    ssl_certificate_key  /etc/ssl/server.key;
    ssl_client_certificate /etc/ssl/ca.crt;
    ssl_verify_client    on;
    ssl_verify_depth     2;

    # Pass client cert info to upstream
    proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header X-Client-DN   $ssl_client_s_dn;

    location /api/ {
        proxy_pass http://backend_service;
    }
}
```

### 5.3 Service Mesh Security (Istio/Envoy)

**Istio Security Architecture:**

```
                   Istiod (Control Plane)
                   ├─ Citadel: Certificate authority
                   ├─ Galley: Config validation
                   └─ Pilot: Service discovery + policy distribution
                        │
                        │ xDS API (Envoy config)
                        ▼
┌──────────────┐    ┌─────────────────────────────────┐    ┌──────────────┐
│  Service A   │    │  Envoy Sidecar (Service A)       │    │  Service B   │
│  (port 8080) │◄──►│  mTLS enforcement                │◄──►│  Envoy Sidecar│
│              │    │  Authorization policy            │    │              │
└──────────────┘    │  Traffic policy                  │    └──────────────┘
                    └─────────────────────────────────┘
```

**Istio mTLS Policy (PeerAuthentication):**

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # All traffic must use mTLS; reject plaintext
---
# Per-workload exception
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: legacy-service-exception
  namespace: production
spec:
  selector:
    matchLabels:
      app: legacy-service
  mtls:
    mode: PERMISSIVE  # Accept both mTLS and plaintext during migration
```

**Istio Authorization Policy (RBAC):**

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: database-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/app-service-account"]
    to:
    - operation:
        ports: ["5432"]
  # Implicit deny for everything not matched
```

**Istio Traffic Policy (Circuit Breaker):**

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: payment-service
spec:
  host: payment-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 100
        http2MaxRequests: 1000
    outlierDetection:
      consecutiveGatewayErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

### 5.4 Microservices Security Patterns

**Secrets Injection Pattern:**

```
Bad practice:
  ENV VAR in Dockerfile / K8s manifest → visible in image layer, K8s etcd

Good practice (Vault Agent Injector):
  K8s Pod spec annotation → Vault Agent sidecar injects secrets as:
    - Environment variables (in-memory, never on disk)
    - Files in tmpfs volume (memory-only, not persisted)
  Secret rotation → Vault signals agent → secret updated without pod restart
```

**Vault Agent Annotation Example:**

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "app-payment-role"
  vault.hashicorp.com/agent-inject-secret-db-creds: "secret/data/prod/db"
  vault.hashicorp.com/agent-inject-template-db-creds: |
    {{- with secret "secret/data/prod/db" -}}
    export DB_USERNAME="{{ .Data.data.username }}"
    export DB_PASSWORD="{{ .Data.data.password }}"
    {{- end }}
```

**Sidecar Proxy Pattern:**

All service-to-service traffic routes through a sidecar proxy (Envoy):
- Encryption: mTLS between all services without application code changes
- Authentication: Service identity via X.509 (SPIFFE SVIDs)
- Authorization: Policy enforced at proxy, not in application code
- Observability: Automatic distributed tracing and metrics

### 5.5 Authentication Architecture

**Federation Architecture:**

```
User Browser
    │ Initiates SSO request
    ▼
Service Provider (SP) / Relying Party (RP)
    │ Redirects to IdP
    ▼
Identity Provider (IdP) [Okta / Azure AD / PingFederate]
    │ Authenticates user (MFA)
    │ Issues SAML Assertion or OIDC ID Token
    ▼
Service Provider
    │ Validates assertion/token
    │ Maps to local identity
    └─ Grants access
```

**OIDC Authorization Code + PKCE Flow:**

```
1. User clicks "Login"
2. App generates code_verifier (random, 43-128 chars)
   code_challenge = BASE64URL(SHA256(code_verifier))
3. Redirect to Authorization Endpoint:
   GET /authorize?
     response_type=code
     &client_id=CLIENT_ID
     &redirect_uri=https://app/callback
     &scope=openid email profile
     &code_challenge=CODE_CHALLENGE
     &code_challenge_method=S256
     &state=RANDOM_STATE
4. User authenticates at IdP
5. IdP redirects to callback with authorization code
6. App exchanges code for tokens:
   POST /token
     grant_type=authorization_code
     &code=AUTH_CODE
     &redirect_uri=https://app/callback
     &client_id=CLIENT_ID
     &code_verifier=CODE_VERIFIER
7. IdP validates code_verifier against stored code_challenge
8. IdP returns: access_token, id_token, refresh_token
```

**SAML Assertion Structure:**

```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_abc123" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature><!-- RSA-SHA256 signature --></ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      user@example.com
    </saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="T-5min" NotOnOrAfter="T+1hour">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="groups">
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### 5.6 OAuth 2.0 Architecture Patterns

**Grant Type Selection Matrix:**

| Use Case | Grant Type | Reasoning |
|---|---|---|
| Web app (browser + server) | Authorization Code + PKCE | Secure code exchange; PKCE prevents interception |
| Single-page app (SPA) | Authorization Code + PKCE | No client secret in browser; PKCE for security |
| Mobile app | Authorization Code + PKCE | Same as SPA; use system browser for auth |
| Service-to-service (API) | Client Credentials | No user context; machine identity |
| Legacy / CLI (avoid if possible) | Device Authorization | For input-constrained devices |
| Deprecated — DO NOT USE | Implicit | Token exposed in URL fragment; no PKCE support |
| Deprecated — DO NOT USE | Resource Owner Password | Credentials sent to app; bypasses IdP security |

### 5.7 Secrets Management Architecture (Vault HA)

**HashiCorp Vault HA Architecture:**

```
                    Load Balancer (Active node routing)
                          │
              ┌───────────┴──────────┐
              ▼                      ▼
         ┌─────────┐           ┌─────────┐
         │ Vault 1 │           │ Vault 2 │
         │ ACTIVE  │◄──Raft───►│ STANDBY │
         └─────────┘           └─────────┘
              │                      │
              └──────────┬───────────┘
                         │
                    ┌─────────┐
                    │ Vault 3 │
                    │ STANDBY │
                    └─────────┘
                         │
                         ▼
               Storage Backend (Raft integrated / Consul)
                         │
                         ▼
                  HSM (Auto-unseal)
              AWS KMS / Azure Key Vault / CloudHSM
```

**Vault Transit Encryption (Encryption-as-a-Service):**

```bash
# Application encrypts data using Vault's transit engine
# Application never handles the encryption key

# Enable transit engine
vault secrets enable transit

# Create encryption key
vault write -f transit/keys/payment-data type=aes256-gcm96

# Encrypt data
curl -X POST https://vault.example.com/v1/transit/encrypt/payment-data   -H "X-Vault-Token: $VAULT_TOKEN"   -d '{"plaintext": "BASE64(4111111111111111)"}'
# Returns: {"ciphertext": "vault:v1:abc123..."}

# Application stores ciphertext; Vault holds the key
# Decryption requires valid Vault token with decrypt policy
```

### 5.8 Container Security Architecture

**Admission Controller Stack:**

```
kubectl apply / CI/CD Pipeline
        │
        ▼
Kubernetes API Server
        │
        ▼
┌────────────────────────────────────────────────────┐
│              Admission Controllers                  │
│                                                     │
│  1. Validating Admission Webhooks:                  │
│     ├─ OPA/Gatekeeper: Policy enforcement           │
│     │    └─ No privileged containers                │
│     │    └─ No :latest image tags                   │
│     │    └─ Require resource limits                 │
│     │    └─ Require non-root user                   │
│     ├─ Kyverno: Policy as YAML                      │
│     └─ Falco (runtime): Behavioral anomaly          │
│                                                     │
│  2. Mutating Admission Webhooks:                    │
│     ├─ Vault Agent Injector: Inject sidecar         │
│     ├─ Istio: Inject Envoy sidecar                  │
│     └─ Image tag mutation: latest → digest          │
└────────────────────────────────────────────────────┘
        │
        ▼
Scheduled to Node (if policies pass)
```

**OPA Gatekeeper Policy (No Privileged Containers):**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoPrivilegedContainers
metadata:
  name: no-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8snoprivilegedcontainers
spec:
  crd:
    spec:
      names:
        kind: K8sNoPrivilegedContainers
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snoprivilegedcontainers
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Container %v is privileged", [container.name])
        }
```

---

## 6. Data Security Architecture

### 6.1 Data Classification Taxonomy

**Four-Tier Classification Model:**

| Classification | Description | Examples | Controls |
|---|---|---|---|
| **Public** | Intentionally public; no harm if disclosed | Marketing materials, public website content | No special controls |
| **Internal** | Not public but not sensitive; low harm if leaked | Internal memos, org charts | Basic access control, no encryption at rest required |
| **Confidential** | Sensitive business data; significant harm if disclosed | Customer PII, financial data, source code, M&A plans | Encryption at rest and in transit, DLP, access logging, NDA |
| **Restricted** | Highly sensitive; severe harm if disclosed | PHI, payment card data, government classified, trade secrets | Encryption (HSM-managed keys), strict access (need-to-know), audit logging, DLP, IRM |

**Classification Labels in Practice:**

```
Document header: [RESTRICTED] or [CONFIDENTIAL - DO NOT FORWARD]
Email classification: Banner + sensitivity label (Microsoft Purview / Titus)
Database column: Annotated with sensitivity label → feeds DLP policy
S3 object: Tag key=classification, value=restricted
```

### 6.2 Data Flow Diagramming (DFD) for Security Analysis

**DFD Elements:**

```
External Entity (rectangle): Originates or terminates data (users, systems)
Process (circle):             Transforms data (application components)
Data Store (parallel lines):  Persists data (databases, files, queues)
Data Flow (arrow):            Movement of data between elements
Trust Boundary (dashed line): Where data crosses a security boundary
```

**Example DFD (Payment Processing):**

```
[Customer Browser]──HTTPS──►(Web App)──SQL──►‖ Orders DB ‖
                              │                     │
                    Trust     │ API call             │ Query
                   Boundary   │                     │
- - - - - - - - - - - - - - -│- - - - - - - - - - -│- - - -
                              ▼                     ▼
                         (Payment Service)──►‖ Vault (PCI) ‖
                              │
                              ▼
                        [Card Network]
                          External
```

Security analysis at trust boundaries:
- Authentication: Is the caller authenticated at the boundary?
- Authorization: Is the caller authorized to cross the boundary?
- Encryption: Is data encrypted in transit across the boundary?
- Logging: Is traffic at the boundary logged?
- Input validation: Is data validated before processing?

### 6.3 Encryption Architecture

**Encryption at Rest:**

| Tier | Mechanism | Key Management |
|---|---|---|
| Database | Transparent Data Encryption (TDE) | DBMS-managed or external KMS |
| Block storage | AES-256-XTS full disk encryption | OS-managed BitLocker/LUKS or HSM |
| Object storage | Server-Side Encryption (SSE) | SSE-S3, SSE-KMS, SSE-C (customer key) |
| Backups | AES-256 with separate backup key | Backup solution key management |
| File shares | EFFS (Windows) / eCryptfs (Linux) | AD-integrated or GPG |

**Encryption in Transit:**

| Connection Type | Protocol | Minimum Version | Cipher Suites |
|---|---|---|---|
| Web applications | TLS | TLS 1.2 (prefer 1.3) | ECDHE-RSA-AES256-GCM-SHA384 |
| API-to-API | mTLS | TLS 1.2 | ECDHE-ECDSA-AES256-GCM-SHA384 |
| Database connections | TLS | TLS 1.2 | Per database driver |
| Email (MTA-to-MTA) | STARTTLS + MTA-STS | TLS 1.2 | ECDHE ciphers |
| VPN tunnels | IPsec IKEv2 | — | AES-256-GCM, SHA-384, DH group 20+ |

**Encryption in Use (Emerging):**

| Technique | Description | Use Case |
|---|---|---|
| Homomorphic Encryption | Compute on encrypted data without decrypting | Cloud-processed sensitive analytics |
| Secure Multi-party Computation | Compute across parties without revealing inputs | Cross-org data collaboration |
| Confidential Computing | Hardware-isolated execution (Intel SGX, AMD SEV) | Trusted execution environment for secrets processing |
| Tokenization | Replace sensitive value with non-reversible token | PCI DSS card number storage |

### 6.4 Key Management Hierarchy (HSM → KEK → DEK)

```
HARDWARE SECURITY MODULE (HSM)
  └─ Root of trust; keys never exported in plaintext
  └─ FIPS 140-2 Level 3 (on-prem HSM cluster) or
     FIPS 140-2 Level 2 (cloud HSM: AWS CloudHSM, Azure Dedicated HSM)
       │
       ▼ Generates and protects
KEY ENCRYPTION KEY (KEK)
  └─ Encrypts/decrypts DEKs
  └─ Changes infrequently (annual rotation)
  └─ Stored in HSM or KMS (AWS KMS CMK, Azure Key Vault key)
       │
       ▼ Wraps
DATA ENCRYPTION KEY (DEK)
  └─ Directly encrypts data
  └─ Short-lived; rotated frequently (daily, per-record, per-object)
  └─ Stored alongside encrypted data (in wrapped form)
  └─ Unwrapped by KEK only when needed for decryption
```

**Envelope Encryption (AWS KMS Pattern):**

```python
# 1. Request data key from KMS
response = kms.generate_data_key(
    KeyId='arn:aws:kms:us-east-1:123456789:key/mrk-abc123',
    KeySpec='AES_256'
)
plaintext_key = response['Plaintext']      # Use for encryption, then destroy
encrypted_key = response['CiphertextBlob'] # Store alongside encrypted data

# 2. Encrypt data with plaintext DEK (AES-256-GCM)
ciphertext = aes_256_gcm_encrypt(plaintext_data, plaintext_key)
del plaintext_key  # Never persist plaintext key

# 3. Store: ciphertext + encrypted_key (together)
store(ciphertext, encrypted_key)

# 4. Decrypt: KMS unwraps DEK, then DEK decrypts data
plaintext_key = kms.decrypt(CiphertextBlob=encrypted_key)['Plaintext']
plaintext_data = aes_256_gcm_decrypt(ciphertext, plaintext_key)
```

### 6.5 DLP Architecture

**DLP Deployment Points:**

```
NETWORK DLP
  ├─ Inline: Proxy or NGFW intercepts outbound traffic
  │    ├─ Email: MTA-level inspection (SMTP)
  │    ├─ Web: Proxy inspection of HTTP/HTTPS (TLS inspection)
  │    └─ FTP/cloud sync protocols
  └─ SPAN/tap: Passive monitoring (detection only, no blocking)

ENDPOINT DLP
  ├─ Agent on endpoint (Symantec DLP, Forcepoint, Microsoft Purview DLP)
  ├─ Monitors: clipboard, print, removable media, screen capture, app behavior
  └─ Controls: Block copy to USB; block printing; require encryption for email

CLOUD DLP
  ├─ CASB integration: Inspect files uploaded to cloud storage
  ├─ API-based: Scan existing cloud data (Google DLP API, Macie)
  └─ Inline CASB: Real-time inspection of cloud app traffic
```

**DLP Policy Design:**

```
Policy: Detect and block PII in outbound email

Data identifiers:
  ├─ Regex: SSN (xxx-xx-xxxx), CCN (16-digit Luhn), PHI keywords
  ├─ ML model: PII entity recognition
  └─ Fingerprint: Known sensitive document fingerprints

Conditions:
  ├─ Recipient domain not in approved list
  ├─ Count: ≥5 SSNs in single email
  └─ Context: User is not in HR or legal group

Actions:
  ├─ Block with quarantine
  ├─ Notify user with policy justification
  ├─ Alert DLP team (high-severity incident)
  └─ Log for compliance audit trail
```

### 6.6 Database Activity Monitoring (DAM) Placement

```
                     Network tap / SPAN
                           │
┌──────────────────────────▼──────────────────────────┐
│                  DAM Sensor                          │
│  (Imperva SecureSphere / IBM Guardium / McAfee DAM)  │
│   ├─ Captures all SQL/NoSQL activity                 │
│   ├─ Baselines normal query patterns                 │
│   ├─ Detects: SQL injection, bulk exports,           │
│   │    privilege escalation, unusual hours access    │
│   └─ Blocks (in-line) or alerts (out-of-band)        │
└──────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   Oracle DB          MySQL/RDS          MongoDB Atlas
  (prod-finance)    (prod-webapp)       (prod-analytics)
```

DAM vs. native DB auditing: DAM is transparent to DBAs; cannot be disabled
by a rogue DBA. Native DB auditing (Oracle Unified Auditing, SQL Server Audit)
is easier to disable by someone with DBA rights.

### 6.7 Data Masking and Tokenization Patterns

**Static Data Masking (SDM):**
- One-time transformation of production data for non-production environments
- Replaces sensitive values with realistic but fictional data
- Non-reversible (for non-prod use cases)
- Tools: Informatica IDQ, Delphix, IBM Optim

**Dynamic Data Masking (DDM):**
- Masks data at query time based on user role
- Original data unchanged in database
- DBA sees full PAN; customer service rep sees "****-****-****-4242"
- Tools: Satori, BigID DDM, SQL Server DDM, Oracle DDM

**Tokenization:**
- Replaces sensitive value with a non-sensitive placeholder (token)
- Token-to-value mapping stored in secure token vault
- Detokenization requires access to vault + authorization
- Format-preserving tokenization: Token looks like original (same length/format)
- PCI DSS: Tokenization of PANs is a scoping reduction mechanism

```
Payment Card: 4111 1111 1111 1111
Token:        9876 5432 1098 7654  ← same length/format; no mathematical relationship
Token Vault:  {token: 9876... → PAN: 4111...}  ← protected separately
```

### 6.8 GDPR/CCPA Technical Architecture Requirements

| Requirement | Technical Implementation |
|---|---|
| Right to Access (DSAR) | Data subject request portal; automated PII search across all systems |
| Right to Erasure | Deletion API that cascades across microservices; data lineage tracking |
| Data Minimization | Schema review; fields collected only if purpose documented |
| Purpose Limitation | Data catalog with purpose tags; DLP policies enforcing purpose |
| Storage Limitation | Data retention schedule; automated deletion pipelines |
| Pseudonymization | Replace direct identifiers with pseudonyms; mapping table encrypted separately |
| Breach Notification (72h) | IR playbook with automated breach detection + DPO escalation |
| Consent Management | Consent management platform (OneTrust, Cookiebot); immutable consent audit log |
| Data Transfer Controls | TLS + SCCs for EU-US transfers; Binding Corporate Rules for intra-group |

---

## 7. Identity Architecture

### 7.1 IAM Architecture: Directory Services, Federation, PAM

**Enterprise IAM Stack:**

```
AUTHORITATIVE IDENTITY SOURCES
  ├─ HR System (Workday, SAP): Source of truth for identity lifecycle
  ├─ Active Directory / Azure AD: Directory services
  └─ LDAP (OpenLDAP): Unix/Linux authentication

FEDERATION LAYER
  ├─ IdP (Okta / PingFederate / Azure AD): SAML 2.0 / OIDC
  ├─ SP Connections: SaaS applications (Salesforce, Workday, ServiceNow)
  └─ Just-in-Time (JIT) provisioning: Auto-create accounts on first SAML login

PRIVILEGE ACCESS MANAGEMENT (PAM)
  ├─ Credential Vault (CyberArk / BeyondTrust / Delinea)
  ├─ Session Management (RDP/SSH proxy with recording)
  └─ JIT/JEA: Request-based privileged access with approval workflow

IDENTITY GOVERNANCE (IGA)
  ├─ SailPoint / Saviynt / One Identity
  ├─ Joiner/Mover/Leaver automation
  └─ Certification campaigns (access reviews)
```

### 7.2 Identity Governance Architecture (Joiner/Mover/Leaver)

**Lifecycle Automation:**

```
JOINER (New Employee):
  HR System creates record
    │ Auto-trigger via SCIM or HR connector
    ▼
  IGA platform provisions:
    ├─ AD account (from template role)
    ├─ Email account
    ├─ Core SaaS app access (Slack, Zoom, HR portal)
    ├─ Role-based access (from job title/department mapping)
    └─ MFA enrollment invitation sent

MOVER (Role Change):
  HR updates job title or department
    │ Delta sync to IGA
    ▼
  IGA platform:
    ├─ Adds new role entitlements
    ├─ Triggers re-certification for existing access
    └─ Removes entitlements not required in new role (SOD enforcement)

LEAVER (Termination):
  HR triggers termination event
    │ Priority: execute within defined SLA (e.g., same-day for involuntary)
    ▼
  IGA platform:
    ├─ Disable AD account
    ├─ Revoke all active sessions (OIDC token revocation)
    ├─ Transfer owned assets to manager
    ├─ Revoke all SaaS app access
    └─ Archive mailbox per retention policy
```

**Separation of Duties (SOD) Controls:**

```
SOD Rule Examples:
  ├─ Create Vendor + Approve Payment = Conflict (fraud risk)
  ├─ Developer + Production Deploy = Conflict (change control risk)
  └─ Administer AD + Manage PAM = Conflict (privilege escalation risk)

Enforcement:
  ├─ Preventive: IGA blocks granting conflicting entitlement
  ├─ Detective: Quarterly SOD audit report + exception review
  └─ Compensating: Additional approval required for temporary SOD exception
```

### 7.3 Privileged Access Management Architecture

**PAM Architecture (CyberArk reference):**

```
Digital Vault (Credential Store)
  ├─ AES-256 encrypted, hardened OS
  ├─ Access via PVWA (web interface) or API
  └─ Audit log of all credential accesses
       │
       ▼
CPM (Central Policy Manager)
  ├─ Rotates passwords automatically (on schedule or post-use)
  ├─ Verifies passwords are current
  └─ Reconciles out-of-sync credentials
       │
       ▼
PSM (Privileged Session Manager)
  ├─ RDP/SSH proxy — user never gets direct credential
  ├─ Full session video recording
  ├─ Keystroke logging
  └─ Session isolation (no local clipboard, no file transfer unless approved)
       │
       ▼
Target Systems (Windows/Linux/DB/Network devices)
```

**JIT Access Workflow:**

```
1. User requests privileged access via ticketing system (ServiceNow)
2. Auto-approval for pre-approved requests; manual for sensitive systems
3. PAM grants time-limited (e.g., 2-hour) access to specific target
4. Credential checked out from vault (or JIT local account created)
5. Session recorded by PSM
6. At expiry: access revoked, credential rotated, account disabled
7. Recording stored in vault for compliance retention
```

### 7.4 Certificate Authority Hierarchy

**PKI Hierarchy:**

```
OFFLINE ROOT CA (air-gapped HSM)
  ├─ Signs Intermediate CA certs only
  ├─ Never connected to network
  ├─ Ceremony-based signing with N-of-M key ceremony
  └─ Very long key life (20 years), short certificate validity

ISSUING (INTERMEDIATE) CA
  ├─ Online; issues end-entity certificates
  ├─ Protected by HSM (FIPS 140-2 Level 3)
  ├─ Separate CAs per use case:
  │    ├─ User/Device Auth CA (802.1X, VPN)
  │    ├─ Server TLS CA (internal HTTPS)
  │    ├─ Code Signing CA
  │    └─ Email (S/MIME) CA
  └─ Validity: 5-10 years; short-lived end-entity certs (1-2 years)

END-ENTITY CERTIFICATES
  ├─ User certs: Smart card / FIDO2 authentication
  ├─ Device certs: Machine authentication (802.1X EAP-TLS)
  ├─ Server certs: Internal TLS (SAN: *.internal.example.com)
  └─ Code signing certs: Authenticode, JAR signing

REVOCATION
  ├─ CRL (Certificate Revocation List): Published to LDAP/HTTP
  ├─ OCSP (Online Certificate Status Protocol): Real-time status
  └─ OCSP Stapling: Server includes OCSP response in TLS handshake
```

### 7.5 PKI Architecture for Enterprise and IoT

**IoT PKI Special Considerations:**

| Challenge | Solution |
|---|---|
| Scale: millions of devices | Automated certificate enrollment (EST, SCEP, ACME) |
| Constrained devices | EC key pairs (P-256) — smaller keys, faster operations |
| Certificate lifecycle | Short validity (90 days) with auto-renewal |
| Device identity | Unique cert per device; burned in at manufacturing (IDevID) |
| Revocation at scale | OCSP over CoAP; CRL too large for constrained devices |
| Network segmentation | PKI accessible from IoT VLAN; isolated from corporate PKI |

### 7.6 FIDO2/WebAuthn Architecture

**WebAuthn Registration Flow:**

```
1. Server generates challenge (random, base64url)
2. Browser calls navigator.credentials.create({
     publicKey: {
       challenge: CHALLENGE,
       rp: {id: "example.com", name: "Example"},
       user: {id: USER_ID, name: "user@example.com"},
       pubKeyCredParams: [{type: "public-key", alg: -7}],  // ES256
       authenticatorSelection: {
         authenticatorAttachment: "platform",  // or "cross-platform"
         userVerification: "required"
       }
     }
   })
3. Authenticator (TPM/YubiKey/TouchID) generates key pair
   Private key stored in authenticator hardware
   Public key returned in credential
4. Server stores: credential ID, public key, AAGUID (device type)

FIDO2 Authentication Flow:
1. Server generates challenge
2. Browser calls navigator.credentials.get({publicKey: {challenge, allowCredentials}})
3. Authenticator prompts user (PIN/biometric)
4. Authenticator signs challenge with private key
5. Server verifies signature with stored public key
6. No credential transmitted; no phishable data exchanged
```

---

## 8. Security Operations Architecture

### 8.1 SOC Architecture: Tiered Analyst Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     THREAT INTELLIGENCE                         │
│   External feeds · ISAC sharing · Threat hunt hypothesis        │
└────────────────────────────┬────────────────────────────────────┘
                             │ Intel feeds detection rules
                             ▼
┌──────────────────────────────────────────────────────────────┐
│                     SIEM / XDR PLATFORM                       │
│  Log ingestion → Parsing → Correlation → Alert generation     │
└─────────────────────────┬────────────────────────────────────┘
                          │ Alerts
                          ▼
┌──────────────────────────────────────────────────────────────┐
│                    TIER 1 — TRIAGE                            │
│  Alert triage · Basic investigation · Ticket creation         │
│  SLA: Acknowledge within 15 min; initial triage within 1hr    │
│  Escalation trigger: Confidence ≥ Medium or asset value High  │
└─────────────────────────┬────────────────────────────────────┘
                          │ Escalation
                          ▼
┌──────────────────────────────────────────────────────────────┐
│               TIER 2 — INCIDENT RESPONSE                      │
│  Deep dive investigation · Containment · Forensics            │
│  Coordinates with IT/cloud/app teams                          │
│  Runs SOAR playbooks; invokes manual response as needed       │
└─────────────────────────┬────────────────────────────────────┘
                          │ Complex/critical incidents
                          ▼
┌──────────────────────────────────────────────────────────────┐
│               TIER 3 — THREAT HUNT / ADVANCED IR              │
│  Proactive threat hunting · Custom tooling                    │
│  Reverse engineering · Attribution research                   │
│  Detection improvement · Purple team exercises                │
└──────────────────────────────────────────────────────────────┘
```

### 8.2 SIEM Architecture

**SIEM Data Pipeline:**

```
LOG SOURCES
  ├─ Windows Event Logs (WEC → Syslog → SIEM)
  ├─ Linux Syslog / Auditd
  ├─ Firewall / NGFW (Syslog CEF)
  ├─ IDS/IPS (Suricata → EVE JSON)
  ├─ EDR (CrowdStrike / SentinelOne API)
  ├─ Cloud (CloudTrail → S3 → SIEM; Azure Monitor → Event Hub)
  ├─ DNS query logs
  └─ Application logs (custom parsing)
       │
       ▼ Transport
COLLECTION TIER
  ├─ Syslog aggregators (rsyslog, syslog-ng)
  ├─ Log forwarders (Splunk UF, Elastic Agent, Filebeat, NXLog)
  └─ API collectors (cloud services, SaaS platforms)
       │
       ▼
PARSING / ENRICHMENT TIER
  ├─ Field extraction (regex, grok patterns, CEF/LEEF parsing)
  ├─ Normalization (common schema: ECS, OCSF)
  ├─ Enrichment: GeoIP, asset inventory, user lookup, threat intel IOC match
  └─ Deduplication and aggregation
       │
       ▼
STORAGE TIER
  ├─ Hot tier: SSD/NVMe (0-30 days): Full indexed search
  ├─ Warm tier: Cheaper SSD (30-90 days): Slower search
  └─ Cold tier: Object storage (90 days - 7 years): Compliance archive
       │
       ▼
DETECTION / CORRELATION ENGINE
  ├─ Rule-based correlation (SIEM correlation rules)
  ├─ Statistical anomaly detection
  ├─ ML-based behavioral models (UEBA)
  └─ Threat intel IOC matching (STIX indicators)
       │
       ▼
ALERT MANAGEMENT
  ├─ Alert tuning (reduce false positives)
  ├─ Priority scoring (CVSS + asset value + confidence)
  └─ Ticketing integration (ServiceNow, Jira)
```

### 8.3 SOAR Placement and Playbook Integration

**SOAR Architecture:**

```
SIEM (Alert source)
  │ Webhook / API alert push
  ▼
SOAR Platform (Palo Alto XSOAR / Splunk SOAR / IBM SOAR)
  ├─ Playbook Engine:
  │    ├─ Trigger: Alert type + severity
  │    ├─ Enrichment phase:
  │    │    ├─ VirusTotal (hash/URL/IP lookup)
  │    │    ├─ Shodan (IP context)
  │    │    ├─ AD lookup (user context)
  │    │    └─ CMDB lookup (asset context)
  │    ├─ Decision gate: Auto-close (false positive) vs. escalate
  │    └─ Response phase:
  │         ├─ Isolate host (EDR API)
  │         ├─ Block IP (firewall API)
  │         ├─ Disable AD account (LDAP)
  │         └─ Create IR ticket (ServiceNow API)
  │
  ├─ Case Management: Track all evidence, actions, timeline
  └─ Reporting: MTTR, automation rate, playbook coverage
```

**Phishing Response Playbook (SOAR):**

```
Trigger: Phishing email reported via "Report Phishing" button

1. Extract: sender, reply-to, URLs, attachments, headers
2. Enrich: URL reputation (VT, URLScan), hash lookup, sender domain age
3. Decision:
   ├─ Benign (confidence > 90%) → Close with feedback to reporter
   ├─ Suspicious (confidence 50-90%) → Escalate to T2, quarantine email
   └─ Malicious (confidence > 90%) → Auto-response:
       ├─ Delete all copies from mailboxes (Exchange/O365 API)
       ├─ Block sender domain at email gateway
       ├─ Block URLs at proxy
       ├─ Block file hash at EDR
       ├─ Check for users who clicked (proxy logs)
       └─ Notify affected users + security team
```

### 8.4 XDR Architecture vs. Point Solutions

**Point Solution Architecture (Legacy):**

```
EDR (endpoint telemetry) → SIEM
NDR (network telemetry) → SIEM
CASB (cloud app telemetry) → SIEM
Email Security (email telemetry) → SIEM
SIEM correlates across siloed telemetry (complex, delayed)
```

**XDR Architecture:**

```
┌──────────────────────────────────────────────────────────┐
│                    XDR PLATFORM                          │
│  (CrowdStrike Falcon / Microsoft Defender XDR / Palo XSIAM)│
│                                                          │
│  Unified data lake across all telemetry sources          │
│  ├─ Endpoint: EDR telemetry                              │
│  ├─ Network: NDR/NGFW telemetry                          │
│  ├─ Identity: AD / Entra ID telemetry                    │
│  ├─ Cloud: CSPM / CWPP telemetry                         │
│  └─ Email: Email gateway telemetry                       │
│                                                          │
│  Cross-source correlation (no hand-off latency)          │
│  Unified investigation graph                             │
│  Automated response across all pillars                   │
└──────────────────────────────────────────────────────────┘
```

**XDR vs. SIEM+SOAR:**

| Capability | XDR | SIEM + SOAR |
|---|---|---|
| Data integration | Native (same vendor) | Many integrations required |
| Detection latency | Lower (pre-correlated) | Higher (log forwarding lag) |
| False positive rate | Lower (correlated context) | Higher (siloed correlation) |
| Coverage | Vendor ecosystem | Any log source |
| Customization | Less flexible | Highly customizable |
| Cost model | Platform license | Log volume + SOAR license |

### 8.5 Threat Intelligence Platform (TIP) Architecture

**TIP Architecture:**

```
EXTERNAL INTEL FEEDS                    INTERNAL INTEL
  ├─ Commercial (Recorded Future,         ├─ IR findings
  │   Mandiant, CrowdStrike Intel)        ├─ Threat hunt observations
  ├─ Open source (AlienVault OTX,         ├─ Malware analysis output
  │   MISP community, Abuse.ch)           └─ Red team IOCs
  ├─ ISAC/ISAO sharing
  └─ Government (CISA AIS, FBI)
           │                                     │
           └──────────────┬──────────────────────┘
                          ▼
                    TIP PLATFORM
              (MISP / ThreatQ / Anomali)
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
        SIEM            Firewall        Endpoint
    (IOC matching)   (Block lists)   (Hash / URL block)

STIX/TAXII integration:
  ├─ STIX 2.1 objects: indicator, malware, threat-actor, campaign, course-of-action
  └─ TAXII 2.1 server: authenticated distribution to consumers
```

### 8.6 UEBA Data Flow and Baseline Modeling

**UEBA Architecture:**

```
DATA SOURCES → UEBA PLATFORM → RISK SCORES → SIEM / SOC

Data Sources:
  ├─ AD logon events (4624, 4625, 4768, 4769)
  ├─ VPN access logs
  ├─ File access (CIFS/NFS audit, SharePoint)
  ├─ Email patterns (volume, recipients, attachments)
  ├─ EDR process execution
  └─ Cloud access logs (O365, AWS CloudTrail)

UEBA Processing:
  1. Baseline modeling (14-30 days): Normal peer group behavior
  2. Anomaly detection: Statistical deviation from baseline
     ├─ Time anomaly: Login at 3am vs. 9am normal
     ├─ Volume anomaly: 1000 file accesses vs. 20 normal
     ├─ Location anomaly: Access from new country
     └─ Peer group anomaly: Access to resources unlike peers
  3. Risk scoring: Combine weighted anomaly signals → risk score
  4. Case creation: High-risk entity → SOAR / analyst queue
```

### 8.7 Log Retention Architecture

**Tiered Retention:**

| Tier | Storage Type | Latency | Retention | Use Case |
|---|---|---|---|---|
| Hot | SSD/NVMe index (Elasticsearch, Splunk) | Seconds | 0-30 days | Active investigations, real-time detection |
| Warm | HDD index or tiered (S3 Intelligent-Tiering) | Minutes | 30-90 days | Recent investigations, trend analysis |
| Cold | Object storage (S3 Glacier, Azure Archive) | Hours | 90 days - 7 years | Compliance, forensic investigation, legal hold |

**Compliance Retention Requirements:**

| Regulation | Log Type | Minimum Retention |
|---|---|---|
| PCI DSS 4.0 | Audit logs (Req 10.5) | 12 months (3 months hot) |
| HIPAA | Access and security logs | 6 years |
| SOX | Financial system audit logs | 7 years |
| GDPR | Access logs involving personal data | Data minimization principle; typically 6-12 months |
| NIST 800-53 (AU-11) | Audit records | Organization-defined (often 3 years) |
| FedRAMP | System audit logs | 90 days online; 1 year offline |

---

## 9. Resilience Architecture

### 9.1 Business Continuity Planning (BCP) Architecture

**BCP Scope:**

```
BCP Framework Components:
  ├─ Business Impact Analysis (BIA)
  │    ├─ Identify critical business processes
  │    ├─ Determine financial/operational impact of disruption
  │    └─ Define RTO (Recovery Time Objective) and RPO (Recovery Point Objective)
  │
  ├─ Risk Assessment
  │    ├─ Threat scenarios: natural disaster, cyberattack, vendor failure
  │    ├─ Likelihood and impact scoring
  │    └─ Residual risk after controls
  │
  ├─ Continuity Strategies
  │    ├─ Warm standby / active-passive
  │    ├─ Active-active (continuous availability)
  │    └─ Manual workarounds (paper-based, phone trees)
  │
  ├─ Crisis Communication Plan
  │    ├─ Internal escalation tree
  │    ├─ External communication (customers, regulators, media)
  │    └─ Public relations and legal coordination
  │
  └─ Testing Schedule
       ├─ Tabletop exercises (quarterly)
       ├─ Component failover tests (semi-annual)
       └─ Full DR failover test (annual)
```

### 9.2 Disaster Recovery: RTO/RPO, Active-Active vs. Active-Passive

**RTO and RPO Definitions:**

```
INCIDENT OCCURS
      │
      ▼ ──────────────────────────────────────── RPO ──────►
  LAST BACKUP                               INCIDENT    (data loss window)
  (recovery point)
      │
      ▼
  RECOVERY BEGINS
      │
      ▼ ──────────────────────────────────────────────────►
  RECOVERY BEGINS                             RTO EXPIRES
  (IT restores service)                     (system back online)
```

**DR Architecture Patterns:**

| Pattern | Description | RTO | RPO | Cost |
|---|---|---|---|---|
| **Backup & Restore** | Restore from backup to new environment | Hours-days | Hours-days | Lowest |
| **Pilot Light** | Minimal always-on infra; scale up on disaster | Hours | Minutes | Low |
| **Warm Standby** | Scaled-down replica always running; scale up on disaster | Minutes | Seconds-minutes | Medium |
| **Active-Active (Multi-site)** | Full capacity in multiple sites; traffic load balanced | Near-zero | Near-zero | Highest |

**Active-Active Architecture (AWS Multi-Region):**

```
Route 53 (latency-based or geolocation routing)
  │
  ├─────────────────────────────────────────────────┐
  ▼                                                 ▼
us-east-1 Region                           eu-west-1 Region
  ├─ ALB + ASG                               ├─ ALB + ASG
  ├─ RDS Aurora (write)◄──Global DB Repl────►├─ RDS Aurora (read/write failover)
  ├─ ElastiCache                             ├─ ElastiCache
  └─ S3 (CRR to eu-west-1) ─────────────────►└─ S3 (CRR from us-east-1)
```

### 9.3 Backup Architecture: 3-2-1-1-0 Rule

**3-2-1-1-0 Rule:**

| Digit | Meaning |
|---|---|
| **3** | Three copies of data |
| **2** | Two different storage media types |
| **1** | One copy off-site |
| **1** | One copy offline or air-gapped (immutable) |
| **0** | Zero backup errors (verified restoration) |

**Immutable Backup Architecture:**

```
PRIMARY DATA
    │ Backup job (daily)
    ▼
BACKUP SERVER
    │ Replication (immediate or scheduled)
    ▼
CLOUD OBJECT STORE (S3 with Object Lock / Azure Immutable Blob)
    │ Object Lock: COMPLIANCE mode
    │ Retention: 30 days minimum
    │ Cannot be deleted or overwritten (even by root account)
    │
    ├─ Ransomware cannot encrypt: no write access from backup network
    └─ Insider threat cannot delete: Object Lock enforced by cloud provider

AIR-GAPPED OFFLINE COPY
    ├─ Tape or offline hard drives
    ├─ Physically disconnected from network
    ├─ Write-once media (WORM tapes)
    └─ Stored off-site (separate facility)
```

### 9.4 Resilience Testing: Chaos Engineering for Security

**Chaos Engineering Principles Applied to Security:**

```
HYPOTHESIS: "Our incident response playbook can contain a compromised EC2
instance within 15 minutes of detection."

EXPERIMENT DESIGN:
  1. Scope: Non-production environment with production-like data flows
  2. Steady state: Normal monitoring metrics (no active alerts)
  3. Inject fault: Simulate compromised instance (run malicious process,
     establish C2 beacon, begin lateral movement)
  4. Measure: Time from first indicator to containment (isolation)
  5. Compare to RTO/detection SLA

SECURITY CHAOS SCENARIOS:
  ├─ Terminate random availability zone → test multi-AZ resilience
  ├─ Introduce network partition → test service mesh circuit breakers
  ├─ Simulate KMS key unavailability → test encryption failure handling
  ├─ Kill SIEM indexer → validate alert persistence and queue handling
  ├─ Inject unauthorized API call → validate GuardDuty detection latency
  └─ Simulate IdP unavailability → test authentication fallback path

TOOLS:
  ├─ AWS Fault Injection Simulator (FIS)
  ├─ Chaos Monkey (Netflix)
  ├─ Gremlin
  └─ LitmusChaos (Kubernetes)
```

### 9.5 Incident Response Architecture

**Detection Pipeline → Triage → Containment → Eradication:**

```
DETECTION PIPELINE
  ├─ SIEM alert: Correlation rule fires
  ├─ EDR alert: Behavioral detection
  ├─ User report: Phishing / anomaly observed
  ├─ External notification: Bug bounty, threat intel partner
  └─ Automated scan: Vulnerability scanner finds active exploit
       │
       ▼
TRIAGE (Tier 1 SOC)
  ├─ Validate: Is alert a true positive?
  ├─ Scope: What systems/data are affected?
  ├─ Classify: Incident severity (P1/P2/P3/P4)
  └─ Escalate to IR team (P1/P2) or handle (P3/P4)
       │
       ▼
CONTAINMENT (Tier 2 IR)
  ├─ Short-term: Isolate affected system (EDR quarantine; VLAN move)
  ├─ Prevent spread: Block C2 domains/IPs; disable compromised accounts
  ├─ Preserve evidence: Memory dump; disk snapshot before cleanup
  └─ Establish secure command channel (separate from potentially compromised network)
       │
       ▼
ERADICATION
  ├─ Remove malware artifacts (registry keys, persistence mechanisms)
  ├─ Patch exploited vulnerability
  ├─ Rotate compromised credentials
  └─ Verify no residual attacker presence (threat hunt)
       │
       ▼
RECOVERY
  ├─ Restore from known-good backups
  ├─ Validate integrity of restored systems
  ├─ Gradual return to production (monitor closely)
  └─ Validate security controls are functioning
       │
       ▼
POST-INCIDENT REVIEW
  ├─ Root cause analysis (5-Whys, fishbone)
  ├─ Timeline reconstruction
  ├─ Detection gap analysis (MITRE ATT&CK coverage review)
  └─ Action items: controls improvement, playbook updates
```

---

## 10. Architecture Review Process

### 10.1 Threat Model-Driven Architecture Review Checklist

**Pre-Review Artifacts Required:**

- [ ] Architecture diagram (component, data flow, deployment)
- [ ] Data Flow Diagram with trust boundaries marked
- [ ] Asset inventory (crown jewels identified)
- [ ] Threat model output (STRIDE or equivalent)
- [ ] Previous architecture review findings and remediation status
- [ ] Compliance requirements applicable to this system

**Architecture Review Checklist:**

**Identity and Access:**
- [ ] All authentication mechanisms identified and reviewed
- [ ] MFA enforced for privileged access and internet-facing applications
- [ ] Service accounts use least privilege; no shared credentials
- [ ] Secrets not hardcoded; secrets management system in use
- [ ] Session management: timeout, revocation, token rotation

**Network Security:**
- [ ] Network segmentation appropriate for data sensitivity
- [ ] All data flows documented; unnecessary flows blocked
- [ ] Ingress/egress filtering in place
- [ ] Management interfaces on separate network segment
- [ ] TLS version and cipher suite requirements met

**Data Protection:**
- [ ] Data classification applied to all data stores
- [ ] Encryption at rest for Confidential and above
- [ ] Encryption in transit for all data flows
- [ ] Key management hierarchy documented; HSM or KMS in use
- [ ] Backup and recovery tested

**Application Security:**
- [ ] Input validation on all user-controlled inputs
- [ ] Output encoding to prevent injection
- [ ] Authentication and authorization reviewed for all endpoints
- [ ] Secrets management for API keys and credentials
- [ ] Dependency scanning results reviewed; critical CVEs addressed

**Logging and Monitoring:**
- [ ] Security-relevant events logged (auth events, admin actions, errors)
- [ ] Logs forwarded to SIEM; not stored only locally
- [ ] Log tampering protection (append-only, remote storage)
- [ ] Alerting in place for critical security events
- [ ] Retention meets compliance requirements

**Resilience:**
- [ ] RTO and RPO defined and achievable with current architecture
- [ ] DR plan documented and tested within 12 months
- [ ] Backup strategy meets 3-2-1-1-0 rule
- [ ] Single points of failure identified and mitigated

### 10.2 Security Architecture Review Board (SARB) Process

**SARB Charter:**

The Security Architecture Review Board is a governance body responsible for
reviewing security architectures of significant systems and ensuring alignment
with enterprise security standards.

**SARB Membership:**
- Chief Information Security Officer (CISO) or delegate (Chair)
- Enterprise Security Architect
- Cloud Security Architect
- Application Security Lead
- Network Security Engineer
- Privacy Officer (for data-handling systems)
- Business stakeholder representative

**SARB Review Process:**

```
1. SUBMISSION (2 weeks before review)
   ├─ Architecture package submitted to SARB secretary
   └─ Threat model, architecture diagram, compliance matrix

2. PRE-REVIEW (1 week before)
   ├─ SARB members review materials independently
   └─ Questions submitted to presenter in advance

3. REVIEW SESSION (90 minutes)
   ├─ 30 min: Architecture walkthrough by presenter
   ├─ 45 min: Questions and discussion
   └─ 15 min: SARB deliberation (presenter leaves room)

4. DECISION
   ├─ Approved: No blocking findings
   ├─ Approved with conditions: Deploy after resolving specified findings
   └─ Not approved: Fundamental issues; redesign required

5. FINDINGS TRACKING
   ├─ All findings documented with severity and owner
   ├─ Monthly review of open findings
   └─ SARB re-review required for architectural changes
```

### 10.3 Risk Acceptance Criteria and Formal Sign-Off

**Risk Acceptance Framework:**

| Risk Level | Criteria | Sign-Off Authority | Review Frequency |
|---|---|---|---|
| Critical | CVSS ≥9.0 or data breach potential | CISO + Business Unit Head | Monthly |
| High | CVSS 7.0-8.9 or significant operational impact | CISO | Quarterly |
| Medium | CVSS 4.0-6.9 or limited impact | Security Architect | Semi-annual |
| Low | CVSS <4.0 or minimal impact | Security Team Lead | Annual |

**Formal Risk Acceptance Process:**

```
1. Risk identified and documented (severity, likelihood, impact, affected assets)
2. Mitigation options assessed (implement control vs. accept vs. transfer)
3. Risk owner identified (business unit head who owns the system)
4. Risk acceptance memo drafted:
   ├─ Risk description and evidence
   ├─ Proposed acceptance rationale (cost, timeline, technical infeasibility)
   ├─ Compensating controls in place
   ├─ Residual risk statement
   └─ Review date (not to exceed risk-level frequency above)
5. Sign-off obtained at appropriate authority level
6. Risk registered in GRC platform (ServiceNow, Archer, OneTrust)
7. Periodic review scheduled; re-assess if threat landscape changes
```

### 10.4 Architecture Patterns Anti-Patterns Table

| Pattern (Good) | Anti-Pattern (Avoid) | Why It Matters |
|---|---|---|
| Micro-segmentation with deny-by-default | Flat network / trust all internal traffic | Lateral movement after breach; blast radius |
| Centralized secrets management (Vault) | Hardcoded credentials in source code | Single compromised repo exposes all systems |
| mTLS between microservices | Open service-to-service (no auth) | Service impersonation; unauthorized data access |
| Short-lived credentials (IRSA, WI) | Long-lived static IAM keys | Leaked keys valid indefinitely |
| Least-privilege RBAC | Admin-to-all service accounts | Privilege escalation via service account compromise |
| Immutable infrastructure (cattle) | Long-running mutable VMs (pets) | Undetected persistence; configuration drift |
| Centralized log aggregation | Local-only logging | Logs destroyed/tampered post-compromise |
| OIDC/SAML federation | Local accounts per application | No centralized account lifecycle management |
| API gateway with rate limiting | Direct backend API exposure | Enumeration, scraping, brute force |
| Encrypted secrets at rest (KMS) | Secrets in plaintext config files | Secret exposure on disk access |
| WAF in front of web apps | Direct web server internet exposure | OWASP Top 10 exploitation |
| Private subnets for databases | Database in public subnet | Direct internet exploitation of DB |
| Zero Trust access (ZTNA) | VPN split tunneling to internal network | VPN as lateral movement enabler |

### 10.5 MITRE ATT&CK Mapping to Architectural Controls

**Tactical Layer Controls:**

| ATT&CK Tactic | Representative Techniques | Architectural Control |
|---|---|---|
| Initial Access (TA0001) | T1566 Phishing, T1190 Exploit Public App | Email security gateway; WAF; patch management |
| Execution (TA0002) | T1059 Command/Script, T1203 Exploitation | Application whitelisting; EDR; DAST; no-exec mounts |
| Persistence (TA0003) | T1053 Scheduled Tasks, T1136 Create Account | Immutable infra; IGA lifecycle; FIM; privileged access monitoring |
| Privilege Escalation (TA0004) | T1068 Exploitation, T1548 Abuse Elevation | PAM; JIT access; EDR; patch management; least privilege |
| Defense Evasion (TA0005) | T1562 Impair Defenses, T1070 Indicator Removal | Log protection; centralized SIEM; CSPM; cloud audit integrity |
| Credential Access (TA0006) | T1110 Brute Force, T1555 Credentials in Store | MFA; PAM; secrets management; Credential Guard |
| Discovery (TA0007) | T1046 Network Scan, T1082 System Info | IDS/IPS; network micro-segmentation; least privilege |
| Lateral Movement (TA0008) | T1021 Remote Services, T1550 Pass-the-Hash | Micro-segmentation; PAW; EDR; disable legacy auth |
| Collection (TA0009) | T1005 Data from Local System, T1530 Cloud Storage | DLP; CASB; endpoint DLP; data classification |
| Command and Control (TA0011) | T1071 App Layer Protocol, T1572 Protocol Tunnel | DNS security; proxy/SSL inspection; UEBA; EDR |
| Exfiltration (TA0010) | T1041 Exfil over C2, T1567 Web Service | DLP; CASB; egress filtering; bandwidth anomaly detection |
| Impact (TA0040) | T1486 Ransomware, T1490 Inhibit Recovery | Immutable backups; air-gapped copies; EDR; network segmentation |

**ATT&CK Coverage Heatmap (by architectural control layer):**

```
Control Layer          Tactics Covered
─────────────────────────────────────────────────────────────
Perimeter (FW/WAF)   Initial Access, Exfiltration
Email Security        Initial Access (Phishing)
Network Segment       Lateral Movement, Discovery
EDR                   Execution, Persistence, Priv Esc, Evasion, C2
MFA/PAM               Credential Access, Privilege Escalation
SIEM/UEBA             All tactics (detection layer)
DLP/CASB              Collection, Exfiltration
Backup/Immutable      Impact (Ransomware)
DNS Security          C2, Initial Access (malicious domains)
ZTNA/Zero Trust       Lateral Movement, Credential Access
```

---

## Quick Reference: Architecture Framework Decision Guide

| Situation | Recommended Framework / Standard |
|---|---|
| Enterprise security architecture program | SABSA (risk-driven, business-aligned) |
| EA team already using TOGAF | TOGAF Security Extension |
| NIST-aligned government or regulated environment | NIST SP 800-160 (Systems Security Engineering) |
| Zero Trust initiative | NIST SP 800-207 + CISA ZTMM v2.0 |
| Cloud architecture review | CSA CCM + AWS/Azure/GCP Well-Architected |
| Application threat modeling | STRIDE (functional teams) or PASTA (risk-focused) |
| Supply chain security architecture | SLSA + NIST SP 800-161 |
| IoT security architecture | NIST SP 800-213 + ETSI EN 303 645 |
| OT/ICS security architecture | IEC 62443 + NIST SP 800-82 |
| Container/K8s security architecture | CIS Kubernetes Benchmark + NIST SP 800-190 |

---

## See Also

- [Zero Trust Reference](ZERO_TRUST_REFERENCE.md)
- [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md)
- [Cloud Security Architecture](disciplines/cloud-security.md)
- [Container Security Reference](CONTAINER_SECURITY_REFERENCE.md)
- [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md)
- [Identity Security](disciplines/identity-access-management.md)
- [GRC Reference](GRC_REFERENCE.md)
- [Threat Modeling](disciplines/threat-modeling.md)
- [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md)
- [DevSecOps](disciplines/devsecops.md)
