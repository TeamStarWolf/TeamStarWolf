# Zero Trust Architecture

## Introduction

Zero Trust Architecture (ZTA) is a security paradigm that eliminates implicit trust and enforces continuous verification for every user, device, and workload — regardless of whether they are inside or outside the traditional network perimeter. The foundational principle, coined by John Kindervag at Forrester Research in 2010, is **"never trust, always verify."**

Traditional perimeter-based security assumed that everything inside the corporate network was safe. Modern threats — cloud adoption, remote work, supply chain compromises, and insider threats — shattered that assumption. ZTA treats every access request as potentially hostile and requires explicit verification before granting access.

## Where to Start

1. **Read NIST SP 800-207** (free PDF) — the authoritative U.S. government reference for ZTA
2. **Read the CISA Zero Trust Maturity Model** (free) — practical pillar-based roadmap
3. **Inventory your identity providers** — Identity is the new perimeter; start there
4. **Map your most sensitive data and applications** — ZTA protects assets, not network zones
5. **Assess your current MFA posture** — phishing-resistant MFA (FIDO2) is the baseline
6. **Pick one pillar** (Identity is recommended first) and mature it before expanding

## Free Training

- [NIST SP 800-207: Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf) — foundational standard (free PDF)
- [CISA Zero Trust Maturity Model v2](https://www.cisa.gov/zero-trust-maturity-model) — free government guide
- [Google BeyondCorp papers](https://cloud.google.com/beyondcorp) — real-world ZTA implementation at scale
- [Microsoft Zero Trust Guidance Center](https://learn.microsoft.com/en-us/security/zero-trust/) — free, extensive
- [Cloudflare Learning: What is Zero Trust?](https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/) — free conceptual primer
- [NSA Zero Trust Guidance](https://media.defense.gov/2021/Feb/25/2002588479/-1/-1/0/CSI_EMBRACING_ZT_SECURITY_MODEL_UOO115131-21.PDF) — NSA cybersecurity information sheet (free PDF)

## Tools & Repositories

### Identity & Access
| Tool | Purpose | Notes |
|---|---|---|
| [Azure AD / Entra ID Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/) | Risk-based adaptive access policies | Deep Microsoft 365 integration |
| [Okta](https://www.okta.com/) | Identity platform with adaptive MFA | Broad SaaS integration |
| [Ping Identity](https://www.pingidentity.com/) | Enterprise SSO/MFA/PAM | Strong on-prem + cloud hybrid |
| [CyberArk](https://www.cyberark.com/) | Privileged Access Management (PAM) | Industry leader for PAM/PIM |
| [BeyondTrust](https://www.beyondtrust.com/) | PAM + Remote Access | Strong least-privilege enforcement |

### Network & Access Proxy
| Tool | Purpose | Notes |
|---|---|---|
| [Zscaler Private Access (ZPA)](https://www.zscaler.com/products/zscaler-private-access) | ZTNA — replace VPN | Cloud-delivered, app-level proxy |
| [Cloudflare Access](https://www.cloudflare.com/products/zero-trust/access/) | ZTNA — identity-aware application proxy | Free tier available |
| [Palo Alto Prisma Access](https://www.paloaltonetworks.com/sase/access) | SASE + ZTNA | Integrated firewall + access control |
| [Tailscale](https://tailscale.com/) | WireGuard-based mesh VPN with device auth | Easy ZTA for small teams; open source client |
| [Boundary (HashiCorp)](https://www.boundaryproject.io/) | Open-source identity-based access management | Good for dynamic cloud infrastructure |

### Microsegmentation
| Tool | Purpose |
|---|---|
| [Illumio](https://www.illumio.com/) | Workload microsegmentation |
| [VMware NSX](https://www.vmware.com/products/nsx.html) | Software-defined networking + microsegmentation |
| [Guardicore (Akamai)](https://www.akamai.com/products/guardicore-segmentation) | Agentless microsegmentation, workload visualization |
| [Cisco Secure Workload](https://www.cisco.com/c/en/us/products/security/tetration/index.html) | Application-aware microsegmentation |

### Service Mesh (Application/Workload Pillar)
| Tool | Purpose |
|---|---|
| [Istio](https://istio.io/) | Service mesh with mTLS, RBAC, traffic policies |
| [Linkerd](https://linkerd.io/) | Lightweight service mesh for Kubernetes |
| [Consul Connect (HashiCorp)](https://www.consul.io/docs/connect) | Service mesh with certificate-based mTLS |

## Commercial Platforms

| Platform | Description |
|---|---|
| **Zscaler Zero Trust Exchange** | Cloud-delivered SASE platform; ZTNA, SWG, CASB, DLP |
| **Palo Alto Prisma Access** | SASE + Prisma Cloud for workload protection |
| **Microsoft Entra + Defender XDR** | Integrated identity, device, and app zero trust stack |
| **Okta Identity Cloud** | Identity-first ZTA: SSO, MFA, lifecycle management, PAM |
| **CrowdStrike Falcon Zero Trust** | Device trust + identity protection integrated with EDR |
| **Fortinet Zero Trust Access** | Network-centric ZTA with ZTNA and NAC |
| **Illumio Core** | Workload microsegmentation for data center and cloud |

## Core Principles

### "Never Trust, Always Verify"
Every access request — from any user, device, or workload, on any network — is treated as untrusted until verified. Network location (inside or outside the perimeter) grants no inherent trust.

### Microsegmentation
The network is divided into small, isolated zones. Each zone requires separate authentication and authorization to access. Breach of one zone does not grant access to others. This limits blast radius.

### Least Privilege Access
Users and workloads receive the minimum access required for their task. Privileges are granted just-in-time (JIT) and just-enough-access (JEA). No standing administrative privileges — admins elevate when needed and de-elevate when done.

### Assume Breach
Design the system assuming attackers are already inside. Focus on minimizing damage, detecting quickly, and containing laterally. This mindset drives micro-segmentation, east-west inspection, and aggressive monitoring.

## NIST SP 800-207 Zero Trust Architecture

NIST SP 800-207 is the authoritative U.S. government standard for ZTA, published in August 2020.

### Five Tenets of Zero Trust (NIST)
1. **All data sources and computing services are resources** — every device, service, and data store is treated as a resource regardless of location
2. **All communication is secured regardless of network location** — being on an internal network grants no special trust; communications are authenticated and encrypted
3. **Access to individual enterprise resources is granted per-session** — trust is evaluated for each session; prior access does not guarantee future access
4. **Access is determined by dynamic policy** — real-time evaluation of identity, application state, device health, behavioral signals, and environmental context
5. **Enterprise monitors and measures the integrity of all owned and associated assets** — continuous monitoring informs policy decisions

### ZTA Logical Components
- **Policy Engine (PE)**: Makes the trust decision — grant, deny, or revoke access. Uses policies, threat intelligence, CDM data, and compliance signals
- **Policy Administrator (PA)**: Communicates the PE decision to the enforcement point; establishes and terminates sessions
- **Policy Enforcement Point (PEP)**: The gate — enforces the PE/PA decision; splits into client agent and resource gateway components

## CISA Zero Trust Maturity Model (ZTMM)

The CISA ZTMM provides a roadmap for federal agencies (and is widely adopted commercially) across **five pillars** and **three maturity stages**.

### Five Pillars
| Pillar | Focus |
|---|---|
| **Identity** | User and non-person entities (NPEs): authentication, authorization, lifecycle |
| **Devices** | Hardware health, compliance, inventory, patching |
| **Networks** | Segmentation, encryption, traffic inspection |
| **Applications & Workloads** | App-layer authentication, API security, CI/CD security |
| **Data** | Classification, access governance, encryption, DLP |

### Three Maturity Stages
| Stage | Description |
|---|---|
| **Traditional** | Manual configurations, static policies, perimeter-centric |
| **Advanced** | Some automation, risk-based policies, partial attribute-based access |
| **Optimal** | Dynamic policy, fully automated, continuous monitoring, behavioral analytics |

### Cross-Cutting Capabilities
- **Visibility and Analytics**: Centralized logging, SIEM, UEBA, behavioral baselines
- **Automation and Orchestration**: SOAR, automated policy responses, infrastructure as code
- **Governance**: Policy framework, risk management integration, compliance alignment

## Identity Pillar (Deep Dive)

Identity is universally recommended as the starting point for ZTA implementation.

- **Phishing-resistant MFA**: FIDO2/WebAuthn hardware security keys (YubiKey, Titan Key) — resistant to token theft, AiTM phishing, and MFA fatigue attacks
- **Continuous identity verification**: Risk-based adaptive authentication — step-up auth when anomalies detected (new device, impossible travel, risky sign-in)
- **Privileged Identity Management (PIM/PAM)**: Just-in-time role activation with approval workflows; no standing admin accounts
- **Device-bound credentials**: Certificates tied to specific enrolled devices; prevent credential theft from being used from unauthorized hardware
- **Non-Person Entities (NPEs)**: Service accounts, workload identities, managed identities — apply same ZT principles; avoid long-lived secrets

**Key Tools**: Azure AD/Entra PIM, Okta Privileged Access, CyberArk Privilege Cloud, BeyondTrust Password Safe, HashiCorp Vault (secrets management)

## Device Pillar (Deep Dive)

- **Device health verification**: Before any access is granted, verify device compliance: EDR agent present and healthy, OS patch level meets policy, disk encryption enabled, no known malware
- **Certificate-based device authentication**: Device certificates issued by enterprise PKI; untrusted devices cannot authenticate
- **Mobile Device Management (MDM)**: Microsoft Intune, Jamf Pro (macOS/iOS), VMware Workspace ONE — enforce compliance policies, remote wipe capability
- **Privileged Access Workstations (PAW)**: Dedicated, hardened workstations for administrative tasks; isolated from standard user browsing/email risk

## Network Pillar (Deep Dive)

- **Microsegmentation**: Granular network zones — each workload communicates only with explicitly permitted peers; east-west traffic is controlled and inspected
- **Software-Defined Perimeter (SDP)**: Replaces VPN; applications are invisible to the internet until authenticated users/devices are verified; "dark cloud" concept
- **ZTNA (Zero Trust Network Access)**: Identity-aware proxy model — users connect to a broker that authenticates them and proxies access to the application; no direct network connectivity to the application server
- **East-West Traffic Inspection**: Internal network traffic is not implicitly trusted; IDS/IPS/firewalls inspect lateral traffic, not just north-south
- **Encrypted Communications Everywhere**: TLS 1.3 minimum; mutual TLS (mTLS) between services; deprecate legacy protocols (Telnet, FTP, HTTP, SMBv1)

## Application & Workload Pillar (Deep Dive)

- **Application-layer authentication**: Every app authenticates the user and device independently, not relying on network location
- **API Security**: OAuth 2.0 / OIDC for authorization; API gateways enforce rate limiting, authentication, and schema validation (Kong, AWS API Gateway, Apigee, Azure APIM)
- **Service Mesh**: Istio and Linkerd enforce mTLS between microservices automatically; policy-based service-to-service authorization
- **Continuous Application Security Testing**: SAST, DAST, SCA in CI/CD pipelines; shift-left security baked into development

## Data Pillar (Deep Dive)

- **Data Classification and Labeling**: Sensitivity labels (Microsoft Purview, Titus) on documents and emails; drives access control policies
- **Data Access Governance**: Enforce who can access which data, from which devices, at which times; attribute-based access control (ABAC)
- **Data Loss Prevention (DLP)**: Prevent sensitive data from leaving authorized channels; inspect outbound flows at endpoint and network
- **Encryption at Rest and in Transit**: AES-256 for data at rest; TLS 1.3 in transit; database column-level encryption for PII/PHI/PCI data

## Offensive Angle — Zero Trust Bypass Techniques

Understanding how attackers target ZTA implementations is essential for defenders.

### Identity Provider Attacks
- **MFA Fatigue (Push Bombing)**: Attacker obtains credentials then floods victim with MFA push notifications until they approve out of frustration. **Mitigation**: Number matching, context in push notifications, FIDO2 hardware keys
- **Adversary-in-the-Middle (AiTM) Phishing**: Tools like Evilginx2 proxy authentication in real time, stealing session cookies post-MFA. **Mitigation**: FIDO2 (phishing-resistant), Conditional Access requiring compliant device
- **Device Code Phishing**: Attacker tricks user into entering a device code at `microsoft.com/devicelogin`, which grants the attacker a valid OAuth token without browser interception. **Mitigation**: Block device code flow via Conditional Access where not needed
- **Token Theft**: Steal session tokens from browser storage or memory; replay without needing credentials. **Mitigation**: Token binding, Continuous Access Evaluation (CAE), short-lived tokens

### Device Trust Bypass
- **MDM Enrollment Attack**: Attacker enrolls a malicious device into MDM by exploiting misconfigured enrollment policies (e.g., no enrollment approval required). **Mitigation**: Require device enrollment approval, hardware attestation (TPM)
- **Compromised Compliant Device**: If attacker compromises an already-enrolled compliant device, the device passes all ZT checks. **Mitigation**: EDR behavioral detection; re-evaluate device trust dynamically

### Policy and Configuration Gaps
- **Legacy Authentication Protocols**: SMTP, IMAP, POP3, and Basic Auth bypass Conditional Access policies. **Mitigation**: Block legacy auth in Conditional Access; enforce modern auth only
- **Conditional Access Exclusions**: Emergency break-glass accounts, service accounts, specific user groups excluded from strong auth requirements — often targeted. **Mitigation**: Audit exclusions regularly; monitor excluded accounts aggressively
- **Service Account Abuse**: Service accounts frequently exempt from ZT policies (no MFA, no device compliance) — prime lateral movement targets. **Mitigation**: Workload identity federation; managed identities; apply ZT to service accounts

### Post-Access Exploitation
- **Lateral Movement Within Allowed Application Scope**: ZTA prevents unauthorized application access, but legitimate application vulnerabilities (SSRF, SQLi) can still be exploited once access is granted
- **Overly Permissive Microsegmentation**: Incorrectly defined allow-lists permit more east-west traffic than intended; auditing segmentation policies is critical

## NIST 800-53 Alignment

| Control | Family | Zero Trust Relevance |
|---|---|---|
| AC-2 | Access Control | Account management; enforce least privilege; no standing admin accounts |
| AC-3 | Access Control | Access enforcement; attribute-based and role-based access control |
| AC-17 | Access Control | Remote access control; replace VPN with ZTNA |
| IA-2 | Identification & Auth | Multi-factor authentication for all users; phishing-resistant MFA |
| IA-5 | Identification & Auth | Authenticator management; certificate-based device credentials |
| SC-7 | System & Comms | Boundary protection; microsegmentation; east-west traffic control |
| SC-8 | System & Comms | Transmission confidentiality and integrity; TLS 1.3, mTLS everywhere |
| SC-28 | System & Comms | Protection of information at rest; encryption for all sensitive data |
| SI-4 | System & Info Integrity | System monitoring; continuous monitoring of all assets and communications |
| CM-7 | Configuration Mgmt | Least functionality; disable legacy protocols; enforce minimum required services |

## ATT&CK Coverage

| Technique | ID | ZTA Defense |
|---|---|---|
| Valid Accounts | T1078 | Continuous auth, behavioral analytics, JIT privilege — limits utility of stolen credentials |
| Modify Authentication Process | T1556 | MFA enforcement, phishing-resistant FIDO2, monitoring IdP configuration changes |
| MFA Request Generation (Fatigue) | T1621 | Number matching MFA, FIDO2 hardware keys, anomaly detection on auth attempts |
| Steal Application Access Token | T1528 | Short-lived tokens, Continuous Access Evaluation (CAE), token binding |
| Use Alternate Authentication Material | T1550 | Device compliance checks, session binding, re-authentication on sensitive operations |
| Brute Force | T1110 | Account lockout, rate limiting, CAPTCHA, adaptive risk policies |
| Application Layer Protocol | T1071 | Layer 7 inspection at PEP; DPI on all traffic regardless of source |
| Steal Web Session Cookie | T1539 | FIDO2 passkeys (session-less), short token TTLs, device-bound sessions |

## Certifications

| Certification | Issuer | Level | Notes |
|---|---|---|---|
| **CCZT** (Certificate of Competence in Zero Trust) | Cloud Security Alliance (CSA) | Intermediate | Dedicated ZTA cert; highly recommended |
| **CISSP** | (ISC)² | Expert | Covers ZTA in Architecture domain; broad security |
| **CCSP** | (ISC)² | Expert | Cloud-focused; ZTA in cloud context |
| **CISM** | ISACA | Management | Governance-focused; ZTA strategy and risk |
| **CompTIA Security+** | CompTIA | Entry | ZTA concepts covered; good starting point |
| **CISA** | ISACA | Expert | ZTA in audit and governance context |
| **SC-900 / SC-100** | Microsoft | Entry/Expert | Microsoft-specific ZTA; Azure/Entra-focused |

## Learning Resources

| Resource | Type | Cost |
|---|---|---|
| [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf) | Standard/PDF | Free |
| [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model) | Guide | Free |
| [Google BeyondCorp Research Papers](https://research.google/pubs/?area=security-privacy-and-abuse-prevention) | Research | Free |
| John Kindervag "Build Security Into Your Network's DNA" | Original ZT paper (Forrester) | Free online |
| [Microsoft Zero Trust Adoption Framework](https://learn.microsoft.com/en-us/security/zero-trust/adopt/zero-trust-adoption-overview) | Guide | Free |
| [NSA Zero Trust Pillars Guidance Series](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/) | Advisory | Free |
| [Zero Trust Networks (O'Reilly Book)](https://www.oreilly.com/library/view/zero-trust-networks/9781492096580/) | Book | Paid |
| [Cloudflare Zero Trust Platform Docs](https://developers.cloudflare.com/cloudflare-one/) | Docs | Free |

## Related Disciplines

- [identity-and-access-management.md](identity-and-access-management.md)
- [cloud-security.md](cloud-security.md)
- [network-security.md](network-security.md)
- [endpoint-security.md](endpoint-security.md)
- [privileged-access-management.md](privileged-access-management.md)
- [siem-soar.md](siem-soar.md)
- [threat-modeling.md](threat-modeling.md)
