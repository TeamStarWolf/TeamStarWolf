# Zero Trust Architecture

Zero Trust Architecture (ZTA) is a security model and strategy built on the principle of "never trust, always verify." Unlike traditional perimeter-based security, Zero Trust grants no implicit trust based on network location — whether inside or outside a corporate network. Every access request is explicitly authenticated, authorized, and continuously validated regardless of origin. Zero Trust is distinct from Security Architecture (the broader discipline) and Network Security (which addresses one layer of a ZT implementation); ZTA is a cross-cutting model that touches identity, devices, applications, data, and infrastructure simultaneously.

The model was formalized by John Kindervag at Forrester Research and has since been codified by NIST (SP 800-207), CISA (Zero Trust Maturity Model), the Department of Defense (ZT Reference Architecture), and major cloud providers. The practical driver for adoption is the collapse of the traditional network perimeter: remote work, SaaS, multi-cloud, and BYOD have made "inside the network = trusted" untenable. Zero Trust replaces that assumption with continuous verification at every layer.

The three core ZT principles are: **Verify explicitly** — always authenticate and authorize using all available data points including identity, location, device health, service or workload, data classification, and anomalies; **Use least privilege access** — limit user access with just-in-time and just-enough-access, risk-based adaptive policies, and data protection; **Assume breach** — minimize blast radius and segment access, encrypt end-to-end, use analytics to get visibility and drive threat detection.

---

## Where to Start

Zero Trust implementation is more architectural and strategic than most disciplines. Start with NIST SP 800-207 to understand the formal model, then work through a cloud provider's ZT framework (Microsoft or Google) to see how it maps to real products. Hands-on practice comes through configuring Conditional Access policies, ZTNA solutions, and microsegmentation — not through CTFs.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | NIST SP 800-207 ZTA principles, CISA ZTMM pillars, identity as the new perimeter, Conditional Access concepts, difference between VPN and ZTNA | NIST SP 800-207 (free), Microsoft Zero Trust documentation (free), CISA ZTMM (free) |
| Practitioner | Deploying Conditional Access policies, configuring ZTNA (Zscaler ZPA / Cloudflare Access), device posture integration, microsegmentation design, continuous monitoring | Microsoft Learn SC-900 / AZ-500 labs, Cloudflare One free tier, Tailscale homelab, Okta developer sandbox |
| Advanced | Multi-pillar ZT roadmap development, DoD ZT Reference Architecture mapping, ZTMM maturity assessment, ZT for OT/ICS environments, automating posture-based access decisions | DoD ZT Reference Architecture, CISA ZTMM assessment tooling, SANS ZT-focused webcasts, enterprise ZT design workshops |

---

## ZT Pillars (CISA Model)

CISA's Zero Trust Maturity Model organizes ZT implementation across six pillars, each with four maturity levels: Traditional, Initial, Advanced, and Optimal.

| Pillar | Description |
|---|---|
| **Identity** | All human and non-human identities are validated; strong MFA, continuous authentication, and identity governance |
| **Devices / Endpoints** | Device health and compliance is verified before granting access; MDM, EDR posture checks, certificate-based device identity |
| **Applications / Workloads** | Application-layer access controls; application segmentation, API security, privileged access to workloads |
| **Data** | Data classification, labeling, and protection at rest and in transit; data-centric access policies |
| **Networks / Infrastructure** | Microsegmentation replaces flat networks; encrypt all traffic, limit lateral movement, software-defined perimeters |
| **Visibility / Analytics / Automation** | Continuous monitoring, behavioral analytics, SIEM/SOAR integration, automated policy enforcement |

---

## Free Training & Frameworks

- [NIST SP 800-207 Zero Trust Architecture](https://doi.org/10.6028/NIST.SP.800-207) — The authoritative NIST definition of ZTA; covers logical components, deployment models, and migration strategies; the foundational reference for any ZT program
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model) — CISA's six-pillar ZT maturity model for federal agencies; broadly applicable for any enterprise ZT program; free PDF and assessment guidance
- [Microsoft Zero Trust Documentation](https://learn.microsoft.com/en-us/security/zero-trust/) — Microsoft's comprehensive ZT guidance covering identity, endpoints, applications, data, and infrastructure; directly maps to Entra ID and Microsoft security products
- [Google BeyondCorp Enterprise](https://cloud.google.com/beyondcorp) — Google's real-world ZT implementation that influenced the entire industry; enterprise docs and original research papers are freely available
- [DoD Zero Trust Reference Architecture](https://dodcio.defense.gov/Portals/0/Documents/Library/(U)ZT_RA_v2.0(U)_Sep22.pdf) — DoD's detailed ZT reference architecture; most prescriptive public ZT framework available; valuable even outside federal contexts
- [John Kindervag's Original ZT Research](https://www.forrester.com/report/no-more-chewy-centers-introducing-the-zero-trust-model-of-information-security/RES56682) — The Forrester report that defined Zero Trust; foundational reading to understand the original model and intent
- [Microsoft SC-900 Learning Path](https://learn.microsoft.com/en-us/certifications/exams/sc-900) — Free Microsoft training covering Zero Trust fundamentals, Entra ID, and security concepts; approachable entry point with free practice labs

---

## Tools & Repositories

### Open Source ZTNA & Proxies
- [OpenZiti](https://github.com/openziti/ziti) — Open-source zero trust overlay networking; provides application-embedded zero trust connectivity without requiring network changes; the leading OSS zero trust networking project
- [Pomerium](https://github.com/pomerium/pomerium) — Open-source identity-aware access proxy; provides ZT application access with context-aware policy enforcement; self-hostable alternative to commercial ZTNA for internal applications
- [Tailscale](https://github.com/tailscale/tailscale) — WireGuard-based mesh VPN with zero trust properties; device certificate authentication, ACL-based access controls, and audit logging; strong for homelab and SMB ZT implementation

### Policy & Secrets
- [open-policy-agent/opa](https://github.com/open-policy-agent/opa) — Policy-as-code engine used in ZT implementations for application-layer authorization decisions; Kubernetes admission, API gateway policy enforcement
- [hashicorp/vault](https://github.com/hashicorp/vault) — Secrets management and dynamic credentials; core to ZT infrastructure by eliminating static credentials and enabling just-in-time access provisioning

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **Microsoft Entra ID (Conditional Access)** | Identity pillar of ZT for Microsoft environments; Conditional Access policies enforce MFA, device compliance, location, and risk signals before granting access to any resource; the most widely deployed ZT identity control plane |
| **Okta Adaptive MFA / Okta Identity Cloud** | Identity-as-a-Service with adaptive MFA and contextual access policies; supports any cloud or on-premises app; the leading independent identity platform for ZT |
| **Zscaler Zero Trust Exchange (ZPA / ZIA)** | The market-defining ZTNA platform; ZPA replaces VPN with identity and posture-based application access; ZIA provides SWG; full SASE architecture built on ZT principles |
| **Cloudflare Access (Cloudflare One)** | ZTNA and SASE platform built on Cloudflare's global network; application-level access control with identity, device, and context-based policies; accessible free tier makes it practical for smaller organizations |
| **Palo Alto Prisma Access** | SASE and ZTNA from Palo Alto; integrates with Prisma Cloud and Cortex for full ZT stack across network, cloud, and endpoint; strongest for organizations on the Palo Alto platform |
| **Cisco Duo** | MFA and device trust platform; device health attestation for ZT device pillar; widely deployed in enterprise environments; strong integration with Cisco network infrastructure |
| **Google BeyondCorp Enterprise** | Google's production ZT platform based on BeyondCorp principles; context-aware access for GCP and SaaS applications; native integration with Google Workspace and Chrome Browser |
| **CrowdStrike Falcon (Device Posture)** | EDR-derived device health signals for ZT device trust decisions; integrates with ZTNA platforms to enforce access based on real-time endpoint security posture |
| **Illumio** | Microsegmentation platform for ZT network pillar; application dependency mapping and workload-level segmentation across on-premises and cloud; leader in enterprise microsegmentation |
| **Guardicore (Akamai Guardicore Segmentation)** | Software-defined microsegmentation; granular east-west traffic control with process-level visibility; acquired by Akamai for integration with their network security portfolio |

---

## NIST 800-53 Controls

| Control | Description |
|---|---|
| AC-2 | Account Management — enforce identity lifecycle controls foundational to the identity pillar |
| AC-3 | Access Enforcement — enforce approved authorizations for logical access; direct ZT policy enforcement |
| AC-6 | Least Privilege — restrict user and process access to only what is required; core ZT principle |
| AC-17 | Remote Access — control and monitor remote access methods; replace VPN with ZTNA |
| CA-7 | Continuous Monitoring — ongoing assessment of security controls; maps to ZT visibility pillar |
| CM-7 | Least Functionality — disable unnecessary functions and ports; device and workload ZT hardening |
| IA-2 | Identification and Authentication — multi-factor authentication for all users; ZT identity pillar |
| IA-5 | Authenticator Management — manage and protect credentials; ZT identity credential lifecycle |
| SC-7 | Boundary Protection — monitor and control traffic at network boundaries; ZT network pillar |
| SI-4 | Information System Monitoring — monitor for attacks and unauthorized activity; ZT visibility pillar |

---

## ATT&CK Coverage

Zero Trust Architecture directly mitigates techniques that exploit implicit trust, lateral movement, and weak authentication.

| Technique | ID | ZT Mitigation |
|---|---|---|
| Valid Accounts | T1078 | MFA enforcement and Conditional Access deny access even with valid stolen credentials |
| Remote Services | T1021 | ZTNA replaces broad network access; each service requires explicit policy-based authorization |
| Use Alternate Auth Material | T1550 | Device posture checks and certificate-based authentication block pass-the-hash and pass-the-ticket |
| External Remote Services | T1133 | ZTNA replaces VPN; application-level access policies eliminate broad network entry points |
| Network Sniffing | T1040 | Microsegmentation and end-to-end encryption limit lateral visibility and traffic interception |
| Proxy | T1090 | Continuous identity and device verification detects anomalous routing and proxy-based evasion |
| Application Layer Protocol | T1071 | Microsegmentation and application-layer ZT policies restrict legitimate protocol abuse for lateral movement |

---

## Certifications

- **CCZT** (Certified Zero Trust Professional — Zero Trust Certification Organization / ZCOE) — The only certification dedicated specifically to Zero Trust; covers ZT principles, pillars, and implementation; credential for ZT architects and practitioners
- **CISSP** (Certified Information Systems Security Professional — ISC2) — Security architecture domain covers ZT concepts; the standard credential for security architects implementing ZT programs
- **Microsoft SC-900** (Security, Compliance, and Identity Fundamentals) — Entry-level Microsoft ZT certification; covers Entra ID, Conditional Access, and ZT fundamentals; strong starting point for the identity pillar
- **Microsoft AZ-500** (Azure Security Engineer Associate) — Practical Azure ZT implementation: Entra ID Conditional Access, Privileged Identity Management, Defender for Cloud; required for Azure ZT roles
- **CCNP / CCIE Security** (Cisco) — Network security certifications covering Cisco ZT and SASE implementations; valuable for network-layer ZT deployment
- **PCNSE** (Palo Alto Networks Certified Network Security Engineer) — Covers Prisma Access and ZT architecture on the Palo Alto platform

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Zero Trust Networks | Evan Gilman & Doug Barth | The definitive book on ZT network architecture; device identity, trust scoring, and control plane design; essential reading before implementing network-layer ZT |
| Project Zero Trust | George Finney | Practical ZT implementation narrative; covers organizational change management and phased rollout; useful for practitioners leading ZT adoption programs |
| Zero Trust Security | Jason Garbis & Jerry W. Chapman | Comprehensive ZT implementation guide covering all six pillars with practical architecture guidance and enterprise case studies |

---

## Key Resources

- [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207) — Authoritative NIST Zero Trust Architecture standard; defines ZT components, tenets, and implementation approaches
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model) — Six-pillar maturity model with four levels per pillar; the most actionable ZT assessment framework available
- [Microsoft Zero Trust Deployment Center](https://learn.microsoft.com/en-us/security/zero-trust/deploy/overview) — Step-by-step ZT deployment guidance for Microsoft environments covering all six pillars
- [BeyondCorp: A New Approach to Enterprise Security](https://research.google/pubs/beyondcorp-a-new-approach-to-enterprise-security/) — Google's original BeyondCorp paper; the real-world implementation that validated ZT at global scale
- [DoD Zero Trust Reference Architecture v2.0](https://dodcio.defense.gov/Portals/0/Documents/Library/(U)ZT_RA_v2.0(U)_Sep22.pdf) — The most detailed publicly available ZT reference architecture; prescriptive guidance applicable beyond federal environments
- [Forrester Zero Trust eXtended (ZTX) Framework](https://www.forrester.com/report/the-zero-trust-extended-ztx-ecosystem/RES137210) — Forrester's expansion of the original ZT model across seven pillars; the framework most commercial vendors align their marketing to

---

## Related Disciplines

- [Network Security](/disciplines/network-security) — ZT network pillar; microsegmentation, network access control, and east-west traffic inspection
- [Identity & Access Management](/disciplines/identity-access-management) — ZT identity pillar; the most critical ZT pillar and the primary implementation starting point
- [Cloud Security](/disciplines/cloud-security) — ZT in cloud environments; Conditional Access, workload identity, and CSPM align directly with ZT principles
- [Security Architecture](/disciplines/security-architecture) — ZTA is a security architecture framework; architectural skills and design patterns are prerequisites
- [DevSecOps](/disciplines/devsecops) — ZT for workloads and pipelines; workload identity, secrets management, and CI/CD access controls
