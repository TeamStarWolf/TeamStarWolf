# Security Architecture

Security architecture is the discipline of designing systems, networks, and applications so that security properties are built in from the start rather than bolted on afterward. A security architect translates business requirements and threat intelligence into structured frameworks, reference models, and design patterns that ensure confidentiality, integrity, and availability across the entire technology stack. The role spans cloud, on-premises, hybrid, and OT environments — and requires understanding both how systems are attacked and how to make that attack expensive, detectable, and recoverable.

Good security architecture is not just about controls — it is about making security a natural property of the system. It applies defense-in-depth, eliminates implicit trust, enforces least privilege structurally, and ensures that failures are contained rather than cascading.

## Where to Start

| Level | Description | Free Resource |
|-------|-------------|---------------|
| Beginner | Understand the core principles: CIA triad, defense-in-depth, least privilege, separation of duties, fail secure, economy of mechanism. Learn what a security reference architecture is and why it matters | [NIST SP 800-12: Introduction to Information Security](https://csrc.nist.gov/publications/detail/sp/800-12/rev-1/final) |
| Intermediate | Study threat modeling (STRIDE, PASTA, attack trees), network segmentation design, Zero Trust principles, and secure architecture review processes. Practice applying NIST SP 800-207 and reviewing cloud architecture diagrams | [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final) |
| Advanced | Master enterprise security architecture frameworks (SABSA, TOGAF security extension, Zachman), architect multi-cloud landing zones with security guardrails, conduct formal architecture risk assessments, and design privileged access architectures from scratch | [SABSA Foundation Guide (Free Chapter)](https://sabsa.org/sabsa-foundation-white-paper/) |

## Free Training

| Platform | URL | What You Learn |
|----------|-----|----------------|
| NIST Cybersecurity Framework Resources | https://www.nist.gov/cyberframework | Framework for organizing security program architecture |
| CISA Zero Trust Maturity Model | https://www.cisa.gov/zero-trust-maturity-model | ZTMM stages, pillar-by-pillar implementation guidance |
| Microsoft Security Architecture Documentation | https://docs.microsoft.com/en-us/security/ | Azure security reference architectures, PAW design, ESAE model |
| OWASP Threat Dragon | https://owasp.org/www-project-threat-dragon/ | Free threat modeling tool with DFD-based diagramming |
| AWS Security Reference Architecture | https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/ | AWS multi-account landing zone security design |
| Google Cloud Security Foundations | https://cloud.google.com/architecture/security-foundations | GCP landing zone security blueprint |
| SANS Reading Room (Architecture) | https://www.sans.org/reading-room/ | Research papers on network design, segmentation, and zero trust |

## Tools & Repositories

| Tool | Description | Link |
|------|-------------|-------|
| Microsoft Threat Modeling Tool | Free threat modeling tool supporting STRIDE methodology with DFD templates for Azure and on-premises architectures | https://aka.ms/threatmodelingtool |
| OWASP Threat Dragon | Open-source threat modeling with support for STRIDE, DFDs, and integration into CI/CD pipelines | https://github.com/OWASP/threat-dragon |
| IriusRisk Community | Automated threat modeling platform with a community edition supporting architecture-as-code threat models | https://github.com/iriusrisk |
| Lucidchart / draw.io (diagrams.net) | Open-source diagramming for architecture and DFD creation, exportable to threat modeling tools | https://github.com/jgraph/drawio |
| Checkov | Static analysis for infrastructure-as-code (Terraform, CloudFormation, Kubernetes) — enforces architectural security controls at design time | https://github.com/bridgecrewio/checkov |
| tfsec | Terraform security scanner that validates architecture configurations against CIS Benchmarks and best practices | https://github.com/aquasecurity/tfsec |
| Prowler | AWS/Azure/GCP security assessment tool that validates cloud architecture against CIS, NIST, and SOC2 controls | https://github.com/prowler-cloud/prowler |
| ScoutSuite | Multi-cloud security auditing tool for reviewing architecture posture across providers | https://github.com/nccgroup/ScoutSuite |
| Illumio (Core) | Microsegmentation platform for workload-level Zero Trust enforcement | https://www.illumio.com |
| Guardicore (now Akamai Segmentation) | Application-layer microsegmentation and lateral movement prevention | https://github.com/guardicore |

## Commercial Platforms

| Platform | Description |
|----------|-------------|
| Palo Alto Prisma Cloud | Cloud security posture management (CSPM), workload protection, and architecture compliance at scale |
| Microsoft Defender for Cloud | Multi-cloud security architecture assessment, secure score, and regulatory compliance mapping |
| Wiz | Agentless cloud security platform with a graph-based architecture model showing toxic combinations of risk |
| Orca Security | Cloud-native security posture management with full-stack architecture visibility |
| ThreatModeler | Enterprise threat modeling platform with architecture import and automated STRIDE analysis |
| IriusRisk Enterprise | Automated threat modeling and security requirements management integrated with SDLC |
| SABSA Certified Tools | Tools aligned with the SABSA enterprise security architecture framework for policy-to-control traceability |
| VMware NSX | Network virtualization platform enabling microsegmentation and software-defined security architecture |
| Zscaler Zero Trust Exchange | Cloud-native Zero Trust network access (ZTNA) architecture platform |
| BeyondCorp Enterprise (Google) | Identity-centric Zero Trust access architecture for enterprise workloads |

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---------|--------|-----------|
| PL-8 | Planning | Security and Privacy Architectures — requires documented security architecture aligned to organizational mission |
| SA-8 | System and Services Acquisition | Security Engineering Principles — mandates applying security design principles (fail secure, least privilege, minimization) |
| SA-14 | System and Services Acquisition | Criticality Analysis — identifying critical architecture components and their supply chain dependencies |
| SA-15 | System and Services Acquisition | Development Process, Standards, and Tools — security requirements in the SDLC including threat modeling |
| SA-17 | System and Services Acquisition | Developer Security and Privacy Architecture and Design — requiring vendors to produce formal security architecture documentation |
| SC-2 | System and Communications Protection | Separation of System and User Functionality — architectural separation of privileged and unprivileged processing |
| SC-3 | System and Communications Protection | Security Function Isolation — isolating security-enforcing functions from non-security functions at architectural level |
| SC-7 | System and Communications Protection | Boundary Protection — DMZ design, network segmentation, and inter-zone traffic control |
| SC-28 | System and Communications Protection | Protection of Information at Rest — data-layer encryption as an architectural control |
| CA-3 | Assessment, Authorization, and Monitoring | Information Exchange — documenting and approving system interconnections through architecture review |

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|-------------|------|--------|-----------|
| T1190 | Exploit Public-Facing Application | Initial Access | Flat perimeter architecture allows direct access to internal resources; DMZ/WAF design prevents this |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Implicit trust architectures make stolen credentials extremely powerful; Zero Trust limits blast radius |
| T1021 | Remote Services | Lateral Movement | Flat networks enable lateral movement; microsegmentation and ZTNA architecturally constrain it |
| T1133 | External Remote Services | Initial Access | VPN and remote access architectures with no MFA or segmentation are frequent initial access vectors |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Permissive egress architectures allow DNS/HTTPS/ICMP tunneling; architecture must enforce outbound filtering |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Lack of outbound TLS inspection and egress filtering enables C2 data theft |
| T1071 | Application Layer Protocol | Command and Control | C2 over HTTP/HTTPS blends into allowed traffic; architecture must include SSL inspection and behavioral egress controls |
| T1550 | Use Alternate Authentication Material | Defense Evasion | Pass-the-hash and pass-the-ticket attacks thrive in networks with implicit Kerberos trust; PAW and tiering prevent credential exposure |
| T1557 | Adversary-in-the-Middle | Credential Access | Unencrypted internal protocols (HTTP, LDAP, SMBv1) in flat networks expose credentials; architecture must encrypt internal traffic |
| T1530 | Data from Cloud Storage Object | Collection | Overly permissive cloud IAM architecture exposes storage; CSPM and least-privilege IAM guardrails prevent it |

## Security Architecture Patterns

**Defense-in-Depth Layers** (outer to inner):
1. **Perimeter** — Firewalls, IPS, DDoS scrubbing, WAF
2. **Network** — VLANs, microsegmentation, NAC, encrypted transit
3. **Endpoint** — EDR, application control, secure baseline, patch management
4. **Application** — Input validation, authentication, RBAC, SAST/DAST in CI/CD
5. **Data** — Encryption at rest and in transit, DLP, data classification
6. **Identity** — MFA, PAM, SSO, Zero Trust identity-centric access

**Key Design Patterns**:
- **Bastion Host / Jump Server**: Single hardened entry point into a protected network segment, with full logging
- **Privileged Access Workstation (PAW)**: Dedicated hardened workstation for administrative tasks, isolated from standard user browsing
- **DMZ Architecture**: Semi-trusted zone separating public-facing services from internal networks
- **Break-Glass Accounts**: Emergency standing-privilege accounts with alerting, MFA, and automated audit
- **API Gateway**: Centralized policy enforcement for all API traffic — authentication, rate limiting, logging
- **Reverse Proxy**: Hides internal application topology; provides WAF and TLS termination
- **Zero Trust Microsegmentation**: Deny-by-default workload-to-workload policy, identity-verified per session

## Certifications

| Certification | Issuer | Level | Notes |
|--------------|--------|-------|-------|
| CISSP | (ISC)² | Advanced | Domain 3 (Security Architecture) is core; covers security models, cryptography, and enterprise architecture |
| CCSP | (ISC)² | Advanced | Cloud security architecture focused; aligns with shared responsibility model and cloud-native security design |
| SABSA Chartered Security Architect (SCF) | SABSA Institute | Advanced | Premier enterprise security architecture credential using the SABSA framework |
| TOGAF 9 Certified | The Open Group | Intermediate | Enterprise architecture framework with security extensions; widely required for architecture roles |
| AWS Solutions Architect — Professional | AWS | Advanced | Cloud architecture with security specialization tracks |
| Google Professional Cloud Architect | Google | Advanced | GCP architecture including security controls and landing zone design |
| CISSP-ISSAP | (ISC)² | Advanced | Architecture concentration within CISSP for those specializing in security architecture |

## Learning Resources

| Resource | Type | Notes |
|----------|------|-------|
| *Security Engineering* — Ross Anderson (3rd ed.) | Book | Foundational textbook covering security architecture theory, protocols, and design — free online |
| *The TOGAF Standard* — The Open Group | Standard | Enterprise architecture framework with security extension; free registration download |
| NIST SP 800-207: Zero Trust Architecture | Standard | Definitive US government guidance on Zero Trust design principles and deployment models |
| SABSA Foundation Guide | Framework | SABSA enterprise security architecture methodology — risk-driven, business-aligned architecture |
| *Threat Modeling: Designing for Security* — Adam Shostack | Book | Authoritative guide to threat modeling methodology from the creator of the STRIDE process at Microsoft |
| *Designing Distributed Systems* — Brendan Burns | Book | Patterns and principles for distributed systems with security implications |
| CISA Zero Trust Maturity Model v2.0 | Guidance | Five-pillar ZTMM with maturity stages across identity, devices, networks, applications, and data |
| Microsoft Security Architecture Documentation | Online | PAW design, ESAE (red forest), tiered Active Directory model — directly applicable reference architectures |
| O-ESA: Open Enterprise Security Architecture | Framework | The Open Group's enterprise security architecture reference model |

#### Zero Trust Architecture (Deep Reference)

**CISA Zero Trust Maturity Model (ZTMM) — 5 Pillars**

| Pillar | Traditional | Advanced | Optimal |
|---|---|---|---|
| Identity | Per-app MFA | Risk-based adaptive MFA | Continuous identity validation, ML-driven behavior |
| Devices | MDM enrollment | Posture assessment per request | Automated response to anomalous device behavior |
| Networks | VPN-based perimeter | Microsegmentation | Application-level access, dynamic policy |
| Applications | Monolithic firewall rules | Application-layer access controls | Zero implicit trust, continuous validation per session |
| Data | Perimeter protection | Data classification, DLP at perimeter | Data-centric controls, automated classification, encryption everywhere |

**Zero Trust Architecture Principles (NIST SP 800-207)**
1. All data sources and computing services are treated as resources
2. All communication is secured regardless of network location
3. Access to individual resources is granted per-session
4. Access policy is determined dynamically from client identity + posture + other attributes
5. Monitor all assets and communications for integrity and security posture
6. Authentication and authorization are dynamic and strictly enforced before access

**Reference Architecture — ZTNA Implementation**
- Identity Provider (IdP): Okta, Azure AD / Entra ID, Ping Identity
- Device trust: Intune, Jamf, CrowdStrike Falcon Device Control
- ZTNA gateway: Zscaler Private Access, Cloudflare Access, Palo Alto Prisma Access
- Microsegmentation: Illumio, Guardicore, NSX-T
- Continuous verification: SIEM integration for anomaly-triggered step-up auth

#### Threat Modeling

**STRIDE Methodology**

| Threat | Description | Mitigation |
|---|---|---|
| Spoofing | Pretending to be someone else | Authentication, certificates |
| Tampering | Modifying data or code | Integrity checks, signing, HMAC |
| Repudiation | Denying actions | Non-repudiation logging, audit trails |
| Information Disclosure | Unauthorized data access | Encryption, authorization |
| Denial of Service | Preventing legitimate access | Rate limiting, redundancy, DDoS protection |
| Elevation of Privilege | Gaining unauthorized permissions | Least privilege, authorization enforcement |

**PASTA (Process for Attack Simulation and Threat Analysis)**

7-stage methodology: Define objectives → Define technical scope → Decompose application → Analyze threats → Identify vulnerabilities → Enumerate attacks → Risk/impact analysis

**Threat Modeling Tools**
- Microsoft Threat Modeling Tool (free): DFD-based, STRIDE auto-generation
- OWASP Threat Dragon (free): Cross-platform, DFD + STRIDE
- IriusRisk: Commercial, integrates with Jira/CI pipeline
- Trike: Risk-based, actor-goal decomposition
- pytm: Threat model as code (Python library)

#### Security Architecture Patterns (Extended)

**Defense in Depth Layers**
1. Perimeter: NGFW, WAF, DDoS protection, IPS
2. Network: Segmentation, VLAN, microsegmentation, IDS/IPS sensors
3. Identity: MFA, PAM, JIT access, directory services
4. Endpoint: EDR, AV, application allowlisting, disk encryption
5. Application: SAST/DAST/SCA, WAF, API gateway
6. Data: Encryption at rest/in transit, DLP, data classification
7. Detection/Response: SIEM, SOAR, MDR/XDR

**Reference Architectures**
- NIST SP 800-207: Zero Trust Architecture
- CIS Critical Security Controls v8: 18 controls with implementation groups
- SABSA (Sherwood Applied Business Security Architecture): Business-driven layered model
- TOGAF: Enterprise architecture with security as domain
- Google BeyondCorp: Original zero trust implementation, white papers available

**Secure-by-Design Principles**
- Least privilege: Minimum access required for function
- Separation of duties: No single person can complete sensitive task alone
- Defense in depth: Multiple independent controls — failure of one doesn't compromise system
- Economy of mechanism: Simple designs are easier to analyze and trust
- Fail secure: Failures deny access rather than grant it
- Open design: Security through obscurity is not security
- Complete mediation: Every access checked against policy every time

#### Security Architecture Certifications (Extended)

| Cert | Body | Focus | Level |
|---|---|---|---|
| SABSA Foundation/Practitioner | SABSA Institute | Business-driven security architecture | Practitioner |
| CISSP — Architecture domain | ISC2 | Broad with architecture emphasis | Senior |
| CISA | ISACA | IS audit/control systems | Mid-senior |
| AWS/Azure/GCP Security specialty | Cloud providers | Cloud-native architecture | Mid |
| Google ZTNA certification | Google | Zero Trust implementation | Specialist |

---

## Related Disciplines

- [Zero Trust Architecture](zero-trust-architecture.md)
- [Threat Modeling](threat-modeling.md)
- [Cloud Security](cloud-security.md)
- [Network Security](network-security.md)
- [Identity Access Management](identity-access-management.md)
- [Governance Risk Compliance](governance-risk-compliance.md)
- [DevSecOps](devsecops.md)
