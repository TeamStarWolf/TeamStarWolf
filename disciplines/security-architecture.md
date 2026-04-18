# Security Architecture

Security architecture is the discipline of designing systems, networks, and applications so that security properties are built in from the start rather than bolted on afterward. A security architect translates threat models and risk assessments into structural decisions: network segmentation, identity trust boundaries, encryption in transit and at rest, defense-in-depth layering, and Zero Trust access design. Security architects operate at the intersection of business requirements, threat landscape, and technical feasibility — they define the "why" behind control selection that GRC practitioners then formalize and blue teams then operationalize.

---

## Where to Start

Security architecture is a discipline you grow into — it requires broad technical knowledge plus the ability to reason about adversary behavior. Start with threat modeling (STRIDE) and Zero Trust principles, then build toward the formal architectural frameworks.

1. Learn STRIDE threat modeling using [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
2. Read the [NIST SP 800-207 — Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final) — the authoritative ZTA reference
3. Work through the [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) to understand architecture-level application security requirements
4. Study the [Cloud Security Alliance (CSA) Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/) for cloud architecture patterns
5. Review [SABSA Foundation materials](https://sabsa.org/sabsa-executive-summary/) — the leading enterprise security architecture framework
6. Map your architecture decisions to controls using the [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/)

---

## Free Training

| Resource | What You Learn |
|---|---|
| [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) | STRIDE, PASTA, attack trees — structured threat analysis methodologies |
| [Microsoft Security Architecture Videos](https://learn.microsoft.com/en-us/security/zero-trust/) | Zero Trust implementation patterns for Microsoft environments |
| [Google BeyondCorp Research](https://research.google/pubs/pub43231/) | The original Zero Trust case study from Google — highly readable |
| [NIST SP 800-207 — Zero Trust Architecture (free)](https://csrc.nist.gov/publications/detail/sp/800-207/final) | NIST's definitive ZTA model and deployment patterns |
| [CSA Security Guidance for Cloud v4](https://cloudsecurityalliance.org/artifacts/security-guidance-v4/) | Cloud architecture security across 14 domains — free download |
| [Antisyphon: Active Defense & Threat Hunting](https://www.antisyphontraining.com) | BHIS architectural defense and deception content — PWYW |
| [SEI Architecture Tradeoff Analysis Method (ATAM)](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=513908) | CMU SEI methodology for architecture evaluation |
| [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) | Cloud-native security architecture patterns from AWS |

---

## Tools & Repositories

### Threat Modeling

| Tool | Purpose | Link |
|---|---|---|
| **OWASP Threat Dragon** | Open-source threat modeling with STRIDE — browser-based and desktop | [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) |
| **Pytm** | Pythonic threat modeling framework — define systems as code, generate DFDs and threat reports | [izar/pytm](https://github.com/izar/pytm) |
| **Threagile** | Agile threat modeling as code — YAML-based system definition, auto-generates risk reports | [Threagile/threagile](https://github.com/Threagile/threagile) |
| **Attack Tree Analyzer** | Formal attack tree analysis for security architecture decisions | [ATAnalyzer](https://github.com/kbrindley/ata) |

### Architecture Diagramming & Analysis

| Tool | Purpose | Link |
|---|---|---|
| **draw.io / diagrams.net** | Free architecture diagramming — security zone diagrams, network topology, data flows | [diagrams.net](https://www.diagrams.net/) |
| **Structurizr** | Architecture-as-code using C4 model — generates diagrams from code | [structurizr/structurizr-java](https://github.com/structurizr/structurizr-java) |
| **PlantUML** | Text-based UML and architecture diagrams including threat models | [plantuml/plantuml](https://github.com/plantuml/plantuml) |

### Zero Trust & Network Segmentation

| Tool | Purpose | Link |
|---|---|---|
| **Open Policy Agent (OPA)** | Policy-as-code for Zero Trust authorization decisions | [open-policy-agent/opa](https://github.com/open-policy-agent/opa) |
| **Cilium / eBPF** | Network segmentation and microsegmentation at kernel level for Kubernetes | [cilium/cilium](https://github.com/cilium/cilium) |
| **Istio** | Service mesh providing Zero Trust mTLS between microservices | [istio/istio](https://github.com/istio/istio) |

### Security Validation

| Tool | Purpose | Link |
|---|---|---|
| **MITRE ATT&CK Navigator** | Map architectural controls to ATT&CK coverage — validate defense-in-depth | [mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) |
| **ScoutSuite** | Multi-cloud security auditing — validates cloud architecture against best practices | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) |
| **Prowler** | AWS/Azure/GCP security best practices assessment | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |

---

## Commercial & Enterprise Platforms

| Platform | Category | Key Capabilities |
|---|---|---|
| **Microsoft Threat Modeling Tool** | Threat Modeling | Free Microsoft tool using STRIDE methodology — integrates with Azure architectures |
| **IriusRisk** | Automated Threat Modeling | Codifies architecture security requirements, integrates with Jira and CI/CD pipelines |
| **ThreatModeler** | Enterprise Threat Modeling | Visual process flow diagramming with automated STRIDE analysis and compliance mapping |
| **Zscaler Zero Trust Exchange** | Zero Trust Architecture Platform | ZTNA, CASB, cloud proxy, microsegmentation — full ZT architecture implementation |
| **Illumio** | Microsegmentation | Workload-level segmentation without hardware changes — maps application traffic and enforces least-privilege connectivity |
| **Guardicore (Akamai)** | Microsegmentation | Application-layer segmentation and east-west traffic control |
| **HashiCorp Vault** | Secrets & Identity Management | Centralized secrets management as an architecture primitive — encryption as a service |
| **Tufin Orchestration Suite** | Network Security Policy Management | Firewall rule lifecycle management and security policy automation across complex environments |
| **FireMon** | Security Policy Management | Real-time network security policy analysis, risk assessment, and compliance |
| **AWS Security Hub / Azure Security Center / GCP Security Command Center** | Cloud Security Posture | Native cloud platforms for architecture-level security assessment and posture management |

---

## Frameworks & Architecture Standards

| Framework | Focus | Link |
|---|---|---|
| **SABSA** | Enterprise security architecture — business-driven, attribute-based | [sabsa.org](https://sabsa.org) |
| **TOGAF** | Enterprise architecture — security is one domain | [opengroup.org/togaf](https://www.opengroup.org/togaf) |
| **NIST SP 800-207** | Zero Trust Architecture | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-207/final) |
| **OWASP ASVS** | Application security architecture verification | [owasp.org/asvs](https://owasp.org/www-project-application-security-verification-standard/) |
| **CSA CCM v4** | Cloud security architecture controls matrix | [cloudsecurityalliance.org](https://cloudsecurityalliance.org/research/cloud-controls-matrix/) |
| **NIST SP 800-160** | Engineering trustworthy secure systems | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-160/vol-1-rev-1/final) |
| **CIS Benchmarks** | System hardening baselines for architecture configuration | [cisecurity.org](https://www.cisecurity.org/cis-benchmarks) |
| **Google BeyondCorp** | Zero Trust enterprise access model | [cloud.google.com/beyondcorp](https://cloud.google.com/beyondcorp) |

---

## Books & Learning

| Resource | Focus |
|---|---|
| *Security Engineering* — Ross Anderson | The definitive textbook on security architecture — covers cryptography, protocols, systems, and human factors |
| *Zero Trust Networks* — Gilman & Barth | Practical Zero Trust implementation guide — network, identity, device, and application layers |
| *Threat Modeling: Designing for Security* — Adam Shostack | The standard threat modeling book — STRIDE, attack trees, DFDs by the creator of Microsoft's SDL |
| *Building Secure and Reliable Systems* — Google | Google SRE perspective on security architecture — free online |
| *The SABSA Practitioner Handbook* — SABSA Institute | Reference for SABSA enterprise security architecture framework |
| *Cloud Security Alliance Security Guidance v4* — CSA | Free 200-page cloud architecture security reference |
| *Hacking: The Art of Exploitation* — Jon Erickson | Understanding how systems fail — essential context for defensive architecture |

---

## Certifications

| Certification | Issuer | What It Validates |
|---|---|---|
| **CISSP-ISSAP** — Information Systems Security Architecture Professional | ISC² | Advanced security architecture concentration within CISSP — requires existing CISSP |
| **SABSA Chartered Security Architect (SCF/SCM/SCP)** | SABSA Institute | Enterprise security architecture using the SABSA business-driven methodology |
| **CCSP** — Certified Cloud Security Professional | ISC² | Cloud architecture security across IaaS, PaaS, SaaS — broadly recognized |
| **TOGAF 9 / 10 Certified** | The Open Group | Enterprise architecture (with security as a domain) |
| **Google Professional Cloud Security Engineer** | Google | GCP-specific architecture security — ZTA, IAM, VPC design |
| **AWS Certified Security — Specialty** | Amazon | AWS architecture security including network, identity, data protection design |
| **Microsoft Azure Security Engineer Associate (AZ-500)** | Microsoft | Azure architecture security — IAM, Zero Trust, network security design |
| **CISSP** | ISC² | Broad security knowledge foundational to architecture conversations |

---

## YouTube Channels

| Channel | Focus |
|---|---|
| [Microsoft Security](https://www.youtube.com/@MicrosoftSecurity) | Zero Trust, Azure security architecture, identity design patterns |
| [Google Cloud Tech](https://www.youtube.com/@googlecloudtech) | GCP security architecture, BeyondCorp, cloud-native security |
| [AWS Events](https://www.youtube.com/@AWSEventsChannel) | AWS re:Invent security architecture sessions |
| [SANS Institute](https://www.youtube.com/user/SANSInstitute) | Security architecture and defense-in-depth content from practitioners |

---

## Who to Follow

| Handle | Focus |
|---|---|
| [@adoxographer](https://twitter.com/adoxographer) | Zero Trust, identity architecture, modern enterprise security design |
| [@SwiftOnSecurity](https://twitter.com/SwiftOnSecurity) | Security architecture, policy, pragmatic defense design |
| [@sounilyu](https://twitter.com/sounilyu) | Cyber defense matrix, security architecture frameworks |
| [@0xDUDE](https://twitter.com/0xDUDE) | Application security architecture and threat modeling |
| [@Wietze](https://twitter.com/Wietze) | Hardening, LOLBins, configuration-based defense — architecture implications |

---

## Key Resources

- [NIST SP 800-207 — Zero Trust Architecture (free PDF)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Google BeyondCorp Papers](https://cloud.google.com/beyondcorp#resources)
- [SABSA Institute](https://sabsa.org)
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [CSA Cloud Controls Matrix v4](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
- [CTID Mappings Explorer — Map Controls to ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/)
- [TeamStarWolf Security Pipeline](../SECURITY_PIPELINE.md) — Architecture decisions in the enterprise lifecycle context
