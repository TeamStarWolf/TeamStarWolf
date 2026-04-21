# Threat Modeling

## Introduction

Threat modeling is a structured approach to identifying threats, attack vectors, and mitigations during the **design phase** of a system — before code is written. The goal is to answer four key questions:

1. **What are we building?** (System decomposition)
2. **What can go wrong?** (Threat identification)
3. **What are we going to do about it?** (Mitigations)
4. **Did we do a good enough job?** (Validation)

It is far cheaper to fix a design flaw before implementation than to retrofit security after deployment. Threat modeling shifts security left — it belongs in the architecture phase, not the penetration testing phase.

Threat modeling produces actionable security requirements, guides architecture decisions, informs penetration test scope, and provides audit evidence for compliance programs.

## Where to Start

1. **Read Adam Shostack's "Threat Modeling: Designing for Security"** — the definitive practitioner book
2. **Learn STRIDE** — the most widely used methodology; easy to apply immediately
3. **Install OWASP Threat Dragon** — free, open-source tool; draw your first DFD
4. **Model a simple system you know** — a login flow, a REST API, an internal web app
5. **Practice STRIDE-per-Element** — apply each threat category to each DFD element systematically
6. **Integrate into your SDLC** — threat modeling at architecture review gates before implementation begins

## Free Training

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — free, practical reference
- [OWASP Threat Dragon](https://www.owasp.org/www-project-threat-dragon/) — free open-source threat modeling tool
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) — free Windows tool with STRIDE templates
- [SAFECode Threat Modeling Guides](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf) — free PDF, industry best practices
- [Adam Shostack's Elevation of Privilege Card Game](https://shostack.org/games/elevation-of-privilege) — free PDF; STRIDE as a card game; great for team workshops
- [LINDDUN Privacy Threat Modeling](https://linddun.org/) — free; privacy-focused threat modeling website and guides
- [Threagile Threat Modeling as Code](https://threagile.io/) — free open source; threat modeling from YAML
- [Carnegie Mellon SEI STRIDE Guidance](https://resources.sei.cmu.edu/) — free research papers

## Tools & Repositories

### Threat Modeling Tools
| Tool | Type | Description |
|---|---|---|
| [OWASP Threat Dragon](https://www.owasp.org/www-project-threat-dragon/) | Open source | DFD-based; desktop + web; STRIDE support; exports to JSON |
| [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) | Free (Windows) | STRIDE templates; Azure architecture stencils; TMT file format |
| [Threagile](https://threagile.io/) | Open source | Threat modeling as code; YAML input; risk report + DFD output; CI/CD integration |
| [IriusRisk Community](https://community.iriusrisk.com/) | Free/Commercial | Collaborative; STRIDE, OWASP, PASTA; threat library; requirements generation |
| [draw.io](https://draw.io/) | Free | General diagramming; DFD shapes available; export to OWASP Threat Dragon |
| [Lucidchart](https://lucidchart.com/) | Freemium | Collaborative DFDs; team-friendly; export options |

### Attack Tree Tools
| Tool | Type | Description |
|---|---|---|
| [ADTool](https://satoss.uni.lu/members/piotr/adtool/) | Open source | Attack-Defense trees; probability and cost annotations |
| [Attack Tree modeler (SecurITree)](https://www.amenaza.com/) | Commercial | Bruce Schneier-style attack trees; quantitative risk |
| [draw.io with Attack Tree template](https://draw.io/) | Free | Manual attack tree construction with tree shapes |

### Threat Intelligence & Threat Libraries
| Resource | Description |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Comprehensive adversary tactic/technique library for threat enumeration |
| [CAPEC (Common Attack Pattern Enumeration and Classification)](https://capec.mitre.org/) | MITRE's attack pattern catalog; maps to CWE weaknesses |
| [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) | Software weaknesses taxonomy; foundational for threat modeling |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Web application threat reference |
| [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) | API-specific threat reference |

## Commercial Platforms

| Platform | Description |
|---|---|
| **IriusRisk** | Collaborative, enterprise-grade; STRIDE, PASTA, OWASP; integrates with Jira, GitHub; auto-generates security requirements and countermeasures |
| **ThreatModeler** | Automated threat identification; process flow diagramming; compliance mapping; DevSecOps integration |
| **SD Elements (Security Compass)** | Survey-based threat model generation; outputs security requirements mapped to code frameworks; strong compliance focus |
| **Cairis** | Open-source/commercial academic tool; rich model including personas, environments, goals; good for systems security engineering |
| **Tutamen** | Threat model management and tracking; integrates with issue trackers |

## STRIDE Methodology (Microsoft)

STRIDE is the most widely adopted threat modeling methodology. It provides a mnemonic for six threat categories, each targeting a different security property.

| Threat | Property Violated | Example | Primary Mitigations |
|---|---|---|---|
| **S**poofing | Authentication | Attacker fakes user identity via stolen credentials | MFA, certificate-based auth, FIDO2 |
| **T**ampering | Integrity | MITM modifies API request payload in transit | Digital signatures, HMAC, HTTPS/TLS, input validation |
| **R**epudiation | Non-repudiation | User denies placing fraudulent order; no audit trail | Audit logging, digital signatures, non-repudiation controls |
| **I**nformation Disclosure | Confidentiality | Stack trace exposes internal server paths and versions | Error handling, encryption, data classification, least privilege |
| **D**enial of Service | Availability | SYN flood makes web server unresponsive | Rate limiting, DDoS protection, redundancy, circuit breakers |
| **E**levation of Privilege | Authorization | SQL injection leads to OS command execution | Authorization checks, input validation, least privilege, sandboxing |

### STRIDE-per-Element Approach

Rather than brainstorming threats generally, apply STRIDE systematically to each DFD element:

| DFD Element | Primary STRIDE Threats | Reasoning |
|---|---|---|
| **External Entity** (user, third party) | Spoofing, Repudiation | Entities can be impersonated; their actions may be denied |
| **Data Flow** (arrow between elements) | Tampering, Information Disclosure | Data in motion can be modified or intercepted |
| **Process** (application component) | All six (STRIDE) | Processes can be attacked in any way |
| **Data Store** (database, file system, cache) | Tampering, Information Disclosure, Denial of Service | Data can be modified, exfiltrated, or made unavailable |
| **Trust Boundary crossing** | All threats increase at boundaries | Every boundary crossing is a potential threat surface |

## PASTA (Process for Attack Simulation and Threat Analysis)

PASTA is a risk-centric, seven-stage methodology that connects technical threats to business objectives and quantifies risk. It is more comprehensive than STRIDE and appropriate for mature security programs.

| Stage | Activity | Output |
|---|---|---|
| 1. Define Business Objectives | Identify business context, compliance requirements, risk tolerance | Business impact register |
| 2. Define Technical Scope | Architecture review; identify technical components and dependencies | System inventory, architecture diagrams |
| 3. Application Decomposition | Identify trust boundaries, entry points, assets, use cases | DFD Level 0 and Level 1; asset register |
| 4. Threat Analysis | Threat agent profiling; correlate with threat intelligence and attack libraries | Threat agent profiles; threat event list |
| 5. Vulnerability & Weakness Analysis | SAST/DAST results; CVE correlation; design weakness review | Vulnerability list mapped to threats |
| 6. Attack Modeling | Attack tree construction per threat scenario | Attack trees; attack path analysis |
| 7. Risk & Impact Analysis | Business risk quantification; countermeasure cost-benefit analysis | Risk register; prioritized mitigations |

## LINDDUN (Privacy Threat Modeling)

LINDDUN is the privacy-focused analog to STRIDE. It is applied to DFDs to identify privacy threats — essential for GDPR, HIPAA, and CCPA compliance.

| Letter | Threat Category | Description | Example |
|---|---|---|---|
| **L** | Linkability | Connect data about users across contexts | Correlate browsing history with purchase history |
| **I** | Identifiability | Identify individuals from seemingly anonymous data | Re-identify users from "anonymous" location data |
| **N** | Non-repudiation | User cannot deny having performed an action | Excessive audit logging enables profiling |
| **D** | Detectability | Infer that data about a person exists | Knowing that someone has an HIV record even without content |
| **D** | Disclosure of Information | Expose personal data to unauthorized parties | Database breach exposes PII |
| **U** | Unawareness | Users unaware of data processing practices | Silent data collection without consent notice |
| **N** | Non-compliance | Violations of privacy regulations and policies | Retaining data longer than consent permits |

## Data Flow Diagrams (DFDs)

DFDs are the foundation of most threat models. They visually represent how data moves through a system.

### DFD Elements
| Symbol | Element | Description |
|---|---|---|
| Rectangle | **External Entity** | Users, third-party systems, external services outside your control |
| Rounded Rectangle / Circle | **Process** | Application components that receive, transform, and transmit data |
| Open Rectangle (two parallel lines) | **Data Store** | Databases, file systems, caches, queues, logs |
| Arrow | **Data Flow** | Data movement between elements; label with data type |
| Dashed Line | **Trust Boundary** | Where trust level changes; where attacker threats cross |

### DFD Levels
- **Context Diagram (Level 0)**: Single process (the entire system) and all external entities; high-level view
- **Level 1 DFD**: Main subsystems/processes with their data flows and data stores
- **Level 2 DFD**: Individual components within each subsystem; detailed trust boundaries

### Trust Boundaries
Every trust boundary crossing is a potential threat surface. Common boundaries:
- Internet → DMZ
- DMZ → internal network
- Browser → web server (user input)
- Web server → database
- User space → kernel space
- Container → host OS
- Cloud tenant → cloud control plane

## Attack Trees

Bruce Schneier's attack tree method provides a structured way to enumerate attacker paths toward a goal.

### Structure
- **Root node**: Attacker's goal (e.g., "Exfiltrate customer payment data")
- **Sub-goals**: Alternative or prerequisite methods (e.g., "Compromise database", "Intercept in transit", "Social engineer DBA")
- **Leaf nodes**: Specific, concrete attack actions (e.g., "Execute SQL injection on checkout API")
- **AND nodes**: All children must succeed (attacker must do ALL of these)
- **OR nodes**: Any child suffices (attacker can do ANY of these)
- **Annotations**: Cost, probability, skill required, detectability — enables prioritized countermeasures

### Example Attack Tree: Steal Customer Payment Data
```
[ROOT] Steal Customer Payment Data
├── [OR] Compromise Database Directly
│   ├── SQL Injection in Application
│   ├── Exploit Unpatched DB CVE
│   └── Compromise DBA Credentials
├── [OR] Intercept Data in Transit
│   ├── [AND] MITM on Network
│   │   ├── ARP Spoofing on LAN
│   │   └── TLS Downgrade Attack
│   └── Compromise TLS Termination Point
└── [OR] Compromise Application Server
    ├── Remote Code Execution via Web Vulnerability
    └── Malicious Dependency (supply chain)
```

## Threat Modeling as Code

Modern DevSecOps teams integrate threat modeling into CI/CD pipelines so models stay current with code changes.

### Tools
- **Threagile**: Define your architecture in YAML; generates risk reports, DFDs, and mitigation plans. Runs as a Docker container in CI/CD. Model lives alongside code in version control
- **IriusRisk**: API-driven; integrates with GitHub/Jira; auto-updates threat model when architecture diagrams change
- **pytm (Python Threat Modeling)**: OWASP project; define DFD elements in Python code; generates Graphviz DFDs and reports

### Example Threagile Snippet (YAML)
```yaml
technical_assets:
  payment-api:
    id: payment-api
    type: process
    usage: business
    technologies: [Java, Spring Boot]
    tags: [pci-dss]
    data_formats_sent: [payment-card-data]
    communication_links:
      payment-db:
        target: payment-database
        protocol: jdbc/tls
        authentication: credentials
        data_sent: [payment-card-data]
        data_received: [payment-card-data]
```

Threagile analyzes this and automatically generates STRIDE threats for each component and data flow.

## When to Threat Model

| Trigger | Rationale |
|---|---|
| New system or feature design | Cheapest time to fix design flaws; before any code is written |
| Significant architectural change | New trust boundaries or data flows create new threats |
| Before a penetration test | Model informs test scope; avoids testing wrong components |
| As part of SDLC security review gate | Institutionalizes threat modeling at design review |
| After a significant security incident | Understand what architectural assumption failed; prevent recurrence |
| New compliance requirement | Map threats to compliance controls (HIPAA, PCI DSS, GDPR) |
| Third-party integration | External systems are trust boundary crossings; model the interface |

## Offensive Angle — Why Threat Models Get It Wrong

Understanding common threat modeling failures is essential — these are the gaps attackers find and exploit.

### Incomplete System Decomposition
- **Missing third-party integrations**: Analytics trackers, payment SDKs, monitoring agents, CDN providers often omitted from DFDs. These are real attack surfaces (supply chain, XSS, data leakage)
- **Logging and monitoring pipelines not modeled**: SIEM agents, log shippers, and monitoring tools have elevated privileges and network access; rarely included in threat models
- **Administrative interfaces excluded**: The admin panel, internal API, management plane often skipped because "only internal users access it" — internal attackers and lateral movement reach these too

### Incorrect Trust Assumptions
- **Internal services blindly trusted**: "If it's on the internal network, it's trusted" — this assumption enables lateral movement post-breach; Zero Trust principles should apply inside too
- **Shared hosting trust model failures**: Multi-tenant environments (cloud, SaaS) have subtle trust boundary implications often missed in models
- **Trusting the client**: Assuming the browser/mobile app cannot be modified; all client-side validation is bypassable

### Scope Omissions
- **Supply chain threats**: Build systems, CI/CD pipelines, package registries (npm, PyPI), base container images — all are attack surfaces; rarely modeled
- **Human element absent**: Social engineering, insider threat, physical access not on DFD because "you can't put a person in a DFD" — but these are real attack paths that countermeasures must address
- **The attack on the threat model itself**: An attacker who can modify the threat model document or the IriusRisk/ThreatModeler tool can suppress countermeasures

### Process Failures
- **Threat modeling as a one-time checkbox**: Model done at project start, never updated as architecture evolves; stale models give false assurance
- **Theoretical threats not validated**: Threats identified but never validated with actual attack scenarios or penetration tests; mitigations assumed to work
- **No abuse cases**: Functional requirements modeled but abuse cases (what can a malicious authenticated user do?) not considered
- **Missing threat actor profiles**: Generic "attacker" assumed; missing nation-state, insider, and supply chain threat profiles leads to miscalibrated mitigations

## NIST 800-53 Alignment

| Control | Family | Threat Modeling Relevance |
|---|---|---|
| SA-11 | System & Services Acquisition | Developer security testing — threat modeling is explicitly listed as a security test technique |
| SA-8 | System & Services Acquisition | Security and privacy engineering principles; DFD decomposition and trust boundary analysis |
| SA-14 | System & Services Acquisition | Criticality analysis; identify critical components and flows in threat model |
| SA-15 | System & Services Acquisition | Development process, standards, and tools; threat modeling tool governance |
| PL-8 | Planning | Security and privacy architectures; threat model feeds architecture decisions |
| RA-3 | Risk Assessment | Risk assessment; threat modeling is a structured risk identification technique |
| CA-2 | Assessment, Authorization | Security assessments; threat model informs assessment scope and test cases |
| PM-9 | Program Management | Risk management strategy; threat modeling part of enterprise risk process |
| SC-3 | System & Communications | Security function isolation; trust boundaries in DFD map to SC-3 implementation |
| SI-12 | System & Info Integrity | Information management and retention; data stores in DFD align with data classification |

## ATT&CK Coverage

Threat modeling identifies which techniques are relevant to your architecture. The following are commonly identified in threat models:

| Technique | ID | Threat Modeling Application |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Model identifies internet-facing entry points; drives input validation and WAF requirements |
| Valid Accounts | T1078 | Identity trust boundaries in DFD surface authentication requirements and account compromise scenarios |
| Remote Services | T1021 | Internal service-to-service data flows model remote service attack paths |
| External Remote Services | T1133 | Model VPN, RDP, and admin portal as trust boundary crossings requiring strong auth |
| Exfiltration Over Alternative Protocol | T1048 | Data flow modeling identifies all outbound channels; data store sensitivity drives DLP requirements |
| Application Layer Protocol | T1071 | Modeling all HTTP/HTTPS/DNS data flows surfaces C2 channel risks for outbound filtering |
| Adversary-in-the-Middle | T1557 | Data flows across trust boundaries model AiTM risk; drives mTLS and certificate pinning |
| Data from Cloud Storage | T1530 | Cloud data store modeling identifies overly permissive storage buckets as threats |

## Certifications

| Certification | Issuer | Notes |
|---|---|---|
| **CSSLP** (Certified Secure Software Lifecycle Professional) | (ISC)² | Threat modeling is a core domain; SDLC-focused |
| **CISSP** | (ISC)² | Security Architecture and Engineering domain covers threat modeling principles |
| **CCSP** | (ISC)² | Cloud security architecture; threat modeling for cloud systems |
| **Threat Modeling Practitioner (TMP)** | Toreon | Dedicated threat modeling certification; hands-on |
| **eMAPT** | eLearnSecurity | Mobile application penetration testing with threat modeling component |
| **GWEB** | GIAC/SANS | Web application security; threat modeling for web architectures |
| **CASE .NET / CASE Java** | EC-Council | Certified Application Security Engineer; includes threat modeling |

## Learning Resources

| Resource | Type | Cost |
|---|---|---|
| [Threat Modeling: Designing for Security (Shostack)](https://www.wiley.com/en-us/Threat+Modeling%3A+Designing+for+Security-p-9781118809990) | Book | Paid |
| [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) | Reference | Free |
| [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) | Reference | Free |
| [OWASP Threat Dragon (Tool + Docs)](https://owasp.org/www-project-threat-dragon/) | Tool | Free |
| [Adam Shostack Elevation of Privilege Card Game](https://shostack.org/games/elevation-of-privilege) | Training game | Free PDF |
| [SAFECode Threat Modeling Guide](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf) | Guide | Free |
| [LINDDUN Privacy Threat Modeling Website](https://linddun.org/) | Reference | Free |
| [Threagile Threat Modeling as Code](https://threagile.io/) | Tool | Free open source |
| [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) | Tool | Free |
| [MITRE ATT&CK for Threat Modeling](https://attack.mitre.org/) | Reference | Free |
| [Shostack + Associates Blog](https://shostack.org/blog/) | Blog | Free |
| [PASTA: Risk-Centric Threat Modeling (UBM/Tony UcedaVelez)](https://www.wiley.com/en-us/Risk+Centric+Threat+Modeling-p-9780470500965) | Book | Paid |

## Related Disciplines

- [application-security.md](application-security.md)
- [secure-software-development.md](secure-software-development.md)
- [penetration-testing.md](penetration-testing.md)
- [risk-management.md](risk-management.md)
- [cloud-security.md](cloud-security.md)
- [zero-trust-architecture.md](zero-trust-architecture.md)
- [identity-and-access-management.md](identity-and-access-management.md)
