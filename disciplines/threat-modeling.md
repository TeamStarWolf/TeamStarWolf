# Threat Modeling

Threat modeling is the practice of systematically identifying threats, attack surfaces, attack vectors, and trust boundaries in systems and applications before they reach production. It is a structured, repeatable process that asks four fundamental questions: What are we building? What can go wrong? What are we going to do about it? Did we do a good enough job? The discipline sits at the intersection of security architecture, software engineering, and risk management — it forces security thinking into design decisions rather than bolting defenses onto finished systems.

Effective threat modeling is not a one-time exercise. As systems evolve, threat models must be maintained. The output is not a document — it is a set of decisions: mitigations to implement, risks to accept, monitoring to deploy, and design changes to make. Teams that treat threat modeling as a compliance checkbox produce documents nobody reads. Teams that treat it as an engineering practice produce more secure systems with fewer costly late-stage vulnerabilities.

---

## Where to Start

Begin with understanding data flow diagrams and trust boundaries. Before learning any formal methodology, be able to draw a simple DFD for a web application — identify actors, processes, data stores, and data flows, then mark where trust changes hands. From there, learn STRIDE as your first enumeration methodology, then layer in MITRE ATT&CK to ground abstract threats in real adversary behavior.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | DFD construction, trust boundary identification, STRIDE methodology, OWASP Threat Modeling basics, introduction to ATT&CK for threat enumeration | OWASP Threat Modeling Cheat Sheet, Adam Shostack's "Threat Modeling" book (chapters 1–4), OWASP Threat Dragon (hands-on practice) |
| Practitioner | PASTA and LINDDUN methodologies, NIST SP 800-154, risk rating (DREAD/CVSS), mitigations mapping, threat model as code with pytm or Threagile, DevSecOps integration | SAFECode Practical Threat Analysis guide, pytm documentation, IriusRisk community tier, SANS SEC540 content |
| Advanced | MITRE ATT&CK-based threat modeling, automated DFD generation, CI/CD gate integration, Attack Tree analysis, enterprise-scale threat modeling programs, MITRE EMB3D for embedded systems | MITRE CTID threat modeling publications, Foreseeti securiCAD evaluations, Microsoft SDL threat modeling documentation |

---

## Free Training

- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — Concise, authoritative reference covering STRIDE, PASTA, and the core process steps; the fastest way to understand the methodology landscape and get started with a first threat model
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) — Free open-source threat modeling tool with a browser-based DFD editor; the lowest-friction way to build your first threat model without any setup cost
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) — Free Windows application implementing Microsoft's SDL threat modeling process; the tool used to teach STRIDE; well-documented with extensive template libraries
- [SAFECode Practical Security Stories and Security Tasks](https://safecode.org/publications/) — Free publications on integrating threat modeling into agile development, security user stories, and developer security tasks; highly practical for DevSecOps integration
- [MITRE ATT&CK for Threat Modeling](https://attack.mitre.org) — Free adversary behavior framework; map enumerated threats to real TTPs, validate coverage assumptions, and prioritize mitigations based on actual threat actor behavior
- [Adam Shostack's Threat Modeling Resources](https://shostack.org/resources/) — Free articles, talks, and resources from the author of the definitive threat modeling textbook; covers the four-questions framework and common pitfalls
- [Practical DevSecOps](https://www.practical-devsecops.com) — Free tier content covering threat modeling in CI/CD pipelines; practical integration patterns for engineering teams

---

## Tools & Repositories

### Open Source Threat Modeling Tools
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) — Open-source threat modeling tool with web and desktop versions; supports DFD creation, threat enumeration via STRIDE, and JSON-based model storage for version control integration; the recommended starting tool for teams evaluating open-source options
- [izar/pytm](https://github.com/izar/pytm) — Python-based threat modeling as code framework; define system components, data flows, and trust boundaries in Python and generate DFDs and threat reports automatically; ideal for CI/CD integration and maintaining threat models alongside code
- [Threagile/threagile](https://github.com/Threagile/threagile) — Agile threat modeling as code using YAML; generates DFDs, risk reports, and mitigation recommendations from declarative system definitions; strong Docker support for pipeline integration
- [jgraph/drawio](https://github.com/jgraph/drawio) — The draw.io diagramming tool with built-in threat modeling templates; widely used for manual DFD construction; free desktop and browser versions; integrates with Confluence and SharePoint
- [adamshostack/attacktrees](https://github.com/adamshostack/attacktrees) — Attack tree templates and examples from Adam Shostack; the reference implementation for structured attack tree analysis

### Frameworks & Standards References
- [OWASP Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org) — The community-authored set of values and principles for effective threat modeling programs; essential reading before establishing an enterprise threat modeling practice
- [NIST SP 800-154](https://csrc.nist.gov/publications/detail/sp/800-154/draft) — NIST guide to data-centric system threat modeling; covers DFD-based approaches, threat enumeration, and risk rating aligned to the NIST RMF
- [microsoft/threat-modeling-templates](https://github.com/microsoft/threat-modeling-templates) — Microsoft SDL threat modeling templates for the Microsoft Threat Modeling Tool; covers Azure services, web applications, and on-premises systems

### ATT&CK-Based Threat Modeling
- [MITRE CTID Threat Modeling Publications](https://ctid.mitre.org) — Center for Threat-Informed Defense publications on ATT&CK-based threat modeling; the most rigorous approach to grounding threat models in real adversary behavior
- [MITRE EMB3D](https://emb3d.mitre.org) — Threat model for embedded systems and OT/ICS devices; maps threats to device properties and mitigations; essential for IoT and industrial security threat modeling

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **IriusRisk** | Enterprise threat modeling platform with automated threat and countermeasure generation from architecture diagrams; strong SDLC integration, risk rating automation, and compliance mapping to NIST, ISO 27001, and OWASP; the most feature-complete commercial option |
| **ThreatModeler** | Cloud-native threat modeling platform with automated threat library updates, process flow diagrams, and enterprise reporting; strong for large-scale programs managing hundreds of application threat models |
| **SD Elements (Security Compass)** | Requirements-driven security platform that generates security and compliance requirements from architecture questionnaires; strong for regulated industries needing audit trails linking threats to implemented controls |
| **Foreseeti securiCAD** | Attack simulation and probabilistic threat modeling using enterprise architecture models; generates attack paths and quantified risk scores; strongest for infrastructure and enterprise architecture threat analysis |
| **Microsoft Threat Modeling Tool** | Free Microsoft SDL implementation; STRIDE-based with extensive Azure and on-premises service templates; the standard for Microsoft-stack environments and teams learning the methodology |

---

## Process

The threat modeling process follows a structured lifecycle from scope to validation. Each phase builds on the previous and the process should repeat with each significant system change.

| Phase | Activity | Output |
|---|---|---|
| **1. Scope Definition** | Define system boundaries, assets, actors, and security objectives; establish what is in and out of scope | System description, asset register, security objectives |
| **2. Decomposition (DFDs)** | Build data flow diagrams showing processes, data stores, data flows, and external entities; mark trust boundaries | Threat model DFD, trust boundary map |
| **3. Threat Enumeration** | Apply STRIDE or other methodology to each DFD element; reference ATT&CK for real-world threat grounding | Threat list mapped to components |
| **4. Risk Rating** | Score threats using DREAD, CVSS, or qualitative likelihood x impact; prioritize by risk level | Prioritized risk register |
| **5. Mitigations** | Identify controls, design changes, and monitoring for each threat; map to NIST 800-53 or OWASP controls | Mitigation plan, accepted risks |
| **6. Validation** | Verify mitigations are implemented; validate with penetration testing or code review; update model | Updated threat model, validation evidence |

---

## NIST 800-53 Control Alignment

| Control | ID | Threat Modeling Relevance |
|---|---|---|
| Risk Assessment | RA-3 | Threat modeling is the primary mechanism for identifying and documenting system-specific risks; threat models feed directly into the risk assessment process |
| Security and Privacy Engineering Principles | SA-8 | Threat modeling operationalizes secure design principles by identifying where those principles apply and validating they are implemented correctly |
| Developer Testing and Evaluation | SA-11 | Threat models define what must be tested; penetration tests and security code reviews should validate the mitigations identified in the threat model |
| Development Process, Standards, and Tools | SA-15 | Requires that development processes include security analysis; threat modeling as code integrated into CI/CD directly satisfies this control |
| Security and Privacy Architecture | PL-8 | Enterprise security architecture requires system-level threat models as the basis for architecture decisions and control selection |

---

## ATT&CK Coverage

Threat modeling maps to the MITRE ATT&CK framework at multiple levels. Pre-ATT&CK reconnaissance and resource development phases are addressed by identifying external attack surfaces and asset exposure. The Enterprise matrix drives threat enumeration against application and infrastructure components.

| Threat Modeling Value | ATT&CK Relevance |
|---|---|
| Attack surface reduction | Reduces exposure targeted by Initial Access techniques: T1190 (Exploit Public-Facing Application), T1566 (Phishing), T1133 (External Remote Services) |
| Input validation and execution controls | Addresses Execution techniques: T1059 (Command and Scripting Interpreter), T1203 (Exploitation for Client Execution) |
| Least privilege design | Mitigates Privilege Escalation: T1548 (Abuse Elevation Control Mechanism), T1068 (Exploitation for Privilege Escalation) |
| Trust boundary enforcement | Addresses Lateral Movement: T1021 (Remote Services), T1550 (Use Alternate Authentication Material) |
| Detection prioritization | Maps highest-risk attack paths from the threat model to detection engineering priorities; ensures detection coverage is risk-driven |

Threat models built against the ATT&CK framework enable security teams to prioritize detection engineering, red team exercises, and control investments against the specific techniques most relevant to their architecture rather than treating all techniques as equally important.

---

## Integration with DevSecOps

Threat modeling is most effective when integrated into the software development lifecycle as a first-class engineering activity rather than a pre-release gate.

- **Shift-Left**: Introduce threat modeling at the design phase, before any code is written; design changes cost a fraction of post-implementation fixes
- **Threat Model as Code**: Store threat models in version control alongside source code using pytm or Threagile YAML definitions; models update with architecture changes through pull requests
- **Automated DFD Generation**: Generate DFDs from infrastructure-as-code (Terraform, CloudFormation) using automated parsers; keeps threat models synchronized with actual deployed architecture
- **CI/CD Gate**: Run automated threat analysis in pipelines using Threagile or pytm; fail builds that introduce new high-risk data flows across trust boundaries without corresponding mitigations
- **Security User Stories**: Convert threat model findings into backlog items; each identified threat becomes a security requirement with acceptance criteria tied to mitigation implementation

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Threat Modeling: Designing for Security | Adam Shostack | The definitive threat modeling textbook; covers STRIDE, attack trees, and the four-questions framework with practical examples across web, mobile, and infrastructure systems; required reading for anyone establishing a threat modeling practice |
| The Art of Software Security Assessment | Dowd, McDonald, Schuh | Deep technical treatment of software vulnerability classes that threat modeling must address; essential for building realistic threat enumeration against application components |
| Alice and Bob Learn Application Security | Tanya Jain | Accessible introduction to application security and threat modeling for developers; bridges the gap between security practitioners and engineering teams who need to participate in threat modeling |
| Threat Modeling: A Practical Guide for Development Teams | Izar Tarandach, Matthew Coles | Modern treatment of threat modeling as code and DevSecOps integration; covers pytm and automated approaches for scaling threat modeling across large engineering organizations |

---

## Certifications

- **CSSLP** (Certified Secure Software Lifecycle Professional — ISC2) — The most relevant certification for threat modeling practitioners; covers the full SDLC security lifecycle including threat modeling, secure design, and security requirements; validates expertise directly applicable to the discipline
- **GWEB** (GIAC Web Application Defender) — Covers application security threats and defenses in depth; practical complement to threat modeling for web application practitioners; validates the technical knowledge needed to enumerate and mitigate web application threats
- **CEH** (Certified Ethical Hacker — EC-Council) — Provides the offensive perspective that makes threat enumerators more effective; understanding attacker techniques and tools sharpens threat identification in DFD analysis
- **OSCP** (Offensive Security Certified Professional) — Hands-on offensive certification that deeply informs threat modeling; practitioners who have attempted real exploitation understand threat enumeration at a visceral level that purely defensive training cannot replicate
- **Security+** (CompTIA) — Entry-level foundation covering threat concepts, risk management, and security controls; the starting credential for practitioners entering the threat modeling and security architecture field

---

## Channels

- [Adam Shostack](https://www.youtube.com/@adamshostack) — The authoritative voice on threat modeling methodology; conference talks, tutorials, and the four-questions framework explained by the author of the foundational text
- [OWASP](https://www.youtube.com/@OWASP) — Threat modeling tool demos, methodology presentations, and developer security content from the Open Web Application Security Project
- [SANS Institute](https://www.youtube.com/@SansInstitute) — SEC540 and application security summit recordings covering threat modeling in DevSecOps contexts; practitioner-level content from working security engineers
- [Practical DevSecOps](https://www.youtube.com/@PracticalDevSecOps) — Threat modeling as code tutorials, CI/CD security integration, and DevSecOps engineering content with hands-on demonstrations

---

## Who to Follow

- [@adamshostack](https://x.com/adamshostack) — Adam Shostack; the definitive voice on threat modeling methodology, author of the foundational text, and consistent producer of practical threat modeling content
- [@IzarTarandach](https://x.com/IzarTarandach) — Creator of pytm; threat modeling as code, DevSecOps integration, and modern scalable threat modeling program design
- [@ThreatModeling](https://x.com/ThreatModeling) — Threat modeling community news, methodology updates, and practitioner content aggregation
- [@tanya_jain](https://x.com/tanya_jain) — Tanya Jain; application security and threat modeling for developers; bridge between security practitioners and engineering teams

---

## Key Resources

- [OWASP Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org) — The community statement of values and principles for threat modeling programs; the right starting point before selecting tools or methodologies
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) — Free browser-based and desktop threat modeling tool; the recommended open-source starting point for teams building their first threat models
- [Adam Shostack Four Questions Framework](https://shostack.org/resources/) — The simplest, most portable threat modeling framework; applies to any system, any technology stack, any threat modeling experience level
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — Map threat model findings to ATT&CK techniques; visualize coverage, identify gaps, and communicate risk to stakeholders using the industry-standard framework
- [NIST SP 800-154 (Draft)](https://csrc.nist.gov/publications/detail/sp/800-154/draft) — NIST's guide to data-centric system threat modeling; the authoritative government reference for threat modeling aligned to the NIST Risk Management Framework
- [SAFECode Threat Modeling Publications](https://safecode.org/publications/) — Industry consortium guidance on integrating threat modeling into agile and DevSecOps environments; practical and vendor-neutral
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map threat model output to ATT&CK; visualize which techniques your architecture is exposed to and where detection coverage needs to be built

---

## Related Disciplines

- [Security Architecture](/disciplines/security-architecture) — Threat modeling is the analytical engine of security architecture; architecture decisions are validated against threat models and threat models are grounded in architecture diagrams
- [DevSecOps](/disciplines/devsecops) — Threat modeling is the highest-leverage shift-left security practice in DevSecOps; integrating it into pipelines and sprint planning is a core DevSecOps engineering challenge
- [Application Security](/disciplines/application-security) — Threat modeling defines the security requirements that application security testing validates; the disciplines are inseparable in a mature SDLC security program
- [Risk & Compliance](/disciplines/governance-risk-compliance) — Threat models feed risk assessments and control selection decisions; threat modeling is the system-level instantiation of organizational risk management
- [Offensive Security](/disciplines/offensive-security) — Offensive practitioners provide the adversary perspective that makes threat enumeration realistic; red team findings should continuously update and validate threat models
