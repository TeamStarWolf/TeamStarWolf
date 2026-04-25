# Threat Modeling Reference

> **Threat Modeling** — comprehensive reference covering STRIDE, PASTA, LINDDUN, attack trees, DREAD, MITRE ATT&CK integration, Data Flow Diagrams, cloud/microservices threats, and practical SDLC integration for software and infrastructure security.

---

## Table of Contents

1. [Why Threat Modeling](#why-threat-modeling)
2. [STRIDE Methodology (Microsoft)](#stride-methodology-microsoft)
3. [PASTA (Process for Attack Simulation and Threat Analysis)](#pasta-process-for-attack-simulation-and-threat-analysis)
4. [LINDDUN (Privacy Threat Modeling)](#linddun-privacy-threat-modeling)
5. [Attack Trees](#attack-trees)
6. [DREAD Risk Scoring (Legacy, contextual use)](#dread-risk-scoring-legacy-contextual-use)
7. [MITRE ATT&CK Integration](#mitre-attck-integration)
8. [Data Flow Diagrams (DFDs) for Threat Modeling](#data-flow-diagrams-dfds-for-threat-modeling)
9. [Practical Threat Modeling Workflow](#practical-threat-modeling-workflow)
10. [Threat Modeling Tools](#threat-modeling-tools)
11. [Threat Modeling for Cloud & Microservices](#threat-modeling-for-cloud--microservices)
12. [Secure Design Principles (Mitigations Catalog)](#secure-design-principles-mitigations-catalog)
13. [Threat Modeling Metrics](#threat-modeling-metrics)
14. [Integration with SDLC](#integration-with-sdlc)
15. [Resources & Further Reading](#resources--further-reading)

---

## Why Threat Modeling

> "Think like an attacker before attackers think for you."

Threat modeling is a structured approach to identifying security threats, quantifying their risk, and designing mitigations **before** those threats are realized in production systems. It transforms abstract security principles into concrete, actionable design decisions.

### The Business Case

The OWASP Top 10 consistently shows that **most vulnerabilities are design flaws, not coding errors**. An injection vulnerability may be a coding mistake, but a missing authorization check on an admin endpoint is a design flaw that no amount of code review will catch if the design was never scrutinized.

IBM's System Sciences Institute research established the **30x cost multiplier**: a security defect found at the design phase costs approximately 1 unit to fix; the same defect found in production costs 30x more to remediate when you factor in incident response, customer notification, legal exposure, reputation damage, and re-architecture costs.

### When to Threat Model

Threat modeling is triggered by changes that alter the security posture of a system:

| Trigger | Why It Matters |
|---------|---------------|
| New system design | Establish baseline security architecture before any code is written |
| Major new feature | New data flows, trust boundaries, or external integrations require fresh analysis |
| Architecture change | Migrating to microservices, cloud, or serverless changes the attack surface |
| Cloud migration | New attack vectors: IAM, metadata service, shared tenancy, storage buckets |
| Third-party integration | New trust boundary crossing; vendor's security posture becomes your risk |
| Regulatory scope change | PCI DSS, HIPAA, or GDPR scope changes mandate security control review |
| Post-incident review | Incident may reveal design flaw requiring threat model update |

### Inputs and Outputs

**Inputs required for effective threat modeling:**
- Architecture diagrams (logical and physical topology)
- Data Flow Diagrams (Level 0 and Level 1)
- User stories and use cases (what the system is supposed to do)
- Abuse cases (what a bad actor might try to do)
- API specifications (OpenAPI/Swagger, gRPC definitions)
- Network topology diagrams (VLAN boundaries, firewall zones)
- Asset inventory with data classification

**Outputs produced by a threat model:**
- Threat list with unique identifiers (TM-001, TM-002, etc.)
- Risk ratings per threat (likelihood × impact, or CVSS-like scoring)
- Mitigation recommendations mapped to each threat
- Security requirements for developers (functional security stories)
- Acceptance criteria for security testing
- Risk register entries for unmitigated residual risks
- Architecture decision records (ADRs) for security design choices

---

## STRIDE Methodology (Microsoft)

### Origins and Overview

STRIDE was developed at Microsoft by **Loren Kohnfelder and Praerit Garg in 1999** as part of Microsoft's Secure Development Lifecycle (SDL). It became the foundational threat categorization model for software threat modeling and remains the most widely used framework globally.

STRIDE categorizes threats into six types, each violating a specific security property:

| Threat | Security Property Violated | Example Attack | MITRE ATT&CK Tactic |
|--------|---------------------------|----------------|----------------------|
| **Spoofing** | Authentication | ARP spoofing, JWT tampering, forged sender identity | Initial Access |
| **Tampering** | Integrity | Man-in-the-middle modification, SQL injection, parameter tampering | Impact |
| **Repudiation** | Non-repudiation | Log deletion, forging audit trail entries, deniable covert channels | Defense Evasion |
| **Information Disclosure** | Confidentiality | Path traversal, insecure direct object reference, verbose error messages | Collection |
| **Denial of Service** | Availability | DDoS, resource exhaustion, XML bomb, ReDoS | Impact |
| **Elevation of Privilege** | Authorization | IDOR, SSRF to IMDS, deserialization gadget chains, JWT algorithm confusion | Privilege Escalation |

### STRIDE per Element

Each element in a Data Flow Diagram is susceptible to a different subset of STRIDE threats:

| DFD Element | Applicable STRIDE Threats | Rationale |
|-------------|--------------------------|-----------|
| **External Entity** (user, system) | S, R | Can be spoofed or repudiate actions; doesn't process or store data |
| **Process** (application, service) | S, T, R, I, D, E | All threats apply — processes transform data and make authorization decisions |
| **Data Store** (database, file, cache) | T, R, I, D | Can be tampered with, hide repudiation evidence, disclose data, or be made unavailable |
| **Data Flow** (network connection, IPC) | T, I, D | Data in motion can be intercepted, modified, or disrupted |

### STRIDE-per-Interaction

The STRIDE-per-interaction variant applies all six STRIDE categories to **every interaction** (data flow crossing a trust boundary) in the DFD, rather than per element. This produces more thorough coverage but is more time-consuming. Recommended for:
- High-assurance systems (financial, healthcare, government)
- Components handling Crown Jewel data
- External-facing APIs

### Microsoft Threat Modeling Tool

The **Microsoft Threat Modeling Tool** (free download from Microsoft) generates STRIDE threats automatically from DFD components:
- Draw processes, data stores, external entities, and data flows
- Assign element types (e.g., "Web Application", "Database", "Browser")
- Tool generates a threat list with suggested mitigations
- Supports custom stencils for cloud-native architectures

### STRIDE Example: REST API Threat Model

**System**: Web API server with JWT authentication, backed by a PostgreSQL database.

| STRIDE Category | Specific Threat | Mitigation |
|----------------|-----------------|------------|
| Spoofing | JWT forgery if signing key is weak or HS256 allows key substitution | Use RS256 asymmetric signing; rotate private keys on a defined schedule; validate `alg` header server-side |
| Tampering | Unsigned HTTP request body allows MITM modification | Enforce TLS 1.3 minimum; consider request signing (HMAC-SHA256 over body + timestamp) for high-value mutations |
| Repudiation | API actions not logged; attacker can deny malicious calls | Structured audit logging for all state-changing operations; include authenticated user ID, timestamp, source IP, request hash; store in write-once SIEM |
| Information Disclosure | Unhandled exceptions return stack traces with internal paths and DB schema | Implement global exception handler returning generic error codes; log details server-side only; disable debug mode in production |
| Denial of Service | No rate limiting on authentication endpoint allows credential stuffing at scale | Rate limit by IP and username (exponential backoff); account lockout after N failures with CAPTCHA fallback; CDN-layer DDoS protection |
| Elevation of Privilege | Admin endpoint missing authorization check due to developer assumption about middleware order | Explicit authorization check in every controller method; RBAC enforcement at service layer, not middleware only; integration test for every privileged operation |

---

## PASTA (Process for Attack Simulation and Threat Analysis)

PASTA is a **seven-stage, risk-centric threat modeling methodology** that aligns security analysis with business objectives. Unlike STRIDE's technical focus, PASTA deliberately starts with business context and risk appetite before diving into technical threats. It was created by Tony UcedaVelez and Marco Morana, documented in their 2015 book.

### Stage 1: Define Objectives

Establish the business context before any technical analysis:
- **Business objectives**: What must the system do to support the business? What would a breach cost the organization?
- **Compliance requirements**: Which regulations apply? (PCI DSS, HIPAA, GDPR, SOX)
- **Risk appetite**: How much residual risk is the organization willing to accept?
- **Crown jewels identification**: What are the highest-value assets? (customer PII, financial transaction records, proprietary algorithms, authentication credentials)
- **Success criteria**: What does a successful threat model look like for this engagement?

### Stage 2: Define Technical Scope

Map the system boundaries and technology stack:
- Application components, services, and dependencies
- Technology stack (programming languages, frameworks, libraries, ORMs)
- Integration points (third-party APIs, internal services, message queues)
- Trust boundaries and network zones (internet, DMZ, internal, privileged)
- Deployment environment (on-premises, cloud provider, hybrid)
- Data flows across organizational and technical boundaries

### Stage 3: Application Decomposition

Decompose the system into analyzable units:
- **Data Flow Diagrams**: Level 0 (context diagram showing system as single process with external actors) and Level 1 (detailed DFD showing sub-processes and data stores)
- **Entry points**: All inputs to the system — HTTP endpoints, message queues, file uploads, CLI interfaces, scheduled jobs
- **Exit points**: All outputs — API responses, file exports, notifications, logs
- **Trust boundaries**: Every location where security properties must be verified (authentication, authorization, input validation)
- **Assets**: Data assets (PII records, session tokens, encryption keys), functional assets (admin functions, payment processing)
- **Actors**: Legitimate users (roles), external systems, adversarial actors
- **Use cases and abuse cases**: For every use case, derive its abuse case by asking "how could this be misused?"

### Stage 4: Threat Analysis

Analyze the threat landscape relevant to the system:
- **Threat intelligence review**: Which threat actors are currently targeting your industry and geography? (ISAC feeds, vendor advisories, CISA KEV list)
- **Attacker profiling**: Script kiddies, cybercriminal groups (ransomware, data theft), nation-state APTs, insider threats (malicious, negligent), supply chain attackers
- **ATT&CK mapping**: Map threat actor TTPs from MITRE ATT&CK to your architecture components — which ATT&CK techniques are relevant given your stack?
- **Insider threat modeling**: Include privileged user abuse scenarios (sysadmin data theft, developer backdoor)
- **Supply chain threats**: Third-party libraries, CI/CD pipeline compromise, vendor account takeover

### Stage 5: Vulnerability Analysis

Identify weaknesses that threat actors could exploit:
- Map known CVEs to system components (check NVD, vendor advisories, OSS vulnerability databases)
- SAST (Static Application Security Testing) findings — unvalidated input, hardcoded secrets, insecure deserialization
- DAST (Dynamic Application Security Testing) findings — runtime injection, broken authentication, session management flaws
- Architecture-level weaknesses — missing controls per component (no WAF, unencrypted database connection, excessive IAM permissions)
- Configuration vulnerabilities — default credentials, debug mode enabled, verbose error responses

### Stage 6: Attack Modeling

Construct detailed attack scenarios:
- **Attack trees**: For each significant threat, build an attack tree showing the paths an attacker could take (see Attack Trees section)
- **Kill chain analysis**: Map full attack path: Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration
- **Attacker decision logic**: Model attacker cost/benefit at each decision point — would a rational attacker pursue this path given the difficulty and value of the target?
- **Simulation**: Walk through the attack scenarios against the architecture to validate feasibility

### Stage 7: Risk and Impact Analysis

Translate technical threats into business risk:
- **Risk score**: Probability of attack success × Business impact = Risk score
- **Business impact per scenario**: Quantify in dollars using FAIR model or qualitative impact tiers
- **Mitigation priority**: Rank threats by risk score; build mitigation roadmap
- **Residual risk calculation**: After proposed mitigations, what risk remains?
- **Risk acceptance**: Obtain formal risk acceptance for residual risks above appetite threshold from asset owner or risk committee

---

## LINDDUN (Privacy Threat Modeling)

LINDDUN is a **privacy-focused threat modeling framework** analogous to STRIDE for security. Developed by researchers at KU Leuven (Belgium), it provides a systematic method for identifying privacy threats in software systems. It is especially relevant for GDPR compliance, healthcare systems, and any application processing personal data.

### LINDDUN Threat Categories

| Threat | Privacy Property Violated | Example |
|--------|--------------------------|---------|
| **Linkability** | Unlinkability | Correlating pseudonymous records across datasets to re-identify users |
| **Identifiability** | Anonymity | Re-identifying supposedly anonymized data via quasi-identifiers |
| **Non-repudiation** | Deniability | System creates irrefutable proof of a user's sensitive actions |
| **Detectability** | Undetectability | Adversary can detect whether specific data about an individual exists in the system |
| **Disclosure of information** | Confidentiality | Unauthorized access to personal data — data breach, excessive data sharing |
| **Unawareness** | Transparency | Hidden data collection; users unaware of how their data is used |
| **Non-compliance** | Compliance | GDPR Article 5 violations — excessive data collection, missing lawful basis |

### LINDDUN Variants

**LINDDUN PRO** (full methodology):
1. Create a DFD of the system
2. For each DFD element and data flow, systematically apply all seven LINDDUN threat categories
3. Elicit threats using knowledge base of privacy threat trees
4. Prioritize based on privacy risk
5. Select privacy-enhancing technologies (PETs) as mitigations

**LINDDUN GO** (lightweight):
- Card-based, game-like approach designed for time-constrained teams
- 56 threat cards organized by LINDDUN category
- Facilitator draws cards; team discusses whether each applies to the system
- Suitable for agile sprint-level privacy reviews (2-3 hours)
- Outputs: ranked privacy threat list and mitigation backlog

### GDPR Mapping

Each LINDDUN threat category maps to specific GDPR obligations:

| LINDDUN Threat | GDPR Article | Obligation |
|---------------|-------------|------------|
| Linkability | Art. 5(1)(e) | Storage limitation; data minimization |
| Identifiability | Art. 25 | Data protection by design and by default; pseudonymization |
| Non-repudiation | Art. 5(1)(f) | Integrity and confidentiality of user data |
| Detectability | Art. 32 | Security of processing; prevent unauthorized access |
| Disclosure of information | Art. 5(1)(f), Art. 32 | Confidentiality obligation; breach notification (Art. 33-34) |
| Unawareness | Art. 13-14 | Transparency obligation; privacy notice requirements |
| Non-compliance | Art. 5 | Principles relating to processing of personal data |

### Privacy-Enhancing Technologies (PETs) as Mitigations

| Threat | PET Mitigation |
|--------|---------------|
| Linkability | k-anonymity, l-diversity, differential privacy |
| Identifiability | Pseudonymization (replace real ID with token), generalization |
| Disclosure | End-to-end encryption, zero-knowledge proofs, secure multi-party computation |
| Non-repudiation | Onion routing (Tor), mix networks, blind signatures |
| Unawareness | Consent management platforms, privacy dashboards, just-in-time notices |

---

## Attack Trees

### Origins

Attack trees were introduced by cryptographer **Bruce Schneier in his 1999 paper "Attack Trees: Modeling security threats"** (Dr. Dobb's Journal). They provide a formal, hierarchical method for analyzing the security of systems by modeling the different ways an attacker might achieve a goal.

### Structure

An attack tree has:
- **Root node**: The attacker's ultimate goal (e.g., "Exfiltrate customer PII")
- **Intermediate nodes**: Sub-goals the attacker must achieve
- **Leaf nodes**: Atomic attacks — specific, observable techniques
- **AND nodes**: All child nodes must be satisfied for the parent to be achieved
- **OR nodes**: Any single child node satisfying the parent goal

### Example: "Compromise Admin Account" Attack Tree

```
Goal: Compromise Admin Account
├── OR
│   ├── Steal Credentials
│   │   ├── OR
│   │   │   ├── Phishing email with credential harvester
│   │   │   ├── Password spray (weak/reused password)
│   │   │   ├── Credential stuffing from breach database
│   │   │   └── LLMNR/NBT-NS poisoning (if on same network segment)
│   ├── Bypass Authentication
│   │   ├── OR
│   │   │   ├── AiTM proxy (EvilGinx2) — steal session token post-MFA
│   │   │   ├── MFA fatigue attack (push notification bombing)
│   │   │   ├── SIM swap (bypass SMS-based MFA)
│   │   │   └── Recovery code theft (from backup email or password manager)
│   └── Exploit Application Vulnerability
│       ├── OR
│       │   ├── Admin panel IDOR (horizontal privilege escalation to admin user)
│       │   ├── JWT algorithm confusion (RS256 public key used as HS256 secret)
│       │   ├── Insecure deserialization (Java/PHP object injection for RCE)
│       │   └── OAuth implicit flow token leakage via open redirect
```

### Assigning Values to Leaf Nodes

Attack trees become quantitative risk tools when values are assigned to leaf nodes:

| Value Type | Description | Use |
|-----------|-------------|-----|
| **Probability** | Likelihood the attacker attempts and succeeds at this leaf | Roll up via AND (multiply) / OR (max/sum) to root |
| **Cost** | Resources required for the attacker (time, money, skills) | Identify cheapest attack paths — prioritize those mitigations |
| **Difficulty** | Attacker skill level required (1=script kiddie, 5=nation-state) | Assess which paths are viable given expected threat actors |
| **Detectability** | Probability the attack is detected at this leaf | Low detectability = higher actual risk |

Propagation rules:
- **AND node probability**: Product of all child probabilities (attacker must succeed at all)
- **OR node probability**: 1 - Product of (1 - P) for each child (succeeds if any child succeeds)
- **AND node cost**: Sum of all child costs (must pay all)
- **OR node cost**: Minimum child cost (attacker picks cheapest path)

### Attack Tree Tools

| Tool | Features | License |
|------|---------|---------|
| **ADTool** | Graphical AND/OR tree editor, quantitative analysis, SAND trees | Free/Open Source |
| **SeaMonster** | Integrates with UML models, security patterns library | Academic/Free |
| **IriusRisk** | Attack tree generation from threat library, risk scoring | Commercial |
| **draw.io** | Manual trees using flowchart shapes; no automated analysis | Freemium |

---

## DREAD Risk Scoring (Legacy, Contextual Use)

### Overview

DREAD was Microsoft's original risk scoring model before CVSS adoption. It scores five factors on a 1-3 scale (or sometimes 1-10) to produce a composite risk score. While largely superseded by CVSS for CVE scoring, DREAD remains useful for **design-level threat scoring** where no CVE exists and CVSS's strict criteria don't apply.

### DREAD Scoring Criteria

| Factor | Question | Score 1 (Low) | Score 2 (Medium) | Score 3 (High) |
|--------|---------|--------------|-----------------|----------------|
| **Damage** | How bad is the damage if exploited? | Minimal data exposure, no PII | Sensitive data exposed, limited scope | Full data breach, system takeover, regulatory penalty |
| **Reproducibility** | How reliably can the attack be reproduced? | Requires rare conditions, timing-dependent | Exploitable sometimes, requires specific state | Works every time, fully deterministic |
| **Exploitability** | What skills/resources does the attacker need? | Requires advanced custom tooling, nation-state | Moderate skill, available exploit framework | Script-kiddie level, point-and-click tool exists |
| **Affected Users** | How many users are impacted? | Single user, limited blast radius | Subset of users, specific tenant | All users, entire platform, all tenants |
| **Discoverability** | How easy is it to discover the vulnerability? | Requires source code access or deep internal knowledge | Requires active testing, fuzzing | Visible in public documentation or automated scanner finds it |

**Total DREAD score**: Sum of all five factors. Range: 5-15.
- 5-7: Low risk
- 8-11: Medium risk
- 12-14: High risk
- 15: Critical risk

### DREAD Limitations

- **Highly subjective**: Different analysts score the same vulnerability differently; scores are not reproducible across organizations
- **CVSS preferred for CVEs**: CVSS has precise metric definitions, is maintained by FIRST, and is universally understood
- **Discoverability controversy**: Some argue discoverability should not affect risk score — if a vulnerability exists, it should be fixed regardless of how easy it is to find
- **Appropriate use cases**: Design-level threats in threat models where no CVE applies; relative prioritization within a single team; quick triage during threat modeling sessions

---

## MITRE ATT&CK Integration

### Using ATT&CK as a Threat Catalog

The MITRE ATT&CK framework provides a comprehensive, empirically grounded catalog of real-world adversary techniques. Integrating ATT&CK into threat modeling grounds the threat analysis in observed attacker behavior rather than theoretical threats.

**Integration workflow:**

1. **Identify attacker profile**: Which threat actor groups (APTs, cybercriminal organizations) are known to target your industry sector and geographic region? (Use ATT&CK Groups: https://attack.mitre.org/groups/)
2. **Extract relevant TTPs**: For each identified threat actor group, extract their known Tactics, Techniques, and Procedures from ATT&CK
3. **Map TTPs to architecture components**: For each ATT&CK technique, identify which components in your DFD are potentially affected
4. **Control coverage assessment**: For each TTP + component pairing, assess whether your existing security controls would detect, prevent, or be ineffective against this technique
5. **Gap identification**: Unmitigated ATT&CK technique against a specific component = threat model finding requiring mitigation
6. **Mitigation selection**: Use ATT&CK Mitigations (M-codes) and MITRE D3FEND countermeasures to identify appropriate defensive controls

### ATT&CK Navigator for Threat Modeling

The **ATT&CK Navigator** (https://mitre-attack.github.io/attack-navigator/) is a web-based tool for visualizing and annotating ATT&CK matrices:

**Creating a threat model layer:**
1. Navigate to ATT&CK Navigator
2. Create a new layer for your asset type (workstation, Linux server, cloud, container, mobile)
3. For each relevant TTP: color-code based on control coverage:
   - **Red**: No detective or preventive control exists
   - **Yellow**: Partial coverage — control exists but has gaps
   - **Green**: Fully mitigated — preventive and detective controls are in place
4. Export the layer as JSON for documentation and tracking
5. Use multi-layer comparison to show coverage evolution over time

**Threat model navigator layers by asset type:**
- `Enterprise - Windows Workstations`: Focus on Initial Access, Execution, Persistence, Credential Access, Lateral Movement
- `Enterprise - Linux Servers`: Focus on Execution, Privilege Escalation, Defense Evasion, Persistence
- `Cloud (AWS/Azure/GCP)`: Use ATT&CK Cloud matrix — focus on Initial Access (Valid Accounts), Privilege Escalation (IAM), Exfiltration (Transfer to Cloud Account)
- `Containers`: Focus on T1610 (Deploy Container), T1611 (Escape to Host), T1525 (Implant Container Image)

### MITRE D3FEND Integration

**D3FEND** (https://d3fend.mitre.org) is MITRE's defensive countermeasure knowledge base. Each D3FEND technique maps to one or more ATT&CK offensive techniques, providing a structured way to identify defensive countermeasures for each threat model finding.

**D3FEND defensive tactics:**
- **Harden**: Remove attack surface (Credential Hardening, Application Hardening, Network Hardening, Platform Hardening, Message Hardening)
- **Detect**: Identify attacks in progress (File Analysis, Identifier Analysis, Message Analysis, Network Traffic Analysis, Process Analysis, User Behavior Analysis)
- **Isolate**: Contain attacker movement (Network Isolation, Execution Isolation, Enclave Isolation)
- **Deceive**: Mislead attackers (Decoy Environment, Decoy File, Decoy Network Resource, Decoy User Credential)
- **Evict**: Remove attacker from the environment (Credential Eviction, Process Eviction, Network Eviction)

**Workflow**: ATT&CK technique (threat) → D3FEND countermeasure (mitigation) → security control implementation

---

## Data Flow Diagrams (DFDs) for Threat Modeling

### DFD Levels

| Level | Name | Description | Use Case |
|-------|------|-------------|---------|
| **Level 0** | Context Diagram | Entire system as a single process; shows external actors and major data flows crossing the system boundary | Executive overview; scope definition |
| **Level 1** | Detailed DFD | System decomposed into major processes and data stores; trust boundaries visible | Primary threat modeling artifact |
| **Level 2+** | Subprocess DFD | Further decomposition of complex Level 1 processes | High-assurance systems, complex subsystems |

### DFD Elements

| Element | Symbol | Description | Example |
|---------|--------|-------------|---------|
| **External Entity** | Rectangle | Source or destination of data outside the system boundary | User browser, mobile app, partner API, payment gateway |
| **Process** | Circle or rounded rectangle | Transforms data; contains logic | Authentication service, payment processor, file upload handler |
| **Data Store** | Parallel horizontal lines (open rectangle) | Stores data at rest | PostgreSQL database, S3 bucket, Redis cache, local filesystem |
| **Data Flow** | Directed arrow | Data in motion between elements | HTTPS request, SQL query, message queue message, file write |
| **Trust Boundary** | Dashed line | Boundary where security properties must be verified | Internet/DMZ boundary, user/admin boundary, network zone boundary |

### Trust Boundaries in Detail

A trust boundary is crossed whenever data moves from a lower-trust context to a higher-trust context (or vice versa). **Every trust boundary crossing is a potential threat location** and must be analyzed.

**Common trust boundaries in web applications:**

| Boundary | From | To | Controls Required |
|----------|------|-----|------------------|
| Internet → DMZ | Public internet | DMZ / WAF | WAF rules, DDoS protection, TLS termination |
| DMZ → Internal | WAF/Load balancer | Application servers | Firewall ACLs, mTLS between services |
| Application → Database | Application tier | Database tier | Parameterized queries, DB credentials in vault, network ACL |
| User → Admin | Regular user context | Administrative functions | Role-based authorization check, step-up authentication, MFA |
| Client → Server | Browser/mobile client | Backend API | TLS 1.3, authentication token validation, input validation |
| Internal → External API | Application | Third-party SaaS API | Egress filtering, API key rotation, data minimization |
| CI/CD → Production | Build pipeline | Cloud deployment | OIDC federation (no long-lived keys), signed artifacts, least-privilege IAM |

### Applying STRIDE to DFD Trust Boundary Crossings

For each data flow crossing a trust boundary, systematically ask:

1. **Spoofing**: Could the source of this data flow be impersonated? (Missing authentication)
2. **Tampering**: Could the data in this flow be modified in transit? (Missing integrity protection)
3. **Repudiation**: Could either party deny this interaction occurred? (Missing logging)
4. **Information Disclosure**: Could this flow be intercepted? (Missing encryption or excessive data exposure)
5. **Denial of Service**: Could this flow be disrupted or the endpoint overwhelmed? (Missing rate limiting or circuit breakers)
6. **Elevation of Privilege**: Does processing this data grant higher privileges than intended? (Missing authorization check)

---

## Practical Threat Modeling Workflow

### Sprint-Level Threat Modeling (Agile)

Designed for development teams that need to threat model within a sprint cycle without blocking delivery:

**Time budget: ~45 minutes per sprint feature**

| Step | Duration | Activity |
|------|---------|---------|
| **1. Input** | 5 min | Gather: user story, architecture change description, any new external integrations |
| **2. Quick DFD** | 15 min | Whiteboard or Miro: draw data flows for the new feature only; identify new trust boundary crossings |
| **3. STRIDE sweep** | 20 min | Apply STRIDE per element to new/modified DFD components; focus effort on new trust boundary crossings |
| **4. Top threats** | 5 min | Prioritize 3-5 highest-risk threats by likelihood × impact; document with unique IDs |
| **5. Security stories** | 5 min | Convert each mitigation to an acceptance criterion or security story in Jira/GitHub Issues |

**Output**: 3-5 threat findings with mitigations as acceptance criteria attached to the feature ticket.

**Recommended tools for sprint-level**: OWASP Threat Dragon (free, DFD-based, GitHub integration), Miro with threat modeling template, Confluence threat model page template.

### Full Application Threat Model (Architecture Review)

For new applications or significant architecture changes requiring comprehensive threat analysis:

**Time budget: ~10 hours total**

| Phase | Duration | Participants | Output |
|-------|---------|-------------|--------|
| **1. Kick-off** | 1 hour | Security engineer, architect, dev lead, product owner | Scope definition, system overview, threat modeling goals |
| **2. DFD creation** | 2 hours | Architect + security engineer | Level 0 + Level 1 DFDs in Threat Dragon or Lucidchart; trust boundaries marked |
| **3. Threat enumeration** | 3 hours | Security engineer, optionally dev lead | STRIDE per element; ATT&CK technique mapping for relevant threat actors; full threat list |
| **4. Risk rating** | 1 hour | Security engineer | CVSS-like scoring or DREAD for each threat; risk register entries |
| **5. Mitigation mapping** | 2 hours | Security engineer + dev lead | Mitigation per threat; assign owner; target implementation date |
| **6. Report** | 1 hour | Security engineer | Threat model document; risk register update; executive summary |

**Threat model document sections:**
1. Scope and assumptions
2. System architecture overview
3. DFDs (Level 0 and Level 1)
4. Assets and data classification
5. Threat actor profiles
6. Threat list with risk ratings
7. Mitigation roadmap
8. Residual risks (accepted risks with rationale and owner)
9. Review history and version control

### Threat Model Review Cadence

| Trigger | Action | Owner |
|---------|--------|-------|
| New system or major feature | Full threat model | Security engineer |
| Sprint feature | Sprint-level threat model | Developer + security champion |
| Architecture change | Update existing threat model | Architect + security engineer |
| Security incident | Post-incident threat model review | Incident response lead |
| Annual review | Refresh all Tier 1 system threat models | Security team |
| Penetration test completion | Compare pen test findings to threat model findings; update gaps | Security engineer |

---

## Threat Modeling Tools

| Tool | Approach | License | Key Features |
|------|---------|---------|-------------|
| **Microsoft Threat Modeling Tool** | STRIDE/DFD | Free | Template library, automatic STRIDE threat generation from element types, custom stencils |
| **OWASP Threat Dragon** | STRIDE/DFD | Free/Open Source | Web-based, desktop app, GitHub integration, threat library, export to JSON/PDF |
| **IriusRisk** | Automated/Risk-based | Commercial | JIRA integration, regulatory standards mapping, threat library, CI/CD pipeline integration |
| **ThreatModeler** | Automated | Commercial | Cloud-native, enterprise threat library, compliance automation, Visio import |
| **Cairis** | Security requirements | Free/Open Source | Full GDPR/persona/environment modeling, risk management, requirements traceability |
| **draw.io / Lucidchart** | Manual/Flexible | Freemium | Custom threat modeling shapes, collaborative, integrates with Confluence |
| **pytm** | Code-based (Python) | Free/Open Source | Define threat model in Python code, auto-generate DFD + threat list, version control friendly |
| **Tutamen Threat Model** | Hybrid | Commercial | CI/CD integration, developer workflow integration |
| **Threagile** | Code-based (YAML) | Free/Open Source | YAML-defined architecture, generates DFD + threats + risk scores, Docker-based |

### pytm Example (Code-Based Threat Modeling)

The **pytm** library (https://github.com/OWASP/pytm) allows threat models to be defined as Python code, enabling version control alongside application code ("Threat Model as Code"):

```python
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor

tm = TM("API Server Threat Model")
tm.description = "REST API with PostgreSQL backend"
tm.isOrdered = True

# Define trust boundaries
internet = Boundary("Internet")
dmz = Boundary("DMZ")
internal = Boundary("Internal Network")

# Define actors and components
user = Actor("User")
user.inBoundary = internet

web = Server("Web API")
web.inBoundary = dmz
web.isEncrypted = True
web.isHardened = True
web.sanitizesInput = True
web.encodesOutput = True

db = Datastore("PostgreSQL")
db.inBoundary = internal
db.isSQL = True
db.isEncrypted = True  # Database encryption at rest
db.isShared = False

# Define data flows
df1 = Dataflow(user, web, "HTTPS Request")
df1.protocol = "HTTPS"
df1.isEncrypted = True
df1.sanitizesInput = False  # Triggers input validation threats

df2 = Dataflow(web, db, "SQL Query")
df2.protocol = "PostgreSQL"
df2.isEncrypted = False  # Triggers unencrypted connection threat
df2.srcPort = 5432

tm.process()  # Generates threats based on element properties and configurations
# Outputs: threat list, DFD (graphviz), HTML report, data flow table
```

Running `python threat_model.py --report` generates an HTML threat report with findings based on the defined properties.

---

## Threat Modeling for Cloud & Microservices

### Cloud-Specific Threats

| Threat | Description | ATT&CK Technique |
|--------|-------------|-------------------|
| **IAM over-permission** | Overly permissive IAM roles enable privilege escalation or lateral movement to sensitive services | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Metadata service SSRF** | SSRF to IMDS endpoint (169.254.169.254) retrieves temporary credentials for attached IAM role | T1552.005 (Credentials from Cloud Instance Metadata) |
| **Storage bucket exposure** | Misconfigured S3/GCS/Blob storage bucket publicly accessible; contains PII, backups, secrets | T1530 (Data from Cloud Storage) |
| **Secrets in environment variables** | Application secrets (DB passwords, API keys) stored in container environment variables; exposed via /proc or container inspection | T1552.001 (Credentials In Files) |
| **Container escape** | Privileged container or hostPath volume mount allows attacker to escape to host OS | T1611 (Escape to Host) |
| **Cross-tenant isolation failure** | Shared infrastructure misconfiguration allows access to another tenant's data or resources | T1580 (Cloud Infrastructure Discovery) |
| **CI/CD pipeline compromise** | Malicious code injected into build pipeline; compromised dependency; secrets exfiltrated from build environment | T1195 (Supply Chain Compromise) |
| **Serverless event injection** | Untrusted data in Lambda/Cloud Function event payload triggers injection if not validated | T1190 (Exploit Public-Facing Application) |

### Microservices Trust Boundaries

In a microservices architecture, each service-to-service call is a trust boundary crossing that must be protected:

| Control | Description | Implementation |
|---------|-------------|----------------|
| **mTLS** | Mutual TLS authentication between services; both sides present certificates | Istio service mesh, Linkerd, Envoy proxy with cert-manager |
| **JWT service tokens** | Short-lived JWT issued by identity provider per service call; validated at receiver | SPIFFE/SPIRE framework, cloud provider service accounts |
| **API Gateway enforcement** | Centralized authentication, rate limiting, and routing at the perimeter | AWS API Gateway, Kong, Apigee, Azure API Management |
| **Service mesh policy** | Fine-grained authorization between services (service A can call service B only on endpoint X) | Istio AuthorizationPolicy, OPA/Gatekeeper |

### Cloud DFD Trust Boundaries

A complete cloud-native application DFD should include these trust boundaries:

```
[End User Browser]
    |———————————————————— (1) Internet → CDN/WAF boundary
[CDN / WAF]
    |———————————————————— (2) WAF → Load Balancer boundary
[Load Balancer]
    |———————————————————— (3) Load Balancer → Application Tier boundary
[Application Tier (ECS/EKS)]
    |———————————————————— (4) Application → Data Tier (VPC private subnet)
[Data Tier: RDS / ElastiCache]

Application ———————————————— (5) Egress → External APIs
[External Third-Party APIs]

Application ———————————————— (6) App → Cloud Metadata Service (IMDS) *** SHOULD BE BLOCKED ***
[EC2/ECS Instance Metadata: 169.254.169.254]

CI/CD Pipeline ————————————— (7) CI/CD → Cloud Deployment (OIDC, no long-lived keys)
[Cloud Deployment Environment]
```

**Threat analysis per boundary crossing:**

| Boundary | STRIDE Application | Key Threats |
|----------|-------------------|-------------|
| (1) Internet → CDN/WAF | D (DDoS), T (request tampering), I (TLS stripping) | Layer 7 DDoS, HTTP request smuggling |
| (2) WAF → Load Balancer | S (WAF bypass), I (unencrypted internal traffic) | Missing re-encryption between WAF and LB |
| (3) LB → Application | E (container escape via misconfiguration), T (request modification) | Overly permissive ingress rules |
| (4) App → Data | T (SQL injection), I (unencrypted DB connection), E (excessive DB permissions) | ORM bypass, unencrypted RDS connection |
| (5) App → External APIs | T (response tampering), I (data sent to untrusted third party) | Missing response validation, excessive data in API calls |
| (6) App → IMDS | I, E (credential theft for IAM role escalation) | SSRF vulnerability; should be blocked at instance level (IMDSv2 required, egress blocked) |
| (7) CI/CD → Deploy | S (supply chain compromise), E (excessive deployment role permissions) | Compromised build artifact, overly permissive deployment IAM role |

---

## Secure Design Principles (Mitigations Catalog)

### Authentication and Authorization

| Principle | Implementation | Threat Mitigated |
|-----------|---------------|-----------------|
| **Zero Trust** | Verify every request regardless of source; no implicit trust based on network location | Lateral movement, insider threat, compromised VPN |
| **MFA everywhere** | Require MFA for all user-facing authentication; prefer phishing-resistant FIDO2/WebAuthn | Credential stuffing, phishing, password spray |
| **OAuth 2.0 + OIDC** | Federated identity for user authentication; avoid rolling your own auth | Spoofing, credential theft |
| **RBAC / ABAC** | Role-Based or Attribute-Based Access Control; explicit authorization per action | Elevation of privilege, IDOR |
| **Least Privilege** | Grant minimum permissions required; no standing admin access; JIT access for privileged operations | Privilege escalation, blast radius limitation |

### Data Protection

| Principle | Implementation | Threat Mitigated |
|-----------|---------------|-----------------|
| **Encrypt at rest** | AES-256 for all data at rest; customer-managed keys for crown jewels | Information disclosure (storage theft) |
| **Encrypt in transit** | TLS 1.3 minimum; HSTS; no TLS 1.0/1.1 | Information disclosure (MITM), tampering |
| **Tokenization** | Replace PII and payment data with tokens; token vault separate from application | Information disclosure, PCI DSS scope reduction |
| **Field-level encryption** | Encrypt sensitive DB columns (SSN, card numbers) at application layer | Disclosure even if DB is compromised |
| **Key management separation** | Keys managed by HSM or cloud KMS; application never stores keys in code or config | Information disclosure, key compromise |

### Input Validation

| Principle | Implementation | Threat Mitigated |
|-----------|---------------|-----------------|
| **Allowlist validation** | Define acceptable input patterns; reject everything else | Injection (SQLi, XSS, XXE, command injection) |
| **Parameterized queries** | Never concatenate user input into SQL strings; use prepared statements | SQL injection |
| **Content Security Policy** | HTTP response header restricting script sources | Cross-site scripting (XSS) |
| **Schema validation** | Validate API requests against OpenAPI schema before processing | Input validation bypass, business logic abuse |
| **File upload validation** | Validate file type by content (magic bytes), not extension; scan uploaded files | Malware upload, path traversal, RCE |

### Defense in Depth

| Principle | Description |
|-----------|-------------|
| **Multiple independent controls** | No single control failure should result in a security breach; stack preventive, detective, and corrective controls |
| **Fail secure** | On error or unexpected condition, default to deny; never fail open to unauthorized access |
| **Separation of privileges** | Admin functions separated from regular user functions at code, infrastructure, and access levels |
| **Compartmentalization** | Blast radius limitation — compromise of one component should not compromise the entire system |
| **Security by obscurity is not security** | Do not rely on secrecy of implementation as a security control; design systems that are secure even if the implementation is known |

### Auditability

| Principle | Implementation | Threat Mitigated |
|-----------|---------------|-----------------|
| **Immutable audit logs** | All privileged actions logged with user ID, timestamp, action, source IP; logs written to write-once (WORM) storage | Repudiation, log tampering |
| **Correlation IDs** | Request ID propagated through all services; enables full request tracing for incident investigation | Investigation capability |
| **Separate logging account** | Logs shipped to a separate cloud account or SIEM that application credentials cannot access | Log deletion, evidence destruction |
| **Security event alerting** | Alert on anomalous patterns (impossible travel, excessive failures, privilege use) | Detection of active attacks |

---

## Threat Modeling Metrics

Measuring the effectiveness of a threat modeling program requires both process metrics (are we doing it?) and outcome metrics (is it working?).

### Process Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Threat model coverage** | % of Tier 1/2 systems with a completed and current threat model | 100% of Tier 1, ≥90% Tier 2 |
| **Mean Time to Threat Model (MTTM)** | Average time from feature request or architecture change to completed threat model | ≤7 days for sprint features; ≤30 days for new systems |
| **Threat model freshness** | % of threat models reviewed/updated within the last 12 months | ≥90% |
| **Security story conversion rate** | % of identified threats that resulted in a security story or acceptance criterion | ≥95% |

### Quality Metrics

| Metric | Description | Notes |
|--------|-------------|-------|
| **Threats found per session** | Number of unique threats identified per threat model engagement | Baseline for improvement; low count may indicate insufficient depth |
| **Threats per STRIDE category** | Distribution across all 6 STRIDE categories | Uneven distribution may indicate blind spots (e.g., if no Repudiation threats ever found) |
| **High/Critical threat rate** | % of threats rated High or Critical | High % may indicate systemic design issues; track trend |
| **Mitigation implementation rate** | % of identified threats with implemented mitigations within agreed timeline | ≥90% within SLA |

### Outcome Metrics

| Metric | Description | Why It Matters |
|--------|-------------|----------------|
| **Threat model vs. pen test finding overlap** | % of pen test findings that were previously identified in threat models | High overlap = effective threat models; low overlap = gaps in threat modeling |
| **Security defects found in design vs. code review vs. testing vs. production** | Distribution of where security defects are first found | Shift-left goal: more found in design/code review, fewer in production |
| **Mean Cost to Remediate by stage** | Average remediation cost at each SDLC stage | Demonstrates business value of shift-left security |
| **Threats accepted as residual risk that were later exploited** | Count of accepted risks that materialized as incidents | High count = risk acceptance criteria need tightening |

---

## Integration with SDLC

### SDLC Gate Requirements

Embedding threat modeling into SDLC gates ensures security analysis happens at decision points where it can influence design:

| SDLC Phase | Security Gate Requirements | Threat Model Activity |
|-----------|--------------------------|----------------------|
| **Requirements** | Abuse case identification; data classification of inputs and outputs | Define assets and attacker goals |
| **Design** | Threat model mandatory for Tier 1/2 systems before design approval | Full threat model or sprint-level model |
| **Development** | Security stories from threat model in backlog; security code review for high-risk components | Developers implement mitigations; security champion reviews |
| **Testing** | Penetration test validates threat model's highest-risk threats; DAST run against test environment | Compare pen test findings to threat model; close gaps |
| **Deployment** | Threat model sign-off in Change Advisory Board (CAB) for Tier 1 systems | Architecture matches threat model assumptions |
| **Operations** | Threat model updated on significant architecture changes; reviewed annually | Living document; update on system changes |

### Security Champion Program

Security champions are developers embedded in product teams who serve as the first line of security defense:

| Role | Responsibilities |
|------|----------------|
| Security Champion | Participate in sprint-level threat models; conduct security code reviews; escalate security concerns to security team |
| Security Team | Conduct full architecture threat models; provide training to champions; review and approve high-risk threat models |
| Architect | Own DFD creation and maintenance; integrate threat model findings into architecture decisions |
| Product Owner | Prioritize security stories from threat model findings; accept residual risks within their risk appetite |

### Threat Model as Code (tmac)

Version-controlling threat models alongside application code enables:
- **Traceability**: Every system change can be linked to a threat model update
- **Review process**: Threat model changes reviewed in pull requests alongside code changes
- **Automation**: CI/CD pipeline can validate that a threat model exists and is not stale
- **Collaboration**: Developers can view and contribute to threat models in the same tools they use for code

**Implementation approaches:**
- **pytm** (Python-based threat model definition)
- **Threagile** (YAML-based threat model definition)
- **Threat Model Markdown** (structured Markdown with threat table conventions)
- **OWASP Threat Dragon JSON** (stored in repository, rendered by Threat Dragon)

### CI/CD Threat Model Integration

```yaml
# Example GitHub Actions threat model validation
name: Threat Model Check
on:
  pull_request:
    paths:
      - 'architecture/**'
      - 'infrastructure/**'
      - '.github/threat-model.json'

jobs:
  threat-model-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate threat model exists
        run: |
          if [ ! -f .github/threat-model.json ]; then
            echo "ERROR: No threat model found for architecture changes"
            exit 1
          fi
      - name: Check threat model freshness
        run: |
          LAST_MODIFIED=$(git log -1 --format=%ci .github/threat-model.json)
          # Fail if threat model is older than 180 days
          python3 scripts/check_tm_freshness.py "$LAST_MODIFIED" 180
```

---

## Resources & Further Reading

### Essential Books

| Title | Author | Notes |
|-------|--------|-------|
| **Threat Modeling: Designing for Security** | Adam Shostack | The definitive reference — comprehensive coverage of STRIDE, DFDs, and real-world application |
| **The Threat Modeling Manifesto** | Community (2020) | https://www.threatmodelingmanifesto.org — four key questions framework |
| **Threat Modeling: A Practical Guide for Development Teams** | Izar Tarandach & Matthew Coles | Practitioner-focused; agile integration; tool guidance |
| **Threat Modeling** | Frank Swiderski & Window Snyder | Original Microsoft threat modeling book; foundational STRIDE coverage |

### OWASP Resources

| Resource | URL | Description |
|----------|-----|-------------|
| Threat Modeling Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html | Quick reference for threat modeling process |
| OWASP Threat Dragon | https://owasp.org/www-project-threat-dragon/ | Free, open-source DFD-based threat modeling tool |
| OWASP pytm | https://owasp.org/www-project-pytm/ | Python-based threat-modeling-as-code framework |
| OWASP Top 10 | https://owasp.org/www-project-top-ten/ | Starting point for web application threats |
| OWASP Application Security Verification Standard (ASVS) | https://owasp.org/www-project-application-security-verification-standard/ | Requirements derived from threat modeling |

### Microsoft Resources

| Resource | URL |
|----------|-----|
| SDL Threat Modeling overview | https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling |
| Threat Modeling Tool download | https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool |
| STRIDE methodology paper (Kohnfelder) | https://adam.shostack.org/microsoft/The-Threats-To-Our-Products.docx |

### NIST Publications

| Publication | Title | Relevance |
|-------------|-------|-----------|
| SP 800-154 | Guide to Data-Centric System Threat Modeling | Data-centric threat modeling methodology |
| SP 800-30 Rev.1 | Guide for Conducting Risk Assessments | Risk assessment process underlying threat modeling |
| SP 800-160 Vol.1 | Systems Security Engineering | Engineering-level security design principles |
| SP 800-218 | Secure Software Development Framework (SSDF) | SDLC integration of security, including threat modeling |

### MITRE Resources

| Resource | URL | Use |
|----------|-----|-----|
| ATT&CK Framework | https://attack.mitre.org | Adversary TTP catalog for threat modeling |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ | Visualize and annotate coverage against ATT&CK |
| D3FEND | https://d3fend.mitre.org | Defensive countermeasures mapped to ATT&CK techniques |
| ATT&CK for Cloud | https://attack.mitre.org/matrices/enterprise/cloud/ | Cloud-specific ATT&CK techniques |
| CAPEC (Attack Patterns) | https://capec.mitre.org | Common Attack Pattern Enumeration and Classification |

### Community and Training

| Resource | Description |
|----------|-------------|
| Threat Modeling Connect (LinkedIn group) | Community of practice for threat modeling practitioners |
| ThreatModCon | Annual threat modeling conference |
| SANS SEC504, SEC540 | Security courses covering threat modeling in penetration testing and DevSecOps context |
| Adam Shostack's blog | https://shostack.org/blog — commentary from the author of the definitive TM book |

---

*Last updated: 2026-04-24 | TeamStarWolf Cybersecurity Reference Library*
