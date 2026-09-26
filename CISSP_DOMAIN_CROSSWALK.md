# CISSP Domain Crosswalk

> **This library is a supplement to the Official Study Guide, not a replacement for it.** The CISSP tests eight domains — some heavily theoretical, some pure management judgment — and this reference is a technical practitioner's library. This crosswalk maps each of the eight domains of the [ISC2 CISSP exam outline](https://www.isc2.org/certifications/cissp/cissp-certification-exam-outline) (effective **April 15, 2024**) onto the docs already in this library, then names — honestly, domain by domain — exactly where the library runs out and you have to open the OSG. Written practitioner-to-practitioner by someone who holds the cert: the goal is to tell you where your day-job knowledge already covers the exam and where it will quietly let you down.

**Related:** [Certifications Reference](CERTIFICATIONS.md) · [Career Paths & Cert Roadmap](CAREER_PATHS.md) · [Interview Prep](INTERVIEW_PREP.md) · [Frameworks Reference](FRAMEWORKS.md) · [GRC Reference](GRC_REFERENCE.md) · [Security Architecture Reference](SECURITY_ARCHITECTURE_REFERENCE.md)

| | |
|---|---|
| **Read this when** | You are planning a CISSP study campaign and want to reuse what this library already teaches, or you are a strong engineer trying to find the *management* and *theory* blind spots the exam punishes |
| **Start at** | [The eight domains at a glance](#the-eight-domains-at-a-glance) for the weight-and-coverage map, [Exam format](#exam-format) for how the CAT actually behaves, [A twelve-week study plan](#a-twelve-week-study-plan) to run the campaign |

---

## The eight domains at a glance

The weights below are the **official April 15, 2024 outline** weights. The "Library depth" column is an honest self-assessment of how far this library carries you before the OSG has to take over.

| Domain | Weight | What it really is | Library depth |
|---|---|---|---|
| **D1 · Security and Risk Management** | 16% | Think like a risk manager, not an engineer: governance, law, ethics, risk math, BCP | Partial — strong on GRC and program mechanics, thin on legal/ethics/risk arithmetic |
| **D2 · Asset Security** | 10% | Data classification, ownership roles, lifecycle, and destruction | Partial — strong on data protection, thin on the role taxonomy and sanitization theory |
| **D3 · Security Architecture and Engineering** | 13% | Secure design, the classical security models, crypto, physical | Solid — minus the formal models and evaluation criteria |
| **D4 · Communication and Network Security** | 13% | Layered models, secure protocols, components, wireless | Deep — you likely over-know this; study to breadth |
| **D5 · Identity and Access Management** | 13% | Access-control models, identity lifecycle, federation, PAM | Deep — minus the biometric math and model taxonomy |
| **D6 · Security Assessment and Testing** | 12% | Test strategies, control testing, audits, process data | Solid — strong on the *doing*, partial on audit governance |
| **D7 · Security Operations** | 13% | SOC, DFIR, incident lifecycle, DR/BC, admin controls | Deep — minus the legal-evidence and admin-control vocabulary |
| **D8 · Software Development Security** | 10% | Secure SDLC, maturity models, secure coding, DB security | Solid — strong on modern AppSec, partial on process and DB theory |
| **Total** | **100%** | | |

The pattern is worth internalizing before you spend a dollar on training: **the library is deepest exactly where the exam is easiest for a practitioner (D4, D5, D7) and shallowest where the exam is hardest for one (D1, D2, and the theory half of D3)**. Budget your study time against the gaps, not against the weights alone.

---

## Exam format

Study to the format, not just the content — the CISSP CAT rewards different behavior than a fixed-form exam.

| Attribute | Detail |
|---|---|
| **Format** | Computerized Adaptive Testing (CAT) in every language since April 2024 — the 250-item linear exam is retired |
| **Length** | 100–150 items |
| **Time** | Maximum 3 hours |
| **Passing** | 700 out of 1000 |
| **Item types** | Multiple choice plus advanced (drag-and-drop, hotspot) items |
| **Coverage** | All eight domains, weighted as above |

Because it is adaptive, you **cannot go back** and change an answer, and the engine escalates difficulty as you answer correctly — feeling like the questions are getting harder is a good sign, not a bad one. Commit to each answer, manage the clock (roughly a minute an item as a floor), and read every question as "which is the *best* answer for a security manager," not "which is technically true." Several options will be technically correct; the exam wants the one that best fits governance, risk, and the ISC2 mindset.

---

## How to use this crosswalk

Each domain section below gives you four things:

- **What it actually tests** — the domain in plain English, keyed to the public outline, in a practitioner's words.
- **Where the library teaches it** — the docs on disk that cover that ground, with what each one actually contributes. Every link resolves to a real file in this library.
- **What the library does not cover — go to the OSG** — the honest gap. These are the topics you will *not* find here (or find only operationally, not as the exam frames them). Source them from the Official Study Guide and official practice tests.
- **Study tip** — the one thing a practitioner most often gets wrong on that domain.

A closing note on honesty: this library was built for operators — blue teamers, red teamers, detection engineers, vuln-management leads. That makes it a genuinely strong companion for the technical two-thirds of the CISSP and a weak one for the management, legal, and formal-theory third. Where a section says "go to the OSG," take it literally.

---

## Domain 1 — Security and Risk Management (16%)

**What it actually tests.** The largest domain, and the most managerial. The CIA triad plus authenticity and non-repudiation; security governance (the policy/standard/procedure/guideline hierarchy, roles and responsibilities, due care vs due diligence); alignment to control frameworks; legal and regulatory exposure (privacy law, cross-border data flows, intellectual property, computer-crime statutes) and the types of investigations and evidence that follow; the **ISC2 Code of Professional Ethics**; business continuity (BIA, RTO/RPO/MTD); personnel security; the full **risk-management lifecycle** including qualitative and quantitative analysis (SLE, ARO, ALE); threat-modeling concepts; supply-chain risk management; and building a security awareness and training program.

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[GRC Reference](GRC_REFERENCE.md)** | Security governance, FAIR risk quantification, TPRM, program management |
| **[GRC Compliance Reference](GRC_COMPLIANCE_REFERENCE.md)** | NIST CSF 2.0, CIS Controls v8, PCI DSS, HIPAA, SOC 2, ISO 27001 as compliance drivers |
| **[Governance, Risk & Compliance discipline](disciplines/governance-risk-compliance.md)** | The GRC discipline framed as a career track and body of practice |
| **[Frameworks Reference](FRAMEWORKS.md)** | Side-by-side of CSF, 800-53, ISO 27001, SOC 2, PCI, CMMC, GDPR |
| **[Cyber Resilience & BCDR Reference](CYBER_RESILIENCE_BCDR_REFERENCE.md)** | BIA, RTO/RPO/MTD, contingency planning, ISO 22301 — the BCP half of D1 |
| **[Supply Chain Security Reference](SUPPLY_CHAIN_SECURITY_REFERENCE.md)** | SCRM, SBOM, SLSA, third-party/OSS risk |
| **[Security Metrics Reference](SECURITY_METRICS_REFERENCE.md)** | Risk metrics and executive reporting |
| **[Privacy Engineering Reference](PRIVACY_ENGINEERING_REFERENCE.md)** | GDPR/CCPA/HIPAA and Privacy by Design — the privacy-law surface |
| **[Threat Modeling Reference](THREAT_MODELING_REFERENCE.md)** | STRIDE/PASTA/attack trees — the threat-modeling concepts D1 introduces |
| **[Insider Threat Reference](INSIDER_THREAT_REFERENCE.md)** | Personnel security and the HR/legal/privacy guardrails |
| **[Social Engineering Reference](SOCIAL_ENGINEERING_REFERENCE.md)** | Security awareness and training program design |

**What the library does not cover — go to the OSG.** The **ISC2 Code of Ethics canons** (memorize them and their *order* — precedence between canons is testable); the exam's **risk arithmetic** as drilled (SLE = AV × EF, ALE = SLE × ARO, safeguard cost/benefit and ROSI); the specific **legal vocabulary** (types of investigations — administrative, criminal, civil, regulatory — plus evidence standards, liability, and computer-crime law by jurisdiction); and the precise ISC2 definitions of governance terms (due care vs due diligence, the document hierarchy). The library gives you FAIR and program mechanics; it does not drill the ALE math or the canons.

**Study tip.** At 16% this is the single biggest slice, and it is where technical candidates bleed points by choosing the *technically* best answer over the *risk/management* best answer. Retrain the instinct now. Memorize the four ethics canons cold, drill the quantitative risk formulas until they are automatic, and learn the difference between a policy, a standard, a procedure, and a guideline.

---

## Domain 2 — Asset Security (10%)

**What it actually tests.** Identifying and classifying information and assets; **data ownership roles** and their distinct responsibilities (owner, controller, processor, custodian, steward, subject); the **data lifecycle** (create, store, use, share, archive, destroy) and the protection appropriate to each **data state** (at rest, in transit, in use); data retention requirements; **data remanence and secure destruction** (clearing, purging, destruction); baseline scoping and tailoring; and data-protection methods (DRM, DLP, CASB).

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Data Security Reference](DATA_SECURITY_REFERENCE.md)** | Classification tiers, sensitivity labels, DLP channels, encryption at rest/in transit/in use, DSPM discovery |
| **[Privacy Engineering Reference](PRIVACY_ENGINEERING_REFERENCE.md)** | Data minimization, anonymization/pseudonymization, DPIA, field-level encryption |
| **[Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md)** | The mechanisms that protect each data state |
| **[Secrets Management Reference](SECRETS_MANAGEMENT_REFERENCE.md)** | Secret and key lifecycle, handling, and rotation |
| **[Controls Mapping](CONTROLS_MAPPING.md)** | Control baselines that back data-handling requirements |

**What the library does not cover — go to the OSG.** The CISSP-specific **data-role taxonomy** and each role's exact duties (owner vs custodian vs steward is a favorite exam distinction); **classification and clearance models** (government vs commercial schemes and their labels); **media sanitization** to exam depth — NIST SP 800-88 *clear / purge / destroy* and the media-decision matrix (the library covers destruction only lightly); **baseline scoping and tailoring** terminology; and data-remanence theory. Source the role definitions and the 800-88 matrix from the OSG.

**Study tip.** D2 is small (10%) and mostly definitions and ordering — cheap points if you memorize the data roles, the lifecycle order, and the sanitization vocabulary. Do not overthink it, and do not let the small weight tempt you to skip it: the questions are gettable.

---

## Domain 3 — Security Architecture and Engineering (13%)

**What it actually tests.** Secure design principles (defense in depth, least privilege, secure defaults, zero trust, privacy by design, secure-by-design); the **classical security models** (Bell-LaPadula, Biba, Clark-Wilson, Brewer-Nash) and modes of operation; **evaluation criteria** (Common Criteria, EAL, and the TCSEC/ITSEC history); the security capabilities of systems (TPM, TEE, memory protection); vulnerabilities across architectures (client/server, cloud, embedded, ICS, IoT, edge, serverless, microservices, HPC); **cryptography** conceptually (symmetric/asymmetric/hashing, PKI, key management, the crypto lifecycle) and cryptanalytic attacks; and physical/environmental security (site design, fire, power, HVAC).

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Security Architecture Reference](SECURITY_ARCHITECTURE_REFERENCE.md)** | Defense-in-depth, zero-trust architecture, secure design patterns |
| **[Zero Trust Reference](ZERO_TRUST_REFERENCE.md)** | NIST SP 800-207, ZTMM — the modern secure-design principle |
| **[Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md)** | Algorithms, PKI, key management, crypto lifecycle |
| **[Post-Quantum Migration Reference](POST_QUANTUM_MIGRATION_REFERENCE.md)** | Crypto-agility and the FIPS 203/204/205 direction |
| **[Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md)** | TPM 2.0, HSM/FIPS 140-3, Secure Boot, confidential computing, side channels |
| **[Physical Security Reference](PHYSICAL_SECURITY_REFERENCE.md)** | NIST PE controls, site and environmental security |
| **[Cloud Security Reference](CLOUD_SECURITY_REFERENCE.md)** | Cloud-architecture vulnerabilities and design |
| **[ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md)** | Purdue model, IEC 62443 — ICS architecture risk |
| **[Firmware & IoT Security Reference](FIRMWARE_IOT_SECURITY_REFERENCE.md)** · **[Edge & Network Device Security](EDGE_DEVICE_SECURITY_REFERENCE.md)** | Embedded, IoT, and edge system weaknesses |
| **[Container](CONTAINER_SECURITY_REFERENCE.md)** · **[Kubernetes](KUBERNETES_SECURITY_REFERENCE.md)** | Microservices and orchestration architecture risk |

**What the library does not cover — go to the OSG.** The **formal security models** are the big gap: Bell-LaPadula (simple-security and \*-property), Biba's integrity axioms, Clark-Wilson, Brewer-Nash / Chinese Wall, Take-Grant, and Graham-Denning — this library is operational, not theoretical, and these are heavily tested (know which model enforces confidentiality vs integrity, and read-up/read-down rules). Also missing: the **reference monitor** concept and its implementation as the **security kernel** within the **trusted computing base (TCB)** — the abstract model of complete, tamperproof access mediation the Orange Book was written to evaluate; **evaluation frameworks** (Common Criteria, EAL 1–7, the TCSEC "Orange Book" lineage); the **security modes of operation** (dedicated, system-high, compartmented, multilevel); and the cryptanalytic-attack taxonomy as tested. Source the models, the reference monitor, and CC/EAL from the OSG.

**Study tip.** This is the most theory-heavy technical domain, and even strong engineers must memorize the classical models. Build a one-page model cheat-sheet (model → confidentiality or integrity → its axioms). The cryptography here is *conceptual* — when and why, not implementation — so resist the urge to go down the algorithm rabbit hole your day job rewards.

---

## Domain 4 — Communication and Network Security (13%)

**What it actually tests.** Secure network architecture (the **OSI and TCP/IP models**, the protocols and attacks at each layer, IP networking, secure protocols like IPsec/TLS/SSH, segmentation and micro-segmentation, SDN, SD-WAN); secure network **components** (firewalls, switches, wireless access points, NAC, endpoints); secure **communication channels** (voice/VoIP, remote access and VPN, multimedia collaboration, virtualized networks, third-party connectivity); and **wireless** security across Wi-Fi, cellular/5G, Bluetooth, Zigbee, and satellite.

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Networking Fundamentals](NETWORKING_FUNDAMENTALS.md)** | OSI model, TCP/IP deep dive, subnetting, routing — the layered core of D4 |
| **[Network Protocols Reference](NETWORK_PROTOCOLS_REFERENCE.md)** | TCP/IP, DNS, TLS, Kerberos/NTLM, the secure-protocol catalog |
| **[Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md)** | DMZ design, VLAN segmentation, firewall policy, IDS/IPS placement, NAC/802.1X |
| **[Network Defense Reference](NETWORK_DEFENSE_REFERENCE.md)** | NSM, NAC, DDoS protection, network monitoring operations |
| **[Network Attacks Reference](NETWORK_ATTACKS_REFERENCE.md)** | ARP/VLAN/LLMNR attacks — what the secure-design controls defend against |
| **[Zero Trust Reference](ZERO_TRUST_REFERENCE.md)** | Micro-segmentation as a network control |
| **[Wireless Security Reference](WIRELESS_SECURITY_REFERENCE.md)** | Wi-Fi (WPA2/WPA3), Bluetooth, RFID/NFC hardening |
| **[Cloud & Network Security](CLOUD_NETWORK_SECURITY.md)** | Virtualized and cloud networking |
| **[Network Security discipline](disciplines/network-security.md)** | The discipline overview |

**What the library does not cover — go to the OSG.** The exam's **protocol-by-layer mapping drills** at a conceptual level; some legacy and telephony topics (PBX, analog voice, specific multimedia-collaboration terms); the CISSP framing of **converged protocols** (FCoE, iSCSI, MPLS) and WAN technologies to exam depth. The gap here is the opposite of most domains — the library is *deeper and more offensive* than the exam needs. Study to the exam's breadth, not the library's depth.

**Study tip.** If you are a practitioner you almost certainly over-know this domain, and that is the trap: the exam wants layer mapping and "which secure protocol replaces which insecure one," not packet-level tradecraft. Memorize the OSI layer → protocol → attack → control table and move on. Do not spend a week here.

---

## Domain 5 — Identity and Access Management (IAM) (13%)

**What it actually tests.** Physical and logical **access control** to assets; **identity management** (the identity lifecycle — provisioning through deprovisioning, registration and proofing, identity providers, federation, SSO, just-in-time); **authentication and authorization** (MFA, biometrics with FAR/FRR/CER, session and credential management); **federated identity** (SAML, OIDC, OAuth, cross-domain trust); the **access-control models** (DAC, MAC, RBAC, ABAC, RuBAC, ReBAC); accountability; and privileged access management.

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Identity & Access Management Reference](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)** | FIDO2/WebAuthn, RBAC/ABAC/ReBAC, federation, SCIM, JIT/PAM, IGA |
| **[Identity Security Reference](IDENTITY_SECURITY_REFERENCE.md)** | IAM/PAM, MFA bypass techniques, vendor controls, identity detection |
| **[Active Directory Security Reference](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md)** | Kerberos, directory architecture, tiered admin model |
| **[Password Security Reference](PASSWORD_SECURITY_REFERENCE.md)** | NIST 800-63B policy, credential storage (Argon2/bcrypt/PBKDF2) |
| **[Zero Trust Reference](ZERO_TRUST_REFERENCE.md)** | Identity as the zero-trust control plane |

**What the library does not cover — go to the OSG.** The exam's **access-control model taxonomy** and its nuances (MAC vs DAC vs RBAC vs RuBAC vs ABAC — and which the exam labels "non-discretionary"); **biometric accuracy metrics** as tested (FAR, FRR, and the CER crossover point); the conceptual **federation flows** at the "which protocol for which scenario" level; **identity proofing and assurance** (the IAL/AAL/FAL levels from NIST 800-63); and the **reference monitor** — the abstraction behind all access mediation, though the exam files its formal treatment under Domain 3's architecture material. The library is vendor- and attack-deep; source the model taxonomy and biometrics math from the OSG.

**Study tip.** Nail the access-control model taxonomy and the biometric metrics — CER is the point where FAR equals FRR, and a lower CER means a better system. Keep the federation trio straight (SAML is XML-based enterprise SSO; OAuth 2.0 is delegated authorization; OIDC is the authentication layer on top of OAuth). Under time pressure, practitioners fumble authentication vs authorization — drill the distinction.

---

## Domain 6 — Security Assessment and Testing (12%)

**What it actually tests.** Designing assessment, test, and audit **strategies** (internal, external, third-party); conducting security **control testing** (vulnerability assessment, penetration testing, log review, synthetic transactions, code review and testing, misuse-case testing, coverage and interface testing, breach-and-attack simulation, compliance checks); **collecting security process data** (account management, management review, KPIs/KRIs, backup verification, training, DR/BC); analyzing and reporting results; and conducting or facilitating **audits**.

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md)** | Scoping, recon, exploitation, post-exploitation, reporting |
| **[Pentest Checklists](PENTEST_CHECKLISTS.md)** | Step-by-step external/internal/AD/web/cloud test checklists |
| **[Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md)** | Vulnerability assessment and program KPIs |
| **[Purple Team Reference](PURPLE_TEAM_REFERENCE.md)** | Control validation and breach-and-attack simulation |
| **[Red Team Reference](RED_TEAM_REFERENCE.md)** | Adversary emulation and rules of engagement |
| **[Security Metrics Reference](SECURITY_METRICS_REFERENCE.md)** | KPIs/KRIs, detection-coverage scoring, executive reporting |
| **[Secure Coding Reference](SECURE_CODING_REFERENCE.md)** | Code review and SAST/DAST as test methods |
| **[Fuzzing & Vulnerability Research](FUZZING_VULNERABILITY_RESEARCH.md)** | Fuzzing and dynamic testing depth |
| **[Run a Coverage-Gap Assessment](guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md)** · **[Run a Purple-Team Exercise](guides/RUN_A_PURPLE_TEAM_EXERCISE.md)** · **[Start a Vuln-Mgmt Program](guides/START_A_VULN_MGMT_PROGRAM.md)** | The assessment activities as runnable procedures |

**What the library does not cover — go to the OSG.** **Audit management** as the exam frames it — internal vs external vs third-party audit roles, the audit lifecycle, and the **SOC report types** (SOC 1 vs SOC 2 vs SOC 3, Type I vs Type II, and who reads each); the formal **test-type definitions** the exam loves (synthetic transactions, misuse-case testing, interface and coverage testing); log-review governance; and "collecting security process data" (account access reviews, the management-review cadence) as a *governance* activity rather than a technical one. The library shows you how to test; source the audit and process-data framing from the OSG.

**Study tip.** The library makes you strong on the *doing*. The exam adds a *governance* layer on top — audit types, report types, and formal test-type definitions. Learn the vocabulary of assessment, not just the practice; a SOC 2 Type II vs Type I question is pure recall and free if you have memorized it.

---

## Domain 7 — Security Operations (13%)

**What it actually tests.** Understanding and complying with **investigations** (evidence collection and handling, reporting, investigative techniques, digital forensics and artifacts); **logging and monitoring** (SIEM, continuous monitoring, egress, UEBA, threat intelligence, threat hunting); configuration and change management; **security operations concepts** (need-to-know, least privilege, separation of duties, privileged-account management, job rotation, SLAs); resource protection; the **incident-management lifecycle** (detection, response, mitigation, reporting, recovery, remediation, lessons learned); detective and preventive **measures** (firewalls, IDS/IPS, allow/deny lists, sandboxing, honeypots, EDR, AI/ML tooling); patch and vulnerability management; **recovery strategies and backup** (RAID, redundancy, recovery sites); disaster recovery; business continuity; and personnel safety.

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md)** | NIST/SANS IR frameworks, live response |
| **[IR Playbooks](IR_PLAYBOOKS.md)** | Ransomware, BEC, exfiltration, DDoS, cloud incident procedures |
| **[SIEM Reference](SIEM_REFERENCE.md)** · **[Network Monitoring Reference](NETWORK_MONITORING_REFERENCE.md)** | Logging, monitoring, and detection engineering |
| **[Digital Forensics Reference](DIGITAL_FORENSICS_REFERENCE.md)** | Order of volatility, chain of custody, host artifacts |
| **[Network Forensics Reference](NETWORK_FORENSICS_REFERENCE.md)** | Packet, flow, and encrypted-traffic reconstruction |
| **[Threat Hunting](THREAT_HUNTING_REFERENCE.md)** · **[Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md)** | Proactive detection and intel-driven operations |
| **[ATT&CK Detection Strategies](detections/strategies/README.md)** · **[Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md)** | The detective-measures catalog |
| **[SOAR Automation Reference](SOAR_AUTOMATION_REFERENCE.md)** | Response automation and playbook design |
| **[Endpoint Security Reference](ENDPOINT_SECURITY_REFERENCE.md)** | EDR and endpoint detective/preventive controls |
| **[Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md)** | 3-2-1 immutable backups, restore testing |
| **[Cyber Resilience & BCDR Reference](CYBER_RESILIENCE_BCDR_REFERENCE.md)** | DR/BC, RTO/RPO, recovery-site strategy |
| **[Honeypot & Deception Reference](HONEYPOT_DECEPTION_REFERENCE.md)** | Honeypots and deception as detective measures |
| **[Respond to Ransomware](guides/RESPOND_TO_RANSOMWARE.md)** · **[Onboard a Log Source](guides/ONBOARD_A_LOG_SOURCE.md)** · **[Hunt for LOTL Activity](guides/HUNT_FOR_LOTL_ACTIVITY.md)** | Operations as runnable procedures |

**What the library does not cover — go to the OSG.** The **administrative controls** the exam stresses as governance concepts (separation of duties, job rotation, mandatory vacation, dual control, need-to-know) — a technical candidate underweights these badly; the CISSP **legal-evidence framing** (evidence types — real, documentary, testimonial; admissibility; chain of custody as legal doctrine; eDiscovery); **recovery-site definitions** (hot, warm, cold, mobile, cloud) and **RAID levels** to exam depth; and the exam's specific **incident-management step order**, which may differ from the NIST/SANS wording you use daily. Source the admin-control and legal-evidence vocabulary from the OSG.

**Study tip.** D7 is a practitioner's home turf and overlaps with D1 — expect it. Two traps: first, the exam's incident lifecycle step *names and order* may not match your day-to-day framework, so learn the ISC2 version; second, it heavily tests administrative controls (SoD, job rotation, mandatory vacation) that engineers skim past. Memorize the recovery-site tiers and RAID basics — they are recall points.

---

## Domain 8 — Software Development Security (10%)

**What it actually tests.** Security in the **SDLC** (development models — Waterfall, Agile, DevOps, DevSecOps; **maturity models** — SAMM, BSIMM, CMMI; change management; integrated product teams); **security controls in development ecosystems** (IDEs, repositories, libraries, CI/CD, application security testing — SAST/DAST/IAST/SCA, runtime protection); assessing software security **effectiveness** (change auditing and logging, risk analysis and mitigation); assessing the security of **acquired software** (COTS, OSS, third-party, managed services, SaaS/IaaS/PaaS); and **secure coding** (guidelines and standards, programming-language weaknesses, API security, secure deployment, OWASP).

**Where the library teaches it.**

| Doc | What it contributes |
|---|---|
| **[Secure Coding Reference](SECURE_CODING_REFERENCE.md)** | OWASP Top 10, input validation, auth/session security, SAST/DAST, supply chain |
| **[DevSecOps Reference](DEVSECOPS_REFERENCE.md)** | CI/CD security, SAST/DAST/SCA tooling, secrets detection, IaC scanning, pipeline gates |
| **[Application Security discipline](disciplines/application-security.md)** | The AppSec discipline overview |
| **[API Security Reference](API_SECURITY_REFERENCE.md)** | OWASP API Top 10, JWT/BOLA/BFLA, API testing |
| **[Web Application Security Reference](WEB_APPLICATION_SECURITY_REFERENCE.md)** | Web vulnerability classes and secure coding |
| **[CWE Weakness Reference](CWE_REFERENCE.md)** | The weakness taxonomy — programming-language weaknesses |
| **[Supply Chain Security Reference](SUPPLY_CHAIN_SECURITY_REFERENCE.md)** | Acquired and third-party software risk, SBOM, SLSA |
| **[Threat-Model an Application](guides/THREAT_MODEL_AN_APPLICATION.md)** | Building security into design as a runnable procedure |

**What the library does not cover — go to the OSG.** The **SDLC models and software-security maturity models** as the exam *contrasts* them (SAMM vs BSIMM vs CMMI — what each measures and when to use it); the software-security-**effectiveness** and change-audit framing; and **database security** concepts the exam tests but the library barely touches — ACID properties, **aggregation and inference**, **polyinstantiation**, and DBMS access controls. The library is practitioner-grade on modern AppSec and DevSecOps; source the SDLC/maturity-model contrasts and the database-security theory from the OSG.

**Study tip.** The library over-delivers on modern AppSec, so the D8 twist is the *process and theory* side: the SDLC models, the maturity-model trio (SAMM/BSIMM/CMMI), and the database concepts (aggregation, inference, polyinstantiation) that never show up in day-to-day coding. Study those specifically — they are the questions you will not intuit from experience.

---

## A twelve-week study plan

A realistic skeleton for a working professional at roughly 8–12 hours a week. It front-loads the heavy, unfamiliar domains (D1–D3), moves fast through the domains a practitioner already knows (D4, D5, D7), and reserves the last two weeks for full-length practice and memorization. Adjust the pace to your own weak spots — the [at-a-glance table](#the-eight-domains-at-a-glance) tells you where your gaps probably are.

| Week | Focus | Domain(s) | Library anchors |
|---|---|---|---|
| **1** | Governance, frameworks, ethics | D1 | [GRC](GRC_REFERENCE.md), [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md), [Frameworks](FRAMEWORKS.md) + OSG ethics/legal |
| **2** | Risk management + math, BCP, supply chain, personnel | D1 | [Cyber Resilience & BCDR](CYBER_RESILIENCE_BCDR_REFERENCE.md), [Supply Chain](SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Security Metrics](SECURITY_METRICS_REFERENCE.md) + OSG risk formulas |
| **3** | Classification, data roles, lifecycle, sanitization | D2 | [Data Security](DATA_SECURITY_REFERENCE.md), [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md) + OSG roles/800-88 |
| **4** | Secure design + the classical security models | D3 | [Security Architecture](SECURITY_ARCHITECTURE_REFERENCE.md), [Zero Trust](ZERO_TRUST_REFERENCE.md) + OSG models/CC/EAL |
| **5** | Cryptography, PKI, physical, system vulnerabilities | D3 | [Cryptography](CRYPTOGRAPHY_REFERENCE.md), [Hardware](HARDWARE_SECURITY_REFERENCE.md), [Physical](PHYSICAL_SECURITY_REFERENCE.md), [Cloud](CLOUD_SECURITY_REFERENCE.md) |
| **6** | Layered models, secure protocols, components, wireless | D4 | [Networking Fundamentals](NETWORKING_FUNDAMENTALS.md), [Network Protocols](NETWORK_PROTOCOLS_REFERENCE.md), [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md), [Wireless](WIRELESS_SECURITY_REFERENCE.md) |
| **7** | Access-control models, lifecycle, federation, PAM | D5 | [IAM](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Password Security](PASSWORD_SECURITY_REFERENCE.md), [AD Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) + OSG biometrics/models |
| **8** | Test strategies, control testing, audits, process data | D6 | [Pentest Methodology](PENETRATION_TESTING_METHODOLOGY.md), [Vuln Mgmt](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Purple Team](PURPLE_TEAM_REFERENCE.md), [Security Metrics](SECURITY_METRICS_REFERENCE.md) + OSG audit/SOC reports |
| **9** | Investigations, logging/monitoring, detective measures | D7 | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md), [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md), [SIEM](SIEM_REFERENCE.md), [Detection Strategies](detections/strategies/README.md) |
| **10** | Incident lifecycle, admin controls, DR/BC + secure SDLC | D7, D8 | [Cyber Resilience & BCDR](CYBER_RESILIENCE_BCDR_REFERENCE.md), [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md), [Secure Coding](SECURE_CODING_REFERENCE.md), [DevSecOps](DEVSECOPS_REFERENCE.md) + OSG SDLC/DB theory |
| **11** | Full-length practice exams + weak-domain drill | All | Re-hit the domain sections above where you scored low; redo risk math, models, taxonomies |
| **12** | Final memorization + logistics + one last practice | All | Cheat-sheets: ethics canons, security models, RAID/recovery sites, biometrics, data roles, ALE math |

Two rules that matter more than the schedule: **take a full-length, timed practice exam before week 11** so you know your real baseline early, and **treat every "+ OSG" cell as mandatory reading**, not optional — those are the gaps this library cannot close.

---

## Sources

- [ISC2 CISSP Certification Exam Outline](https://www.isc2.org/certifications/cissp/cissp-certification-exam-outline) — the official outline, effective April 15, 2024; domains and weights
- [ISC2 CISSP Computerized Adaptive Testing (CAT)](https://www.isc2.org/certifications/cissp/cissp-cat) — CAT format, item count, and time limit
- [ISC2 — Computerized Adaptive Testing for CISSP Examinations in All Languages](https://www.isc2.org/Insights/2024/02/Computerized-Adaptive-Testing-CISSP-Examinations-All-Languages) — retirement of the linear exam
- [ISC2 CISSP Exam Refresh FAQ](https://www.isc2.org/certifications/cissp/cissp-exam-refresh-faq) — the April 2024 refresh detail
- [ISC2 Code of Ethics](https://www.isc2.org/ethics) — the four professional-ethics canons (Domain 1)

---

*CISSP and ISC2 are trademarks of the International Information System Security Certification Consortium, Inc. (ISC2). This crosswalk is an independent, original study aid built only from ISC2's public exam outline and this library's own documents; it is not affiliated with, authorized, sponsored, or endorsed by ISC2, contains no exam content or brain-dump material, and does not reproduce or paraphrase any third-party courseware or study guide. Consult the Official (ISC2) CISSP Study Guide and official practice tests for authoritative exam preparation.*
