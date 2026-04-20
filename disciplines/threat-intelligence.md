# Threat Intelligence

Threat intelligence is the discipline of collecting, analyzing, and acting on information about adversaries — who they are, what they want, how they operate, and what they are targeting right now. Done well, it transforms raw data into decisions: which vulnerabilities to patch first, which detections to build next, which sectors to brief, and how to posture defenses against the specific groups most likely to target your organization. The intelligence cycle — direction, collection, processing, analysis, dissemination, feedback — provides the operational framework, while structured data formats like STIX 2.1 and transport mechanisms like TAXII 2.1 enable machine-speed sharing across platforms and organizations.

The discipline spans four tiers: strategic intelligence informs executive decisions and long-term resource allocation; operational intelligence tracks adversary campaigns and intent; tactical intelligence details specific techniques, tools, and infrastructure; and technical intelligence covers indicators — IP addresses, domains, file hashes, and signatures — that can be directly ingested into security controls. Most practitioners work across all four tiers simultaneously, and the best CTI programs feed directly into detection engineering, vulnerability management, and incident response rather than existing as standalone reporting functions.

---

## Where to Start

Anchor on the intelligence cycle before anything else — it provides the framework that prevents CTI from becoming a firehose of unactionable indicators. Then learn MITRE ATT&CK as the common language for describing adversary behavior; it is the shared vocabulary that allows TI reports, detection rules, and red team plans to reference the same concepts. Pick one platform (MISP or OpenCTI) and learn it hands-on before worrying about commercial alternatives.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Intelligence cycle, indicator types (IOC/TTP), STIX/TAXII basics, MITRE ATT&CK threat group profiles, source evaluation | [MITRE ATT&CK website](https://attack.mitre.org), [MISP community docs](https://www.misp-project.org/documentation/), [Recorded Future University (free)](https://university.recordedfuture.com), [SANS CTI Summit talks (YouTube)](https://www.youtube.com/@SansInstitute) |
| Practitioner | Platform operation (MISP/OpenCTI), threat actor profiling, campaign tracking, pivot techniques, feed curation and deduplication | [OpenCTI deployment labs](https://docs.opencti.io), [MISP Galaxy documentation](https://github.com/MISP/misp-galaxy), [Hatching Triage community](https://tria.ge), [CISA advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) |
| Advanced | Intelligence program design, adversary emulation alignment, deception operations, attribution methodology, fusion center integration | [SANS FOR578 previews (YouTube)](https://www.youtube.com/@SansInstitute), [CrowdStrike annual Global Threat Report](https://www.crowdstrike.com/global-threat-report/), [Mandiant M-Trends](https://www.mandiant.com/m-trends), [CTID publications](https://ctid.mitre-engenuity.org/) |

---

## Free Training

- [SANS Cyber Threat Intelligence Summit Talks](https://www.youtube.com/@SansInstitute) — Annual summit recordings covering advanced CTI methodology, threat actor tracking, and intelligence program design from working analysts; free YouTube archive is among the best CTI content available anywhere
- [Recorded Future University](https://university.recordedfuture.com) — Free learning portal covering intelligence fundamentals, indicator lifecycle, threat actor profiling, and intelligence-driven defense; accessible to anyone without a paid Recorded Future subscription
- [MITRE ATT&CK Training](https://attack.mitre.org/resources/training/cti/) — Free official ATT&CK for CTI course covering how to use ATT&CK as a common language for threat intelligence reporting and sharing
- [OpenCTI Documentation and Community](https://docs.opencti.io) — Free documentation and community resources for the leading modern open-source threat intelligence platform; hands-on platform practice is essential
- [CISA Advisories and Joint Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories) — Free government threat intelligence covering nation-state actor activity, critical infrastructure threats, and joint advisories with NCSC and allied agencies; high-signal, authoritative sourcing
- [Mandiant Threat Intelligence Free Resources](https://www.mandiant.com/resources) — Mandiant's public threat actor profiles, APT group documentation, and campaign summaries represent some of the most accurate adversary research published openly
- [Hatching Triage Community](https://tria.ge) — Free malware sandbox with community intelligence sharing; excellent for understanding malware families and their C2 infrastructure through behavioral analysis
- [BHIS Webcasts on Threat Intelligence](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering threat hunting, intelligence analysis, and CTI program development
- [FIRST.org Resources](https://www.first.org/resources/) — Free guidance on TLP protocol, CVSS scoring, PSIRT operations, and CTI best practices from the global incident response and security community
- [CTI League Resources](https://cti-league.com/resources/) — Volunteer-driven community sharing real threat intelligence during crises; good model for understanding how peer CTI sharing networks operate

---

## Tools & Repositories

### Threat Intelligence Platforms
- [MISP/MISP](https://github.com/MISP/MISP) — The world's most deployed open-source threat intelligence platform; event-based sharing, indicator correlation, galaxy taxonomies, and STIX/TAXII export; the community standard for structured threat sharing across ISACs and government agencies
- [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) — Graph-based open-source TI platform built natively on STIX 2.1; superior for tracking adversary infrastructure, campaign timelines, and relationship mapping; the modern platform of choice for new TI program deployments
- [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) — Open-source SIRP tightly integrated with MISP; bridges threat intelligence platform and case management for operationalizing intelligence during live incidents
- [TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) — Analysis and response engine companion to TheHive; runs automated enrichment analyzers against observables across 100+ intelligence sources

### Feeds & Indicator Management
- [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) — Curated lists of known-good indicators to reduce false positives in MISP deployments; covers CDNs, cloud providers, Alexa top sites, and legitimate infrastructure
- [MISP/misp-galaxy](https://github.com/MISP/misp-galaxy) — Structured threat actor clusters, malware families, ransomware groups, and threat taxonomies in MISP Galaxy format; the most comprehensive open threat actor library available
- [pan-unit42/iocs](https://github.com/pan-unit42/iocs) — Palo Alto Unit 42 public IOC releases from active threat research; high-quality vetted indicators from one of the industry's most respected research teams
- [stamparm/ipsum](https://github.com/stamparm/ipsum) — Daily updated IP threat intelligence aggregating blacklists from dozens of public sources; lightweight and useful as a free enrichment feed
- [intelowl/IntelOwl](https://github.com/intelowl/IntelOwl) — Aggregates dozens of threat intelligence analyzers into a single API; integrates with VirusTotal, MISP, OTX, Shodan, and 100+ sources for automated IOC enrichment at scale

### STIX / TAXII & Structured Data
- [oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) — The official OASIS Python library for creating, parsing, and validating STIX 2.x objects; essential for programmatic threat intelligence platform integration
- [oasis-open/cti-taxii-server](https://github.com/oasis-open/cti-taxii-server) — Reference TAXII 2.x server implementation for standing up a standards-compliant sharing endpoint
- [mitre/cti](https://github.com/mitre/cti) — The MITRE ATT&CK STIX repository; all Enterprise, ICS, and Mobile ATT&CK data in machine-readable STIX 2.0/2.1 format for programmatic consumption

### ATT&CK & Threat Mapping
- [mitre/attack-navigator](https://github.com/mitre/attack-navigator) — The official ATT&CK Navigator for heatmap visualization; maps threat actor techniques, coverage gaps, and campaign profiles
- [center-for-threat-informed-defense/attack_flow](https://github.com/center-for-threat-informed-defense/attack_flow) — CTID's Attack Flow project for modeling adversary behavior as linked sequences of ATT&CK techniques; elevates TI reports from lists of techniques to structured attack narratives
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — Generic SIEM detection rule format; TI analysts use Sigma to convert intelligence into detections deployable across Splunk, Elastic, Microsoft Sentinel, and 30+ other platforms

### Hunting & Enrichment Utilities
- [Te-k/harpoon](https://github.com/Te-k/harpoon) — CLI tool for gathering intelligence from dozens of APIs (Shodan, Censys, VirusTotal, Hybrid Analysis, PassiveDNS); reduces pivot time from indicators to adversary infrastructure
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata; standardized event schemas that normalize telemetry for threat hunting and TI correlation across SIEM platforms

---

## Commercial & Enterprise Platforms

Open-source tools cover analyst workflows well, but enterprise TI programs typically layer in commercial platforms for automated enrichment, curated finished intelligence, and scale. These platforms dominate the enterprise market.

| Platform | Strength |
|---|---|
| **Recorded Future** | The market leader for machine-speed threat intelligence; aggregates open web, dark web, paste sites, and technical sources into a unified intelligence graph; strongest for strategic and operational intelligence at enterprise scale; real-time alerting and API integration with every major SIEM |
| **Mandiant Advantage (Google)** | Unmatched adversary research depth from decades of IR engagements; the most accurate APT profiles in the industry; finished intelligence from the firm that coined "Advanced Persistent Threat"; now part of Google Cloud |
| **CrowdStrike Falcon Intelligence** | Integrated with the Falcon EDR platform; adversary tracking focused on eCrime and nation-state groups with real-time alerts and ATT&CK-mapped reporting; Adversary Intelligence module provides named threat actor dossiers |
| **ThreatConnect** | TI platform and SOAR hybrid; strongest for operationalizing intelligence into detection and response workflows; extensive integration library and CAL (Collective Analytics Layer) for automated enrichment |
| **Anomali ThreatStream** | Enterprise TI platform with strong STIX/TAXII support and ISAC integration; well-suited for organizations operating across multiple intelligence sharing communities |
| **Silobreaker** | Natural language intelligence aggregation and geopolitical analysis; strongest for strategic intelligence, executive reporting, and early warning on emerging threats |
| **EclecticIQ Platform** | European-headquartered TI platform with strong EU government adoption; STIX/TAXII native, excellent for intelligence sharing network operators |
| **MISP (self-hosted)** | The dominant open-source option across government, financial sector, and ISACs; full-featured with no per-indicator licensing; requires operational investment to run at scale |
| **OpenCTI (self-hosted/SaaS)** | The modern open-source platform of choice for new deployments; STIX 2.1 native, graph-based, and excellent API ecosystem |

---

## NIST 800-53 Control Alignment

Threat intelligence programs support and are supported by multiple [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) control families. CTI is not a standalone compliance control — it is the operational input that makes other controls more effective and targeted.

| Control Family | Control ID(s) | Threat Intelligence Application |
|---|---|---|
| Risk Assessment (RA) | RA-3, RA-10 | Threat intelligence informs risk assessments by providing adversary context: which threat actors target your sector, what techniques they use, and which assets they prioritize — turning generic risk ratings into adversary-informed risk priorities |
| Risk Assessment (RA) | RA-5, RA-5(2) | Vulnerability intelligence: correlating CVE severity with active exploitation evidence from CTI feeds; prioritizing patches based on adversary tooling observed in campaigns |
| Incident Response (IR) | IR-4, IR-8 | Intelligence-driven IR: threat actor TTPs inform IR playbook design; CTI platforms provide campaign context during active incidents to accelerate scope determination and attacker eviction |
| System and Information Integrity (SI) | SI-5 | Security alerts and advisories: government CTI (CISA, MS-ISAC) and commercial feeds provide advance warning of exploitation campaigns; SI-5 requires organizations to receive and act on this intelligence |
| Planning (PL) | PL-7, PL-8 | Concept of operations for security: CTI-informed threat models inform security architecture decisions and guide defensive prioritization at the program planning level |
| Program Management (PM) | PM-9, PM-16 | Threat awareness program: formal CTI program supports enterprise risk management and provides threat context for the supply chain risk management program |
| Supply Chain Risk Management (SR) | SR-6, SR-8 | Supply chain intelligence: monitoring for adversary targeting of software supply chains, tracking vulnerability disclosures in third-party components, and receiving threat notifications for critical supplier relationships |
| Audit and Accountability (AU) | AU-6 | Audit review informed by CTI: threat intelligence drives the prioritization of log review and correlation; SIEM rules are tuned against known adversary TTPs rather than generic anomaly thresholds |
| Configuration Management (CM) | CM-4 | Security impact analysis: CTI on exploitation techniques for specific vulnerabilities informs the risk analysis of unpatched configurations and prioritizes remediation urgency |

---

## ATT&CK Coverage

Threat intelligence practitioners use the [MITRE ATT&CK framework](https://attack.mitre.org) as the primary language for describing, tracking, and communicating adversary behavior. The CTI use case is not just mapping techniques — it is tracking which groups use which techniques and translating that into detection priorities and adversary emulation plans.

| Technique | ID | How Threat Intelligence Addresses It |
|---|---|---|
| Phishing | [T1566](https://attack.mitre.org/techniques/T1566/) | CTI tracks phishing kit evolution, lure themes per threat actor, and infrastructure patterns; enables proactive blocking of phishing domains before campaigns hit the inbox |
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Credential compromise intelligence from dark web monitoring; breach correlation against internal account lists; early warning when employee credentials appear in stealer log dumps |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Malware family TTPs inform detection rule development; knowing which interpreter a threat actor prefers (PowerShell vs. WMI vs. Python) drives targeted detection engineering |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | C2 infrastructure tracking; domain reputation feeds; threat actor C2 framework profiling enables network-level blocking before exfiltration occurs |
| Supply Chain Compromise | [T1195](https://attack.mitre.org/techniques/T1195/) | Software supply chain intelligence: tracking adversary targeting of open-source repositories, managed service providers, and build pipelines; SolarWinds and 3CX attacks were supply chain CTI events |
| Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) | Vulnerability exploitation intelligence: CTI feeds track active exploitation of CVEs, often before vendor patches are available; enables emergency mitigations and hunting for compromise indicators |
| Lateral Movement via Remote Services | [T1021](https://attack.mitre.org/techniques/T1021/) | Threat actor playbook analysis reveals preferred lateral movement techniques; CTI-informed detection rules target the specific tool combinations known adversaries use |
| Data Encrypted for Impact (Ransomware) | [T1486](https://attack.mitre.org/techniques/T1486/) | Ransomware group tracking: monitoring RaaS affiliate activity, negotiation site intelligence, leak site monitoring; early warning on campaigns targeting specific sectors or geographies |
| Trusted Relationship | [T1199](https://attack.mitre.org/techniques/T1199/) | Third-party and MSP compromise intelligence: tracking adversary exploitation of managed service provider access to pivot into customer environments |
| Gather Victim Identity Information | [T1589](https://attack.mitre.org/techniques/T1589/) | Open source intelligence (OSINT) monitoring for adversary reconnaissance against your organization; dark web monitoring for leaked employee data, org charts, and internal documentation |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Intelligence-Driven Incident Response | Rebekah Brown & Scott Roberts | The definitive practitioner guide to building a CTI program; covers the intelligence cycle, ATT&CK integration, and operationalizing intelligence in real SOC workflows |
| The Intelligence-Driven Computer Network Defense Paper | Hutchins, Cloppert, Amin | The original Lockheed Martin Kill Chain paper that defined adversary-focused defense; free PDF; the foundational concept behind threat-informed defense programs |
| The Diamond Model of Intrusion Analysis | Caltagirone, Pendergast, Betz | Free academic paper defining the adversary-capability-infrastructure-victim model; the analytical framework underlying most modern TI platforms |
| Structured Analytic Techniques for Intelligence Analysis | Heuer & Pherson | Intelligence community analytical tradecraft methods applied to cyber threat intelligence; teaches rigorous analysis over gut-feel attribution |
| Applied Network Security Monitoring | Bejtlich | The NSM foundation underpinning how telemetry feeds CTI analysis and hunting; essential for understanding how collected data becomes actionable intelligence |

---

## Certifications

- **GCTI** (GIAC Cyber Threat Intelligence) — The premier CTI certification; validates skills in intelligence collection, analysis, ATT&CK mapping, and threat actor profiling; the most recognized credential for TI practitioners; pairs with SANS FOR578
- **CREST CCTIM** (CREST Certified Cyber Threat Intelligence Manager) — UK and international credential validating CTI management and analysis competency; recognized across financial sector and government programs in CREST member countries
- **Certified Threat Intelligence Analyst (CTIA — EC-Council)** — Covers intelligence cycle, threat hunting, and dark web monitoring; more accessible entry-level option; less technically demanding than GCTI but widely recognized in HR screening

---

## Channels

- [SANS Cyber Threat Intelligence Summit](https://www.youtube.com/@SansInstitute) — Annual summit talks covering adversary tracking, intelligence program design, and TI methodology from working analysts; some of the best free CTI content available
- [Mandiant](https://www.youtube.com/@Mandiant) — APT research presentations, threat actor deep dives, and IR case studies from the field's most prolific adversary research team
- [CrowdStrike](https://www.youtube.com/@CrowdStrike) — Adversary intelligence briefings, eCrime and nation-state tracking, and annual Global Threat Report analysis
- [CISA](https://www.youtube.com/@cisagov) — Official government advisories, joint alert analyses, and critical infrastructure threat briefings
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Free webcasts on threat hunting, intelligence-driven defense, and SOC integration of threat intelligence

---

## Who to Follow

- [@riskybusiness](https://x.com/riskybusiness) — Risky Business podcast; sharp analysis of threat intelligence news and adversary activity from Patrick Gray and Adam Boileau
- [@MsftSecIntel](https://x.com/MsftSecIntel) — Microsoft Threat Intelligence; nation-state and eCrime actor tracking, Volt Typhoon analysis, and MSTIC research publications
- [@Unit42_Intel](https://x.com/Unit42_Intel) — Palo Alto Unit 42; prolific IOC releases and detailed threat actor campaign analysis
- [@CrowdStrike](https://x.com/CrowdStrike) — Adversary naming, eCrime and APT intelligence briefings, and annual Global Threat Report content
- [@Mandiant](https://x.com/Mandiant) — APT research, incident findings, and adversary infrastructure analysis
- [@campuscodi](https://x.com/campuscodi) — Catalin Cimpanu; fast and accurate threat intelligence reporting on malware, APTs, and cybercrime
- [@vxunderground](https://x.com/vxunderground) — Malware sample library and threat intelligence aggregation; visibility into crimeware and APT tooling landscape
- [@GovCERT_CH](https://x.com/GovCERT_CH) — Swiss CERT; high-quality technical IOC releases and campaign analysis
- [@MISP_Project](https://x.com/MISPProject) — Platform updates, new galaxy additions, and community intelligence sharing news

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — The recommended ATT&CK analysis surface for TI workflows; load threat actor profiles, map campaign techniques, correlate with MISP and OpenCTI integrations, and export STIX bundles for sharing
- [MITRE ATT&CK](https://attack.mitre.org) — The universal language for describing adversary behavior; 600+ techniques with real-world procedure examples, threat group mappings, and campaign documentation
- [MISP Project](https://www.misp-project.org) — Community hub for the world's most deployed open-source TI platform; documentation, galaxy updates, and sharing community links
- [OpenCTI Platform](https://www.opencti.io) — Documentation and community for the leading modern open-source TI platform
- [FIRST.org TLP Standard](https://www.first.org/tlp/) — The Traffic Light Protocol standard for intelligence sharing classification; required knowledge for any CTI practitioner sharing intelligence across organizations
- [The Diamond Model](https://www.activeresponse.org/the-diamond-model/) — Free original paper defining the analytic model that underlies how most TI platforms structure adversary relationships
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) — The original kill chain paper; foundational framework for structuring TI around adversary operations
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) — The standard transport mechanism for STIX-based intelligence sharing
- [CrowdStrike Adversary Universe](https://adversary.crowdstrike.com) — Free publicly accessible threat actor profiles with ATT&CK mappings and campaign descriptions

---

## Related Disciplines

- [detection-engineering.md](detection-engineering.md) — Threat intelligence is the fuel that powers detection engineering: CTI-derived TTPs translate directly into Sigma rules, YARA signatures, and SIEM correlation logic; the best detection programs are threat-informed, meaning detections are built against the specific techniques of adversaries most likely to target the organization
- [incident-response.md](incident-response.md) — CTI and IR are tightly coupled operational disciplines: during an active incident, threat intelligence provides campaign context that accelerates attacker identification, scope determination, and eviction; post-incident, IR findings feed back into the intelligence cycle as new adversary data
- [vulnerability-management.md](vulnerability-management.md) — Threat intelligence transforms vulnerability management from CVSS-score-driven prioritization to exploitation-evidence-driven prioritization; knowing which CVEs are actively exploited by specific adversary groups enables risk-ranked patching that matches actual threat exposure
- [cloud-security.md](cloud-security.md) — Cloud-targeted threat groups (Scattered Spider, APT29 targeting Azure, UNC3944) require cloud-specific CTI; understanding adversary techniques for abusing cloud IAM, storage, and compute helps cloud security teams prioritize which misconfigurations to fix first
- [identity-access-management.md](identity-access-management.md) — Credential theft, AiTM phishing, and MFA fatigue campaigns are the dominant initial access technique for many tracked adversary groups; CTI on these campaigns drives IAM control prioritization and phishing-resistant MFA adoption timelines
- [governance-risk-compliance.md](governance-risk-compliance.md) — Threat intelligence informs risk register entries with adversary-contextualized likelihood ratings; CTI outputs feed the threat model that underpins enterprise risk assessments and compliance program scoping decisions
