# Threat Intelligence

Threat intelligence is the discipline of collecting, processing, analyzing, and disseminating information about adversaries, their capabilities, and their intent to support decision-making across security operations. The intelligence cycle — direction, collection, processing, analysis, production, and dissemination — provides the operational framework that separates a mature CTI program from a reactive indicator feed. Intelligence is typically categorized into four tiers: strategic intelligence informs executive and board-level decisions about risk and investment; operational intelligence supports campaign tracking and incident response planning; tactical intelligence guides detection engineering and hunting hypothesis development; and technical intelligence covers raw indicators of compromise such as IP addresses, domains, file hashes, and malware signatures. Each tier requires different sources, different analytical methodologies, and different consumer audiences.

Structured data formats have become the connective tissue of modern threat intelligence operations. STIX 2.1 (Structured Threat Information Expression) provides the object model for representing threats — adversaries, campaigns, malware, attack patterns, and indicators — while TAXII 2.1 (Trusted Automated eXchange of Intelligence Information) defines the transport layer for sharing STIX bundles between platforms and organizations. MITRE ATT&CK has emerged as the universal language for describing adversary behavior at the technique level, enabling analysts to communicate findings, map detection coverage, and compare threat actors using a common vocabulary. Mastery of ATT&CK is no longer optional for a working CTI analyst — it is a baseline requirement.

Artificial intelligence is rapidly reshaping how CTI teams handle enrichment, correlation, and finished intelligence production. Machine learning models now assist with automated malware family classification, infrastructure clustering, and dark web monitoring at scales that exceed analyst capacity. However, the analytical judgment required to assess source reliability, evaluate attribution confidence, and produce actionable finished intelligence remains a fundamentally human skill. The most effective CTI programs combine automated collection and enrichment pipelines with structured analytical methodology and close feedback loops with detection engineering and incident response teams.

---

## Where to Start

Anchor on the intelligence cycle first — it provides the operational framework that keeps CTI work purposeful rather than reactive. Then internalize MITRE ATT&CK as the common language for describing adversary behavior, before moving to hands-on platform operation with MISP or OpenCTI.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Intelligence cycle, source types (OSINT/HUMINT/SIGINT), indicator types, STIX/TAXII basics, MITRE ATT&CK framework | MITRE ATT&CK, OpenCTI community docs, SANS Cyber Threat Intelligence Summit talks (free YouTube) |
| Practitioner | Platform operation (MISP/OpenCTI/ThreatConnect), threat group profiling, campaign tracking, feed curation, pivot techniques | MISP/OpenCTI deployment labs, Recorded Future University (free), CTI-League resources |
| Advanced | Intelligence program design, adversary emulation alignment, deception operations, attribution methodology, fusion center integration | SANS FOR578 content (audit free), CISA advisories, threat actor deep dives from CrowdStrike/Mandiant annual reports |

---

## Free Training

- **SANS Cyber Threat Intelligence Summit Talks (YouTube)** — Annual free recordings covering advanced CTI methodology, threat actor tracking, and intelligence program design from working analysts
- **Recorded Future University** — Free learning portal covering intelligence fundamentals, indicator lifecycle, threat actor profiling, and intelligence-driven defense
- **MITRE ATT&CK Website and Training** — Free framework documentation, adversary group profiles, and the official ATT&CK for CTI course covering how to use ATT&CK as a common language for TI reporting
- **OpenCTI Documentation and Community** — Free documentation and community resources for the leading open-source threat intelligence platform
- **CISA Advisories and TLP Reports** — Free government threat intelligence covering nation-state actor activity, critical infrastructure threats, and joint advisories with NCSC and allied agencies
- **Mandiant Threat Intelligence Free Tier** — Mandiant public threat actor profiles, campaign summaries, and APT group documentation represent some of the most accurate adversary research available
- **Hatching Triage Community** — Free malware sandbox with community intelligence sharing; excellent for understanding malware families and their C2 infrastructure
- **BHIS Webcasts on Threat Intelligence** — Free webcasts covering threat hunting, intelligence analysis, and CTI program development from John Strand and practitioners
- **ThreatConnect Blog and Academy** — Free educational content on the intelligence cycle, TI platform best practices, and operationalizing intelligence in SOC workflows
- **FIRST.org Resources** — Free guidance from the global Forum of Incident Response and Security Teams including TLP protocol documentation, CVSS scoring guides, and CTI best practices

---

## Tools & Repositories

### Threat Intelligence Platforms
- [MISP/MISP](https://github.com/MISP/MISP) — The world's most deployed open-source threat intelligence platform; event-based sharing, indicator correlation, galaxy taxonomies, and STIX/TAXII export; the community standard for structured threat sharing
- [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) — Graph-based open-source TI platform built natively on STIX 2.1; superior for tracking adversary infrastructure, campaign timelines, and relationship mapping; the modern alternative to MISP for new deployments
- [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) — Open-source SIRP tightly integrated with MISP; bridges TI platform and case management for operationalizing intelligence during incidents
- [TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) — Analysis and response engine companion to TheHive; runs automated enrichment analyzers and active response actions against observables

### Feeds & Indicator Management
- [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) — Curated lists of known-good indicators to reduce false positives in MISP; covers CDNs, cloud providers, Alexa top sites, and legitimate infrastructure
- [MISP/misp-galaxy](https://github.com/MISP/misp-galaxy) — Structured threat actor clusters, malware families, and threat taxonomies in MISP Galaxy format; the most comprehensive open threat actor library available
- [pan-unit42/iocs](https://github.com/pan-unit42/iocs) — Palo Alto Unit 42 public IOC releases from their threat research; high-quality vetted indicators from one of the industry's most respected research teams
- [stamparm/ipsum](https://github.com/stamparm/ipsum) — Daily updated IP threat intelligence aggregating blacklists from dozens of sources; useful as a free enrichment feed
- [davidonzo/Threat-Intel](https://github.com/davidonzo/Threat-Intel) — Community-contributed IOC lists for integration into MISP or direct ingestion into SIEM pipelines

### STIX / TAXII & Structured Data
- [oasis-open/cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) — The official OASIS Python library for creating, parsing, and validating STIX 2.x objects; essential for programmatic TI platform integration
- [oasis-open/cti-taxii-server](https://github.com/oasis-open/cti-taxii-server) — Reference TAXII 2.x server implementation; use for standing up a standards-compliant sharing endpoint or testing platform integrations
- [mitre/cti](https://github.com/mitre/cti) — The MITRE ATT&CK STIX repository; all ATT&CK Enterprise, ICS, and Mobile data in machine-readable STIX 2.0/2.1 format for programmatic consumption
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — Generic SIEM detection rule format with thousands of community rules; TI analysts use Sigma to convert intelligence into detections across Splunk, Elastic, Microsoft Sentinel, and more

### ATT&CK & Threat Mapping
- [mitre/attack-navigator](https://github.com/mitre/attack-navigator) — The official MITRE ATT&CK Navigator for heatmap visualization; used to map threat actor techniques, coverage gaps, and campaign profiles
- [center-for-threat-informed-defense/attack_flow](https://github.com/center-for-threat-informed-defense/attack_flow) — CTID Attack Flow project for modeling adversary behavior as linked sequences of ATT&CK techniques; elevates TI reports from lists of techniques to structured attack narratives

### Hunting & Enrichment Utilities
- [intelowl/IntelOwl](https://github.com/intelowl/IntelOwl) — Aggregates dozens of threat intelligence analyzers into a single API; integrates with VirusTotal, MISP, OTX, Shodan, and 100+ sources for automated IOC enrichment
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata; defines data models for security events that help analysts normalize telemetry for threat hunting and TI correlation
- [Te-k/harpoon](https://github.com/Te-k/harpoon) — CLI tool for gathering threat intelligence from dozens of APIs (Shodan, Censys, VirusTotal, Hybrid Analysis, PassiveDNS); reduces pivot time from indicators to infrastructure

---

## Commercial & Enterprise Platforms

The open-source ecosystem covers analyst workflows well, but enterprise deployments typically layer in commercial platforms for scale, automated enrichment, and curated finished intelligence. The platforms below dominate the enterprise market.

| Platform | Strength |
|---|---|
| **Recorded Future** | The market leader for machine-speed threat intelligence; aggregates open web, dark web, and technical sources into a single graph; strongest for strategic and operational intelligence at scale |
| **Mandiant Advantage** | Google-owned; unmatched adversary research depth from Mandiant IR engagements; APT profiles, campaign timelines, and finished intelligence from the firm that coined "Advanced Persistent Threat" |
| **CrowdStrike Falcon Intelligence** | Integrated with the Falcon EDR platform; adversary tracking focused on eCrime and nation-state groups with real-time alerts and ATT&CK-mapped reporting |
| **ThreatConnect** | TI platform + SOAR hybrid; strongest for operationalizing intelligence into detection and response workflows; extensive integration library |
| **Anomali ThreatStream** | Enterprise TI platform with strong STIX/TAXII support and ISAC integration; good for organizations operating across multiple intelligence sharing communities |
| **MISP (self-hosted)** | The dominant open-source option in government, financial sector, and ISACs; full-featured with no per-indicator licensing |
| **OpenCTI (self-hosted / SaaS)** | The modern open-source platform of choice for new TI program deployments; STIX 2.1 native, graph-based, excellent API |
| **EclecticIQ Platform** | European-headquartered enterprise TI platform with strong EU government adoption; STIX/TAXII native, excellent for sharing network operators |
| **Silobreaker** | Natural language intelligence aggregation and geopolitical analysis; strongest for strategic intelligence and executive reporting |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Intelligence-Driven Computer Network Defense Paper | Hutchins, Cloppert, Amin | The original Lockheed Martin Kill Chain paper that defined adversary-focused defense; free PDF; the foundational concept behind threat-informed defense |
| Intelligence-Driven Incident Response | Rebekah Brown & Scott Roberts | The definitive practitioner guide to building a CTI program; covers the intelligence cycle, ATT&CK integration, and operationalizing intelligence in real SOC workflows |
| The Diamond Model of Intrusion Analysis | Caltagirone, Pendergast, Betz | Free academic paper defining the adversary-capability-infrastructure-victim model; the analytical framework underlying most modern TI platforms |
| Threat Intelligence and Me | Recorded Future | Free ebook covering CTI fundamentals with practical workflow guidance; accessible starting point before tackling more technical texts |
| Applied Network Security Monitoring | Bejtlich | Strong NSM foundation that underpins how collected telemetry feeds CTI analysis and hunting; chapter-length treatment of the analyst mindset |

---

## Certifications

- **GCTI** (GIAC Cyber Threat Intelligence) — The premier CTI certification; validates skills in intelligence collection, analysis, ATT&CK mapping, and threat actor profiling; pairs with SANS FOR578
- **CREST CCTIM** (CREST Certified Cyber Threat Intelligence Manager) — UK/international credential validating CTI management and analysis competency; recognized across financial sector and government
- **Certified Threat Intelligence Analyst (CTIA — EC-Council)** — Covers intelligence cycle, threat hunting, and dark web monitoring; more accessible entry-level option; less regarded than GCTI in practice
- **Recorded Future Intelligence Certification** — Free platform-specific certification from Recorded Future covering intelligence analysis methodology; valuable signal for employers if you use the platform

---

## Channels

- [SANS Cyber Threat Intelligence Summit](https://www.youtube.com/@SansInstitute) — Annual summit talks covering adversary tracking, intelligence program design, and TI methodology from working analysts; some of the best free CTI content available
- [Mandiant Research](https://www.youtube.com/@Mandiant) — APT research presentations, threat actor deep dives, and IR case studies from the field's most prolific adversary research team
- [CrowdStrike](https://www.youtube.com/@CrowdStrike) — Adversary intelligence briefings, eCrime and nation-state tracking, and annual Global Threat Report analysis
- [The Shadowserver Foundation](https://www.youtube.com/@ShadowserverFoundation) — Internet-scanning and threat intelligence research; daily feeds covering malware C2, botnets, and exposed infrastructure
- [CISA](https://www.youtube.com/@cisagov) — Official government advisories, joint alert analyses, and critical infrastructure threat briefings
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Free webcasts on threat hunting, intelligence-driven defense, and SOC workflows

---

## Who to Follow

- [@riskybusiness](https://x.com/riskybusiness) — Risky Business podcast; sharp analysis of threat intelligence news and adversary activity from Patrick Gray and Adam Boileau
- [@MsftSecIntel](https://x.com/MsftSecIntel) — Microsoft Threat Intelligence; nation-state and eCrime actor tracking, Volt Typhoon analysis, and MSTIC research
- [@Unit42_Intel](https://x.com/Unit42_Intel) — Palo Alto Unit 42; prolific IOC releases and threat actor campaign analysis
- [@CrowdStrike](https://x.com/CrowdStrike) — Adversary naming, eCrime and APT intelligence briefings, and annual Global Threat Report commentary
- [@Mandiant](https://x.com/Mandiant) — APT research, incident findings, and adversary infrastructure analysis
- [@threatintel](https://x.com/threatintel) — Curated feed of threat intelligence research from across the community
- [@campuscodi](https://x.com/campuscodi) — Catalin Cimpanu; sharp, fast threat intelligence reporting covering malware, APTs, and cybercrime
- [@vxunderground](https://x.com/vxunderground) — Malware sample library and threat intelligence aggregation; massive visibility into the crimeware and APT tooling landscape
- [@GovCERT_CH](https://x.com/GovCERT_CH) — Swiss CERT; high-quality technical IOC releases and campaign analysis
- [@MISP_Project](https://x.com/MISPProject) — Platform updates, new galaxy additions, and community intelligence sharing news
- [@OpenCTI_io](https://x.com/OpenCTI_io) — Platform updates and STIX/CTI community news

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — The recommended ATT&CK analysis surface for TI workflows; load threat actor profiles, map campaign techniques, correlate with MISP/OpenCTI integrations, and export STIX bundles for sharing
- [MITRE ATT&CK](https://attack.mitre.org) — The universal language for describing adversary behavior; 600+ techniques with real-world procedure examples, threat group mappings, and campaign documentation
- [MISP Project](https://www.misp-project.org) — Community hub for the world's most deployed open-source TI platform; documentation, galaxy updates, and sharing community links
- [OpenCTI Platform](https://www.opencti.io) — Documentation and community for the leading modern open-source TI platform
- [The Diamond Model](https://www.activeresponse.org/the-diamond-model/) — Free original paper defining the analytic model that underlies how most TI platforms structure adversary relationships
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) — The original kill chain paper; foundational framework for structuring TI around adversary operations
- [FIRST.org TLP Standard](https://www.first.org/tlp/) — The Traffic Light Protocol standard for intelligence sharing classification; required knowledge for any CTI practitioner sharing intelligence across organizations
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html) — The standard transport mechanism for STIX-based intelligence sharing
