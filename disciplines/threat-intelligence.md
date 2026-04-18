# Threat Intelligence

Collecting, analyzing, and operationalizing information about adversaries, their tools, and their techniques to inform detection, response, and risk decisions.

---

## Where to Start

Threat intelligence is most useful when it is actionable — not a feed of indicators, but an understanding of adversary behavior that changes how your organization detects, responds, and prioritizes. Begin by mastering the ATT&CK framework: it is the shared vocabulary every practitioner uses. Work through the intelligence lifecycle (collection, processing, analysis, dissemination, feedback) and understand how each stage produces something the next can use. Then stand up a local MISP instance to practice ingesting, structuring, and sharing indicators. From there, study structured analytic techniques to move from raw data to analytic conclusions.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Intelligence lifecycle, ATT&CK framework, IOC types, OSINT basics | MITRE ATT&CK website, CISA free catalog, TryHackMe Blue Team path |
| Practitioner | MISP, OpenCTI, STIX 2.1/TAXII, threat actor profiling, indicator enrichment | Antisyphon SOC Core Skills, HTB Academy SOC path, LetsDefend |
| Advanced | Diamond Model, structured analytic techniques, attribution, intelligence programs | SANS FOR578, GCTI, CREST CPSA |

---

## Free Training

- [Antisyphon: SOC Core Skills with John Strand](https://www.antisyphontraining.com/product/soc-core-skills-with-john-strand/) — Pay-what-you-can ($0+); intelligence fundamentals woven throughout SOC operations training; one of the best free entry points in the field
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Hundreds of free webcasts covering threat intelligence, adversary tracking, and hunting; archive spans years of practitioner content
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — Free walkthroughs, panel discussions, and threat intelligence-focused presentations
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; SOC Analyst path covers threat intelligence, log analysis, SIEM, and detection modules
- [TryHackMe — Blue Team Path](https://tryhackme.com/path/outline/blueteam) — Browser-based labs covering threat intelligence and SOC skills from the ground up; no setup required
- [LetsDefend](https://letsdefend.io) — Free SOC simulator with threat intel alert triage exercises; closest thing to day-one SOC experience
- [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) — No-cost federal and public training including CTI fundamentals and intelligence analysis

---

## Tools & Repositories

### Platforms
- [MISP](https://github.com/MISP/MISP) — Malware Information Sharing Platform; the open standard for structured threat indicator sharing
- [misp-galaxy](https://github.com/MISP/misp-galaxy) — Galaxy clusters for threat actors, malware, and tools
- [misp-taxonomies](https://github.com/MISP/misp-taxonomies) — Machine-readable taxonomies used in MISP and threat intel workflows
- [misp-warninglists](https://github.com/MISP/misp-warninglists) — Lists of well-known indicators to filter false positives
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) — Open source cyber threat intelligence platform
- [client-python](https://github.com/OpenCTI-Platform/client-python) — OpenCTI Python client library
- [yeti](https://github.com/yeti-platform/yeti) — Your Everyday Threat Intelligence platform for organizing IOCs and TTPs

### Feeds & Data
- [blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) — Aggregated IP blocklists updated daily
- [ipsum](https://github.com/stamparm/ipsum) — Daily updated list of malicious IPs
- [maltrail](https://github.com/stamparm/maltrail) — Malicious traffic detection system using public blacklists
- [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) — Active and historical phishing domains
- [yabin](https://github.com/AlienVault-OTX/yabin) — YARA rule generator from malware samples

### STIX / TAXII
- [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) — Python library for working with STIX 2.x objects
- [cti-taxii-client](https://github.com/oasis-open/cti-taxii-client) — TAXII 2.x client library

### MITRE ATT&CK
- [attack-navigator](https://github.com/mitre-attack/attack-navigator) — Web-based matrix for annotating ATT&CK coverage
- [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) — ATT&CK content in STIX 2.1 format
- [attack-scripts](https://github.com/mitre-attack/attack-scripts) — Utilities for working with ATT&CK data
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) — Python library for ATT&CK data
- [attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow) — Model adversary behavior as sequences of ATT&CK techniques
- [tram](https://github.com/center-for-threat-informed-defense/tram) — Automated mapping of threat reports to ATT&CK

### Threat Hunting
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — Hunt procedures mapped to ATT&CK techniques
- [Security-Datasets](https://github.com/OTRF/Security-Datasets) — Datasets for detection and hunting research
- [OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata for data normalization
- [ATTACK-Python-Client](https://github.com/OTRF/ATTACK-Python-Client) — Python client for querying ATT&CK STIX data
- [Threat-Hunting-and-Detection](https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection) — KQL-based hunting queries and detection analytics
- [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) — Artifacts and keywords by ATT&CK technique for hunting
- [ThreatHunting](https://github.com/GossiTheDog/ThreatHunting) — Hunting queries and resources from Kevin Beaumont
- [HELK](https://github.com/Cyb3rWard0g/HELK) — Hunting ELK stack with Kafka and Spark for large-scale hunting

### Utility Tools
- [shodan-python](https://github.com/achillean/shodan-python) — Python library for the Shodan search engine
- [dnstwist](https://github.com/elceef/dnstwist) — Domain permutation engine for phishing and brand monitoring
- [CyberChef](https://github.com/gchq/CyberChef) — Swiss army knife for data transformation and IOC decoding
- [APTnotes](https://github.com/kbandla/APTnotes) — Public APT campaign reports going back years

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Threat Intelligence Handbook | CyberEdge Group | Free PDF; covers the intelligence lifecycle, SOC integration, and TI program maturity |
| Intelligence-Driven Incident Response | Brown & Roberts | Applies the F3EAD cycle and Diamond Model to real IR scenarios |
| Applied Incident Response | Steve Anson | Practical IR with Windows forensics and threat intelligence context |
| Hacking the Hacker | Roger Grimes | Profiles of leading security researchers and their methods |
| The Art of Intrusion | Kevin Mitnick | Adversary mindset and real intrusion case studies to calibrate your threat models |

---

## Certifications

- **GCTI** (GIAC Cyber Threat Intelligence) — Covers threat intel analysis, ATT&CK mapping, and structured analytic techniques; the benchmark certification for CTI analysts
- **FOR578** (SANS Cyber Threat Intelligence) — The most respected practitioner course; Diamond Model, F3EAD, and operationalizing intelligence
- **CREST CPSA** — UK-recognized intelligence and security analyst certification
- **Antisyphon SOC Core Skills** — Pay-what-you-can with credential upon completion; practical entry point for anyone building an intelligence foundation

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Free webcasts and training on threat intelligence, threat hunting, and SOC operations; one of the most prolific free resources in the field
- [Mandiant & Google Cloud Security](https://www.youtube.com/@Mandiant) — APT reports, threat actor deep dives, and intelligence briefings
- [CrowdStrike](https://www.youtube.com/@CrowdStrike) — Threat intelligence and adversary tracking
- [Cisco Talos Intelligence Group](https://www.youtube.com/@CiscoTalosIntelligenceGroup) — Threat research, malware analysis, and vulnerability advisories
- [Recorded Future](https://www.youtube.com/@recordedfuture) — Cyber threat intelligence and geopolitical analysis
- [SANS Internet Storm Center](https://www.youtube.com/@SansInstitute) — Daily threat updates and handler diaries
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Accessible practical content bridging offensive and defensive intelligence concepts

---

## Who to Follow

- [@JohnHultquist](https://x.com/JohnHultquist) — John Hultquist, Mandiant/Google threat intelligence head
- [@likethecoins](https://x.com/likethecoins) — Katie Nickels, Red Canary; active ATT&CK contributor and intelligence practitioner
- [@JoeSlowik](https://x.com/JoeSlowik) — Threat intelligence and ICS/OT research
- [@RidT](https://x.com/RidT) — Thomas Rid, author of Active Measures; cyber strategy and history
- [@inversecos](https://x.com/inversecos) — DFIR and threat intelligence research
- [@RedDrip7](https://x.com/RedDrip7) — Threat intelligence and APT tracking
- [@MsftSecIntel](https://x.com/MsftSecIntel) — Microsoft Threat Intelligence
- [@Unit42_Intel](https://x.com/Unit42_Intel) — Palo Alto Networks Unit 42 threat research
- [@TalosSecurity](https://x.com/TalosSecurity) — Cisco Talos Intelligence Group
- [@abuse_ch](https://x.com/abuse_ch) — Operator of MalwareBazaar, URLhaus, and ThreatFox
- [@CISAgov](https://x.com/CISAgov) — US CISA official feed; advisories and KEV updates
- [@NCSC](https://x.com/NCSC) — UK National Cyber Security Centre
- [@Mandiant](https://x.com/Mandiant) — Mandiant threat intelligence
- [@CrowdStrike](https://x.com/CrowdStrike) — CrowdStrike threat intelligence
- [@RecordedFuture](https://x.com/RecordedFuture) — Recorded Future intelligence

---

## Key Resources

- [MITRE ATT&CK](https://attack.mitre.org) — The authoritative adversary behavior framework; every analyst needs to know this fluently
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Interactive ATT&CK navigator with threat group filters, CVE overlays, detection coverage, and compliance mappings all in one interface
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known exploited vulnerabilities with mandated remediation deadlines; the signal-to-noise filter for patch prioritization
- [abuse.ch](https://abuse.ch) — MalwareBazaar, URLhaus, ThreatFox, and Feodo Tracker; free community-driven threat data
- [MITRE CTID](https://ctid.mitre-engenuity.org) — Center for Threat-Informed Defense research and tooling
- [SANS Internet Storm Center](https://isc.sans.edu) — Daily threat diaries and handler notes going back decades
- [AlienVault OTX](https://otx.alienvault.com) — Open Threat Exchange; community-contributed indicators and pulses
- [VirusTotal](https://www.virustotal.com) — File, URL, domain, and IP reputation with multi-engine analysis
