# ICS/OT Security

Protecting industrial control systems, operational technology, and critical infrastructure — including SCADA, PLCs, DCS, and the communication protocols that bind them — from adversaries who increasingly target the physical processes that power grids, water systems, pipelines, and manufacturing depend on.

---

## Where to Start

ICS/OT security requires understanding both the IT security fundamentals you may already have and an entirely different engineering domain beneath them. The consequences of a mistake in OT are measured in physical damage, production loss, or human safety — not just data breaches. Start by studying the ICS ATT&CK matrix to understand how adversaries move from the IT network into the OT environment. Learn the major industrial protocols (Modbus, DNP3, IEC 61850, S7) to understand what normal traffic looks like before you can detect anomalies. CISA and Idaho National Laboratory offer extensive free training that is specifically designed for this domain.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | ICS architecture (Purdue model), industrial protocols, IT/OT convergence risks, ATT&CK for ICS | CISA ICS training (free), INL free courses, MITRE ATT&CK for ICS |
| Practitioner | Protocol analysis, network segmentation, passive monitoring, vulnerability assessment in OT | SANS ICS515, BHIS webcasts, ICS-pcap analysis, GICSP exam preparation |
| Advanced | Adversary emulation in OT, firmware analysis, PLC programming abuse, incident response in ICS environments | GRID, SANS ICS612, MITRE Caldera for OT, Dragos Year in Review |

---

## Free Training

- [CISA ICS Training](https://www.cisa.gov/resources-tools/programs/ics-training-available-through-cisa) — The most comprehensive free ICS security training available; in-person and virtual courses covering ICS fundamentals, network defense, incident response, and vulnerability assessment for critical infrastructure practitioners
- [Idaho National Laboratory (INL) Courses](https://inl.gov/national-security/cyber-security/) — Free and subsidized ICS security courses from the DOE's primary ICS security research lab; INL developed foundational ICS security methodology and trains thousands of practitioners annually
- [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) — No-cost federal training catalog including dedicated ICS/SCADA security modules and critical infrastructure protection content
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — Free framework documenting adversary tactics and techniques specific to industrial control systems with real-world case studies from incidents like TRITON and Industroyer
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering OT/ICS security topics, network monitoring in industrial environments, and incident response considerations unique to operational technology
- [Dragos Year in Review (Free)](https://www.dragos.com/year-in-review/) — Annual free threat intelligence report from the leading ICS security firm; essential reading for understanding the current threat landscape targeting industrial environments
- [S4 Conference Resources](https://s4xevents.com) — The premier ICS security conference; many talks and materials are made available publicly after the event
- [OpenPLC Runtime](https://autonomylogic.com/docs/openplc-runtime/) — Free open-source PLC runtime for lab environments; essential for building a practice ICS environment without industrial hardware
- [ControlThings Platform](https://www.controlthings.io) — Free Linux distribution with ICS-specific security tools pre-installed; purpose-built for ICS security assessments and learning
- [SANS ICS Security Resources](https://www.sans.org/industrial-control-systems-security/) — SANS ICS-specific content overview including free posters and white papers on ICS network monitoring and incident response

---

## Tools & Repositories

### ICS/SCADA Tools & Frameworks
- [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) — Curated collection of ICS security tools, scripts, and resources organized by category; a comprehensive starting point for ICS security tooling
- [ArmisSecurity/ICSSecurityTools](https://github.com/ArmisSecurity/ICSSecurityTools) — Armis ICS security tools and research; passive asset discovery and protocol analysis for OT environments
- [w3h/icsmaster](https://github.com/w3h/icsmaster) — ICS/SCADA master repository aggregating security tools, device fingerprinting, and vulnerability research for industrial environments
- [mitre/caldera-ot](https://github.com/mitre/caldera-ot) — MITRE CALDERA extension for OT adversary emulation; enables ATT&CK for ICS technique simulation in lab environments for detection development and exercise support

### Protocol Libraries & Analysis
- [pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) — Full Modbus protocol stack in Python; essential for understanding and testing Modbus TCP/RTU communication in industrial environments
- [sourceperl/pyModbusTCP](https://github.com/sourceperl/pyModbusTCP) — Lightweight Python Modbus TCP client; useful for scripting protocol-level tests and building simple monitoring tools
- [mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) — Open source IEC 61850 MMS and GOOSE protocol library; essential for working with substation automation and power grid communication
- [klsecservices/s7scan](https://github.com/klsecservices/s7scan) — Siemens S7 PLC scanning and enumeration tool; identifies S7 devices, reads CPU information, and probes device capabilities
- [digitalbond/Redpoint](https://github.com/digitalbond/Redpoint) — Digital Bond's ICS-focused Nmap NSE scripts for enumerating Modbus, DNP3, EtherNet/IP, BACnet, and other industrial protocol devices

### Traffic Capture & Analysis
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Repository of ICS/SCADA protocol packet captures; invaluable for learning to recognize normal protocol behavior and developing detection signatures without industrial hardware
- [arnaudsoullie/ics-default-passwords](https://github.com/arnaudsoullie/ics-default-passwords) — Compiled list of default credentials for industrial control system devices; critical reference for assessing authentication hygiene in OT environments

### Network Monitoring & Detection
- [nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) — NSA's passive ICS/SCADA network visualization tool; builds network topology maps from captured traffic without active scanning that could disrupt industrial processes
- [zeek/zeek](https://github.com/zeek/zeek) — Network analysis framework with ICS protocol parsers (Modbus, DNP3, EtherNet/IP) available through community packages; the foundation for passive OT network monitoring
- [activecm/rita](https://github.com/activecm/rita) — Statistical beaconing detection through Zeek log analysis; applicable to OT network traffic for identifying unexpected communications

### Firmware & IoT Analysis
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — Firmware extraction and analysis tool; the standard first step for analyzing ICS device firmware, identifying file systems, compression formats, and embedded components
- [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) — Firmware Analysis and Comparison Tool; automated firmware extraction, vulnerability scanning, and component identification for IoT and embedded device firmware
- [attify/firmware-analysis-toolkit](https://github.com/attify/firmware-analysis-toolkit) — Toolkit for emulating and dynamically testing firmware; enables running embedded firmware in QEMU for behavioral analysis without physical hardware
- [firmadyne/firmadyne](https://github.com/firmadyne/firmadyne) — Platform for emulating and analyzing Linux-based embedded firmware; enables dynamic testing of network-connected embedded devices
- [craigz28/firmwalker](https://github.com/craigz28/firmwalker) — Bash script for walking extracted firmware and searching for interesting files, credentials, hardcoded passwords, and security-relevant strings
- [REhints/efiXplorer](https://github.com/REhints/efiXplorer) — IDA Pro and Ghidra plugin for UEFI firmware analysis; useful for analyzing boot-level firmware in industrial workstations and HMI systems

### Hardware & Physical Security
- [grandideastudio/jtagulator](https://github.com/grandideastudio/jtagulator) — Open hardware tool for identifying JTAG interface pinouts on circuit boards; used in ICS device hardware security assessment and firmware extraction
- [wavestone-cdt/dyode](https://github.com/wavestone-cdt/dyode) — Do Your Own Data Exfiltration — an open-source unidirectional data diode implementation; demonstrates the principles behind OT network segmentation and secure data transfer
- [e-m-b-a/emba](https://github.com/e-m-b-a/emba) — Embedded firmware security analyzer; automated firmware security testing framework covering known vulnerabilities, hardcoded credentials, and binary protections

### Threat Intelligence & Reference
- [digitalbond/Redpoint](https://github.com/digitalbond/Redpoint) — ICS-specific Nmap scripts from Project Basecamp; includes scripts targeting Modbus, ENIP, BACnet, DNP3, and Siemens S7 devices for asset discovery
- [swisskyrepo/HardwareAllTheThings](https://github.com/swisskyrepo/HardwareAllTheThings) — Hardware and embedded security reference covering JTAG, UART, SPI, I2C, and OT protocol attack techniques with practical exploitation notes

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| *Hacking Exposed Industrial Control Systems* | Bodungen, Singer, Shbeeb, Hahn, Wilhoit | The foundational ICS penetration testing reference; covers ICS architecture, protocol attacks, and assessment methodology with real industrial environments in mind |
| *Industrial Cybersecurity* | Pascal Ackerman | Practical guide to ICS/SCADA security monitoring, network architecture, and implementing defense-in-depth across the Purdue model |
| *Countdown to Zero Day* | Kim Zetter | Definitive account of Stuxnet — required reading for understanding what nation-state ICS attacks look like and the geopolitical context of critical infrastructure security |
| *The ICS Cybersecurity Field Manual* | Various (ISA) | Reference manual covering ICS security fundamentals, ISA/IEC 62443 standards, and practical guidance for defenders working in operational environments |
| *SCADA Security: What's Broken and How to Fix It* | Andrew Ginter | Realistic assessment of SCADA attack surfaces and pragmatic defense recommendations from a practitioner who has assessed hundreds of OT environments |

---

## Certifications

- **GICSP** (Global Industrial Cyber Security Professional) — The premier ICS security certification; covers ICS/SCADA architecture, protocols, security controls, and incident response for operational technology; widely recognized across critical infrastructure sectors
- **GRID** (GIAC Response and Industrial Defense) — Advanced ICS incident response and threat hunting; covers active defense in OT environments, TRITON and similar malware analysis, and forensics in industrial environments
- **CSSA** (Certified SCADA Security Architect — ISA) — ISA's security professional certification aligned with ISA/IEC 62443; covers security management systems and zone-and-conduit architecture for industrial networks
- **ISA/IEC 62443 Cybersecurity Certificate** — ISA's certificate program covering the international standard for industrial automation and control system security; tiered levels from awareness through expert
- **CISSP with ICS/OT focus** — The broad governance credential is increasingly expected for senior ICS security roles; pairs well with GICSP for practitioners moving into program leadership

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Practical ICS/OT security content including network monitoring, detection strategies, and adversary behavior in industrial environments
- [Dragos](https://www.youtube.com/dragos) — ICS-focused threat intelligence, year in review presentations, and practitioner guidance from the field's leading specialized security firm
- [S4 Conference](https://www.youtube.com/@s4xevents) — Recorded talks from the premier ICS security conference covering research, incident case studies, and policy discussions
- [SANS ICS Security](https://www.youtube.com/@SansInstitute) — ICS-specific webcasts and GICSP/GRID exam preparation content from SANS ICS curriculum instructors
- [Idaho National Laboratory](https://www.youtube.com/@INL) — Research presentations and training content from the DOE's primary ICS security research institution
- [CISA](https://www.youtube.com/@cisagov) — Official guidance, incident reports, and advisory content on critical infrastructure protection
- [SecurityWeek ICS Security](https://www.securityweek.com/ics-ot/) — News and analysis channel covering ICS/OT vulnerability disclosures and threat reporting

---

## Who to Follow

- [@RobertMLee](https://x.com/RobertMLee) — Robert Lee, Dragos CEO; the most influential voice in ICS security; builds the field's threat intelligence standards and publishes extensively on adversary behavior in OT environments
- [@digitalbond](https://x.com/digitalbond) — Dale Peterson; founder of S4 Conference and Digital Bond; 20+ years of ICS security research; sharp analyst of ICS vulnerability disclosure debates
- [@ReidWightman](https://x.com/ReidWightman) — ICS vulnerability researcher; discovered critical vulnerabilities in PLCs and industrial protocols; deep technical expertise in ICS protocol analysis
- [@k8em0](https://x.com/k8em0) — Katie Moussouris; security policy and disclosure expert with critical infrastructure focus
- [@CISAgov](https://x.com/CISAgov) — CISA official; ICS-CERT advisories, KEV updates, and critical infrastructure protection guidance
- [@DragosInc](https://x.com/DragosInc) — Dragos threat intelligence and ICS security research updates
- [@SCADAhacker](https://x.com/SCADAhacker) — Joel Langill; ICS security practitioner and educator with deep Modbus and industrial protocol knowledge
- [@securityledger](https://x.com/securityledger) — Security Ledger; strong coverage of ICS/OT and IoT security news
- [@ClarityOT](https://x.com/clarotyteam) — Claroty Team82 research team; prolific ICS vulnerability research with detailed technical disclosures
- [@tlancaster](https://x.com/tlancaster) — Tom Lancaster; ICS security research and threat intelligence
- [@chrissistrunk](https://x.com/chrissistrunk) — Chris Sistrunk, Mandiant; extensive ICS security consulting and research background

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Supports the ICS ATT&CK matrix domain; visualize adversary techniques specific to industrial environments, correlate with detection coverage, and pivot from technique to threat group attribution
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — The definitive adversary behavior framework for industrial control systems; covers 12 ICS-specific tactics and real-world case studies from TRITON, Industroyer, and Sandworm operations
- [CISA ICS-CERT Advisories](https://www.cisa.gov/ics-advisories) — Primary source for ICS vulnerability advisories and critical infrastructure security alerts; subscribe and triage regularly
- [Idaho National Laboratory Cyber Programs](https://inl.gov/national-security/cyber-security/) — Free training, research publications, and the SCADA test bed resources from the DOE's primary ICS security research institution
- [Dragos Year in Review](https://www.dragos.com/year-in-review/) — Annual free report on threat groups targeting industrial environments; the most actionable ICS threat intelligence report published
- [ISA/IEC 62443 Standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) — The international security standard for industrial automation and control systems; the governance framework underlying all serious ICS security programs
- [NERC CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) — Mandatory cybersecurity standards for the bulk electric system in North America; the compliance baseline for energy sector OT security
- [Project Basecamp](https://www.digitalbond.com/blog/2012/01/09/project-basecamp-at-s4/) — Dale Peterson's landmark ICS vulnerability research demonstrating widespread insecure-by-design issues in major PLC platforms; foundational for understanding the ICS attack surface
- [Claroty Team82 Research](https://claroty.com/team82/research) — Prolific ICS vulnerability research with detailed technical disclosures covering PLCs, HMIs, engineering workstations, and industrial protocols
- [ICS-PCAP Repository](https://github.com/automayt/ICS-pcap) — Free packet captures of industrial protocols for analysis practice; essential for building detection skills without access to live industrial equipment
