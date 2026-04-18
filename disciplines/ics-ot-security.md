# ICS/OT Security

Protecting industrial control systems, operational technology, and critical infrastructure — including SCADA, PLCs, DCS, and the communication protocols that bind them — from adversaries who increasingly target the physical processes that power grids, water systems, pipelines, and manufacturing depend on. ICS/OT security sits at the intersection of information technology security and operational engineering, and practitioners must understand both domains to be effective.

The consequences of a security failure in OT are measured in physical damage, production loss, safety incidents, and human harm — not just data breaches. The 2021 Oldsmar water treatment attack, the Colonial Pipeline ransomware disruption, and the TRITON/TRITSIS safety system attack at a Saudi petrochemical facility illustrate the range of real-world impact. Unlike IT security, where patches can be deployed rapidly, OT environments often run decades-old systems that cannot be patched, rebooted during production, or tested against security tools that could cause physical process disruption.

---

## Where to Start

ICS/OT security requires building on IT security fundamentals before layering the OT-specific engineering knowledge on top. Study the ICS ATT&CK matrix to understand how adversaries move from IT networks into OT environments — the TRITON, Industroyer, and Sandworm campaigns are documented case studies worth deep reading. Learn the major industrial protocols (Modbus, DNP3, IEC 61850, S7) so you recognize normal traffic before trying to detect anomalies. CISA and Idaho National Laboratory offer extensive free training purpose-built for this domain.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | ICS architecture (Purdue model), industrial protocols, IT/OT convergence risks, ATT&CK for ICS, safety vs. security tradeoffs | CISA ICS training (free), INL free courses, MITRE ATT&CK for ICS, BHIS ICS webcasts |
| Practitioner | Protocol analysis (Modbus/DNP3/S7), passive network monitoring, vulnerability assessment in OT, network segmentation, zone-conduit architecture | SANS ICS515, ICS-pcap analysis, GICSP exam preparation, Dragos Year in Review reports |
| Advanced | Adversary emulation in OT environments, firmware analysis, PLC programming abuse, incident response for ICS, purple team in OT | SANS ICS612, MITRE CALDERA for OT, Dragos platform training, INL advanced courses |

---

## Free Training

- [CISA ICS Training](https://www.cisa.gov/resources-tools/programs/ics-training-available-through-cisa) — The most comprehensive free ICS security training available; in-person and virtual courses covering ICS fundamentals, network defense, incident response, and vulnerability assessment for critical infrastructure practitioners
- [Idaho National Laboratory (INL) Courses](https://inl.gov/national-security/cyber-security/) — Free and subsidized ICS security courses from the DOE's primary ICS security research lab; INL developed foundational ICS security methodology and trains thousands of practitioners annually
- [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) — No-cost federal training including dedicated ICS/SCADA security modules and critical infrastructure protection content
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — Free framework documenting adversary tactics and techniques specific to industrial control systems with real-world case studies from TRITON, Industroyer, and Sandworm operations
- [BHIS ICS/OT Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering OT/ICS security topics, network monitoring in industrial environments, and incident response considerations unique to operational technology
- [Dragos Year in Review](https://www.dragos.com/year-in-review/) — Annual free threat intelligence report from the leading ICS security firm; essential reading for understanding the threat landscape targeting industrial environments; the most actionable free ICS threat intelligence published annually
- [S4 Conference Resources](https://s4xevents.com) — The premier ICS security conference; many talks and materials are made publicly available after the event; high-quality technical content from practitioners and researchers
- [OpenPLC Runtime](https://autonomylogic.com/docs/openplc-runtime/) — Free open-source PLC runtime for lab environments; essential for building a practice ICS environment without industrial hardware
- [ControlThings Platform](https://www.controlthings.io) — Free Linux distribution with ICS-specific security tools pre-installed; purpose-built for ICS security assessments and learning
- [SANS ICS Security Resources](https://www.sans.org/industrial-control-systems-security/) — SANS ICS-specific free posters, white papers, and course previews on ICS network monitoring and incident response

---

## Tools & Repositories

### ICS/SCADA Tools & Frameworks
- [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) — Curated collection of ICS security tools, scripts, and resources organized by category; a comprehensive starting point for ICS security tooling
- [w3h/icsmaster](https://github.com/w3h/icsmaster) — ICS/SCADA master repository aggregating security tools, device fingerprinting, and vulnerability research for industrial environments
- [mitre/caldera-ot](https://github.com/mitre/caldera-ot) — MITRE CALDERA extension for OT adversary emulation; enables ATT&CK for ICS technique simulation in lab environments for detection development and purple team exercises

### Protocol Libraries & Analysis
- [pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) — Full Modbus protocol stack in Python; essential for understanding and testing Modbus TCP/RTU communication in industrial environments
- [sourceperl/pyModbusTCP](https://github.com/sourceperl/pyModbusTCP) — Lightweight Python Modbus TCP client for scripting protocol-level tests and building monitoring tools
- [mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) — Open-source IEC 61850 MMS and GOOSE protocol library; essential for working with substation automation and power grid communication protocols
- [klsecservices/s7scan](https://github.com/klsecservices/s7scan) — Siemens S7 PLC scanning and enumeration; identifies S7 devices and reads CPU information for asset inventory in Siemens environments
- [digitalbond/Redpoint](https://github.com/digitalbond/Redpoint) — Digital Bond's ICS-focused Nmap NSE scripts for enumerating Modbus, DNP3, EtherNet/IP, BACnet, and other industrial protocol devices

### Traffic Capture & Analysis
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Repository of ICS/SCADA protocol packet captures; essential for learning to recognize normal industrial protocol behavior and developing detection signatures without access to live industrial hardware
- [arnaudsoullie/ics-default-passwords](https://github.com/arnaudsoullie/ics-default-passwords) — Compiled default credentials for industrial control system devices; critical reference for authentication hygiene assessments in OT environments

### Network Monitoring & Detection
- [nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) — NSA's passive ICS/SCADA network visualization tool (note: this repository is archived and no longer actively maintained); builds network topology maps from captured traffic without active scanning; useful as a reference and starting point for building passive OT visibility tools
- [zeek/zeek](https://github.com/zeek/zeek) — Network analysis framework with ICS protocol parsers (Modbus, DNP3, EtherNet/IP) available through community packages; the foundation for passive OT network monitoring
- [activecm/rita](https://github.com/activecm/rita) — Statistical beaconing detection through Zeek log analysis; applicable to OT network traffic for identifying unexpected lateral communications

### Firmware & IoT Analysis
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — Firmware extraction and analysis; the standard first step for analyzing ICS device firmware, identifying file systems, compression formats, and embedded components
- [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) — Firmware Analysis and Comparison Tool; automated firmware extraction, vulnerability scanning, and component identification for IoT and embedded device firmware
- [attify/firmware-analysis-toolkit](https://github.com/attify/firmware-analysis-toolkit) — Toolkit for emulating and dynamically testing firmware in QEMU for behavioral analysis without physical hardware
- [e-m-b-a/emba](https://github.com/e-m-b-a/emba) — Embedded firmware security analyzer; automated security testing covering known vulnerabilities, hardcoded credentials, and binary protections

### Hardware & Physical Security
- [grandideastudio/jtagulator](https://github.com/grandideastudio/jtagulator) — Open hardware tool for identifying JTAG interface pinouts; used in ICS device hardware security assessment and firmware extraction from physical devices
- [swisskyrepo/HardwareAllTheThings](https://github.com/swisskyrepo/HardwareAllTheThings) — Hardware and embedded security reference covering JTAG, UART, SPI, I2C, and OT protocol attack techniques with practical exploitation notes

---

## Commercial & Enterprise Platforms

ICS/OT security has a specialized commercial market dominated by a handful of vendors who understand industrial protocols, the safety-first constraint, and the need for passive-only monitoring approaches.

| Platform | Strength |
|---|---|
| **Dragos Platform** | The gold standard commercial ICS security platform; passive industrial network monitoring, threat detection, and the deepest OT threat intelligence available; built by former ICS-CERT and NSA ICS analysts; the Dragos threat groups database is the authoritative source for ICS adversary tracking |
| **Claroty Platform** | Industrial cybersecurity platform covering asset discovery, vulnerability management, threat detection, and secure remote access for OT environments; strong across manufacturing, energy, and critical infrastructure sectors; Team82 research team publishes prolific ICS vulnerability disclosures |
| **Nozomi Networks** | OT and IoT security platform combining passive monitoring, AI-based anomaly detection, and vulnerability assessment; strong in energy, transportation, and manufacturing; acquired by Armis |
| **Armis** | Agentless device visibility and security for unmanaged OT, IoT, and IoMT (medical) devices; discovers and monitors assets that cannot support agents; strong in healthcare and industrial environments |
| **Fortinet OT Security** | Network security stack adapted for OT environments; FortiGate firewalls with OT protocol awareness, FortiNAC for ICS asset management, and integrated SOC capabilities for IT/OT converged environments |
| **Honeywell Forge** | ICS security and operational platform from an industrial automation vendor with deep protocol and safety system knowledge; strong in process industries (oil and gas, chemicals) |
| **Tenable OT Security (formerly Indegy)** | Industrial network monitoring and vulnerability management integrated with Tenable's broader vulnerability management platform; good for organizations already using Tenable for IT/OT unified visibility |
| **Microsoft Defender for IoT** | OT/ICS network monitoring integrated with Microsoft Sentinel; passive protocol analysis across 60+ industrial protocols; strong for organizations in the Microsoft security ecosystem |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Hacking Exposed Industrial Control Systems | Bodungen, Singer, Shbeeb, Hahn, Wilhoit | The foundational ICS penetration testing reference; covers ICS architecture, protocol attacks, and assessment methodology with real industrial environments in mind |
| Industrial Cybersecurity | Pascal Ackerman | Practical guide to ICS/SCADA security monitoring, network architecture, and defense-in-depth implementation across the Purdue model |
| Countdown to Zero Day | Kim Zetter | Definitive account of Stuxnet; required reading for understanding what nation-state ICS attacks look like and the geopolitical context of critical infrastructure security |
| The ICS Cybersecurity Field Manual | Various (ISA) | Reference covering ICS security fundamentals, ISA/IEC 62443 standards, and practical guidance for defenders in operational environments |
| SCADA Security: What's Broken and How to Fix It | Andrew Ginter | Realistic SCADA attack surface assessment and pragmatic defense recommendations from a practitioner who has assessed hundreds of OT environments |

---

## Certifications

- **GICSP** (Global Industrial Cyber Security Professional) — The premier ICS security certification; covers ICS/SCADA architecture, protocols, security controls, and incident response for operational technology; widely recognized across critical infrastructure sectors
- **GRID** (GIAC Response and Industrial Defense) — Advanced ICS incident response and threat hunting; active defense in OT environments, TRITON and similar malware analysis, and forensics in industrial environments
- **ISA/IEC 62443 Cybersecurity Certificate Program** — ISA's certificate program covering the international standard for industrial automation and control system security; tiered levels from awareness through expert practitioner
- **CISSP with ICS/OT focus** — The broad governance credential increasingly expected for senior ICS security program leadership roles; pairs well with GICSP for practitioners moving into management

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Practical ICS/OT security content including network monitoring, detection strategies, and adversary behavior in industrial environments
- [Dragos](https://www.youtube.com/dragos) — ICS-focused threat intelligence, year in review presentations, and practitioner guidance from the field's leading specialized security firm
- [S4 Conference](https://www.youtube.com/@s4xevents) — Recorded talks from the premier ICS security conference covering research, incident case studies, and policy discussions
- [Idaho National Laboratory](https://www.youtube.com/@INL) — Research presentations and training content from the DOE's primary ICS security research institution
- [CISA](https://www.youtube.com/@cisagov) — Official guidance, incident reports, and advisory content on critical infrastructure protection
- [SANS ICS Security](https://www.youtube.com/@SansInstitute) — ICS-specific webcasts and GICSP/GRID exam preparation content from SANS ICS instructors

---

## Who to Follow

- [@RobertMLee](https://x.com/RobertMLee) — Robert Lee, Dragos CEO; the most influential voice in ICS security; builds the field's threat intelligence standards and publishes extensively on adversary behavior in OT environments
- [@digitalbond](https://x.com/digitalbond) — Dale Peterson; founder of S4 Conference; 20+ years of ICS security research and sharp analysis of ICS vulnerability disclosure debates
- [@ReidWightman](https://x.com/ReidWightman) — ICS vulnerability researcher; discovered critical vulnerabilities in PLCs and industrial protocols; deep technical expertise
- [@CISAgov](https://x.com/CISAgov) — CISA official; ICS-CERT advisories, KEV updates, and critical infrastructure protection guidance
- [@DragosInc](https://x.com/DragosInc) — Dragos threat intelligence and ICS security research updates
- [@SCADAhacker](https://x.com/SCADAhacker) — Joel Langill; ICS security practitioner and educator with deep Modbus and industrial protocol knowledge
- [@ClarityOT](https://x.com/clarotyteam) — Claroty Team82 research team; prolific ICS vulnerability research with detailed technical disclosures
- [@chrissistrunk](https://x.com/chrissistrunk) — Chris Sistrunk, Mandiant; extensive ICS security consulting and research background

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Supports the ICS ATT&CK matrix domain; visualize adversary techniques specific to industrial environments, correlate detection coverage, and pivot from technique to threat group attribution including TRITON, Industroyer, and Sandworm operations
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — The definitive adversary behavior framework for industrial control systems; 12 ICS-specific tactics with real-world case studies from major ICS attacks
- [CISA ICS-CERT Advisories](https://www.cisa.gov/ics-advisories) — Primary source for ICS vulnerability advisories and critical infrastructure security alerts; subscribe and triage regularly
- [Idaho National Laboratory Cyber Programs](https://inl.gov/national-security/cyber-security/) — Free training, research publications, and SCADA test bed resources from the DOE's primary ICS security research institution
- [Dragos Year in Review](https://www.dragos.com/year-in-review/) — Annual free report on threat groups targeting industrial environments; the most actionable ICS threat intelligence report published
- [ISA/IEC 62443 Standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) — The international security standard for industrial automation and control systems; the governance framework underlying all serious ICS security programs
- [NERC CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) — Mandatory cybersecurity standards for the bulk electric system in North America; the compliance baseline for energy sector OT security
- [Claroty Team82 Research](https://claroty.com/team82/research) — Prolific ICS vulnerability research covering PLCs, HMIs, engineering workstations, and industrial protocols
- [ICS-PCAP Repository](https://github.com/automayt/ICS-pcap) — Free packet captures of industrial protocols for analysis practice
