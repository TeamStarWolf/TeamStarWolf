# ICS/OT Security

Protecting industrial control systems, operational technology, and critical infrastructure — including SCADA, PLCs, DCS, and the communication protocols that bind them — from adversaries who increasingly target the physical processes that power grids, water systems, pipelines, and manufacturing depend on. ICS/OT security sits at the intersection of information technology security and operational engineering, and practitioners must understand both domains to be effective.

The consequences of a security failure in OT are measured in physical damage, production loss, safety incidents, and human harm — not just data breaches. Sandworm's INDUSTROYER malware blacked out a portion of Kyiv in December 2016 following the 2015 Ukraine power grid attacks. XENOTIME deployed TRITON/TRISIS to attack Schneider Electric safety instrumented systems at a Saudi petrochemical plant, attempting to disable the last line of protection before a physical catastrophe. Volt Typhoon pre-positioned inside US critical infrastructure networks for years. Stuxnet physically destroyed Iranian centrifuges at Natanz — the first confirmed cyber weapon to cause kinetic damage. Unlike IT security, where patches can be deployed rapidly, OT environments often run decades-old systems that cannot be patched, rebooted during production, or tested with security tools that could cause physical process disruption.

---

## Where to Start

ICS/OT security requires building on IT security fundamentals before layering OT-specific engineering knowledge on top. Study the ICS ATT&CK matrix to understand how adversaries move from IT networks into OT environments — the TRITON, Industroyer, and Sandworm campaigns are documented case studies worth deep reading. Learn the major industrial protocols (Modbus, DNP3, IEC 61850, S7) so you recognize normal traffic before trying to detect anomalies. CISA and Idaho National Laboratory offer extensive free training purpose-built for this domain.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Purdue Reference Model (Levels 0–5), IT/OT convergence risks, industrial protocols (Modbus TCP/RTU, DNP3, IEC 61850, PROFINET, EtherNet/IP, BACnet, OPC-UA), ATT&CK for ICS, safety vs. security tradeoffs | CISA ICS training (free), INL free courses, MITRE ATT&CK for ICS, BHIS ICS webcasts |
| Practitioner | Protocol analysis and lack of auth/encryption, passive network monitoring, vulnerability assessment in OT, network segmentation, zone-conduit architecture, NIST SP 800-82 Rev 3, IEC 62443, NERC CIP | SANS ICS515, ICS-pcap analysis, GICSP exam prep, Dragos Year in Review reports |
| Advanced | Adversary emulation in OT environments, firmware analysis, PLC programming abuse, incident response for ICS, purple team in OT, recreating INDUSTROYER/TRITON TTPs in lab | SANS ICS612, MITRE CALDERA for OT, Dragos platform training, INL advanced courses |

---

## The Purdue Reference Model

The Purdue Enterprise Reference Architecture (PERA) defines the logical layers separating enterprise IT from physical processes. Understanding these levels is essential for designing segmentation controls and understanding where attacks propagate.

| Level | Name | Components | IT/OT Boundary Risk |
|---|---|---|---|
| Level 0 | Physical Process | Sensors, actuators, final control elements | Attacker commands here cause physical damage (Stuxnet centrifuges, TRITON safety systems) |
| Level 1 | Basic Control | PLCs, RTUs, field controllers | Direct process manipulation via unauthorized command messages (T0855) |
| Level 2 | Supervisory Control | SCADA, DCS, HMIs, engineering workstations | HMI exploitation enables Level 0/1 access; engineering workstation compromise is a common pivot |
| Level 3 | Manufacturing Operations | MES, historian, batch management, scheduling | IT/OT convergence zone; historian servers often bridge corporate and OT networks |
| Level 3.5 | Industrial DMZ (iDMZ) | Data diodes, jump servers, patch management, AV updates | Should exist but frequently absent; missing iDMZ is the most common IT-to-OT pivot path |
| Level 4 | Business Logistics | ERP, business systems, corporate IT | Ransomware here frequently disrupts Level 3; Colonial Pipeline is the canonical example |
| Level 5 | Enterprise Network | Internet, corporate IT, remote access | Entry point for adversaries; VPN/remote access compromise typical first step in ICS attacks |

**IT/OT Convergence Risks**: Remote access expansion (VPNs, RDP) during and after COVID dramatically increased IT-to-OT connectivity. Historian databases at Level 3 often connect to both the corporate network and OT. Vendor remote access frequently bypasses the iDMZ entirely. Active Directory used in IT is increasingly deployed in OT for "convenience," extending the blast radius of credential attacks.

---

## ICS Protocols: Authentication and Encryption Gaps

Most industrial protocols were designed for reliability and determinism in isolated networks — security was an afterthought.

| Protocol | Layer | Auth | Encryption | Primary Use | Key Risk |
|---|---|---|---|---|---|
| **Modbus TCP/RTU** | Application | None | None | PLCs, sensors, HMIs across industries | Any host on the network can issue arbitrary read/write commands; no source verification |
| **DNP3** | Application | Optional (SAv5) | None natively | Electric utilities, water/wastewater SCADA | Replay attacks, spoofed responses; SAv5 adoption remains low |
| **IEC 61850** | Application | Role-based (optional) | Optional TLS | Substation automation, protection relays | GOOSE messages multicast with no auth; injection of protection commands possible |
| **PROFINET** | Application/L2 | None | None | Siemens-heavy manufacturing automation | L2 proximity enables spoofing; no built-in confidentiality |
| **EtherNet/IP** | Application | None | None | Rockwell/Allen-Bradley PLCs, conveyors | Unauthenticated CIP commands can read/write I/O and program logic |
| **BACnet** | Application | Optional (BACnet/SC) | None natively | Building automation (HVAC, lighting, access) | Unauthenticated BACnet/IP widely exposed; Shodan shows thousands of internet-facing devices |
| **OPC-UA** | Application | Yes (X.509, user tokens) | TLS supported | Modern ICS data exchange, historian | Auth/encryption available but frequently disabled for "compatibility"; older OPC-DA has none |

**Defensive implication**: Because these protocols cannot be made inherently secure without replacing infrastructure, defense relies on network segmentation (prevent unauthorized hosts from reaching OT networks), passive anomaly detection (alert on unexpected command sequences), and allowlisting communications (zone/conduit architecture per IEC 62443).

---

## Key Incidents

| Incident | Year | Adversary | Impact | Techniques Demonstrated |
|---|---|---|---|---|
| **Stuxnet** | 2010 | Equation Group (NSA/Unit 8200) | ~1,000 Iranian centrifuges at Natanz physically destroyed | PLC logic modification, rootkit concealing process values, supply chain delivery via USB |
| **Ukraine Power Grid (1st)** | 2015 | Sandworm (GRU Unit 74455) | 230,000 customers lost power; 6 hours outage | Spearphishing → IT pivot → BlackEnergy → HMI takeover → manual breaker control |
| **INDUSTROYER/Crashoverride** | 2016 | Sandworm | Kyiv substation blacked out (~1 hour) | Native ICS protocol manipulation (IEC 61850, IEC 104, GOOSE), wiper payload, serial-to-Ethernet mapping |
| **TRITON/TRISIS** | 2017 | XENOTIME (linked to CNIIHM Russia) | Targeted Schneider Electric Triconex SIS at Saudi petrochemical plant | Safety instrumented system compromise; attempted to disable emergency shutdown; first known SIS attack |
| **Volt Typhoon** | 2023–2024 | PRC state-sponsored | Pre-positioned in US water, energy, telecom, transportation networks | Living-off-the-land, credential theft, long-term persistence for potential wartime disruption |

---

## Free Training

- [CISA ICS Training](https://www.cisa.gov/resources-tools/programs/ics-training-available-through-cisa) — The most comprehensive free ICS security training available; in-person and virtual courses covering ICS fundamentals, network defense, incident response, and vulnerability assessment for critical infrastructure practitioners
- [Idaho National Laboratory (INL) Courses](https://inl.gov/national-security/cyber-security/) — Free and subsidized ICS security courses from the DOE's primary ICS security research lab
- [CISA Training Catalog (NICCS)](https://niccs.cisa.gov/training/catalog) — No-cost federal training including dedicated ICS/SCADA security modules
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) — Free framework documenting adversary tactics and techniques specific to industrial control systems with real-world case studies
- [BHIS ICS/OT Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering OT/ICS security topics and incident response considerations
- [Dragos Year in Review](https://www.dragos.com/year-in-review/) — Annual free threat intelligence report; essential for understanding the threat landscape targeting industrial environments
- [S4 Conference Resources](https://s4xevents.com) — The premier ICS security conference; many talks and materials are made publicly available after the event
- [OpenPLC Runtime](https://autonomylogic.com/docs/openplc-runtime/) — Free open-source PLC runtime for lab environments; essential for building a practice ICS environment without industrial hardware
- [ControlThings Platform](https://www.controlthings.io) — Free Linux distribution with ICS-specific security tools pre-installed; purpose-built for ICS security assessments
- [SANS ICS Security Resources](https://www.sans.org/industrial-control-systems-security/) — SANS ICS-specific free posters, white papers, and course previews

---

## Tools & Repositories

### Network Scanning & Enumeration
- [nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) — NSA's passive ICS/SCADA network visualization tool; builds network topology maps from captured traffic without active scanning; archived but still valuable as a reference
- [klsecservices/s7scan](https://github.com/klsecservices/s7scan) — Siemens S7 PLC scanning and enumeration; identifies S7 devices and reads CPU information
- [digitalbond/Redpoint](https://github.com/digitalbond/Redpoint) — ICS-focused Nmap NSE scripts for enumerating Modbus, DNP3, EtherNet/IP, BACnet, and other industrial protocol devices
- **PLCscan** — Scans networks for PLC devices across multiple vendors; identifies live PLCs by protocol response fingerprinting
- **modscan** — Modbus TCP scanner; enumerates connected devices, reads coils, registers, and device identification information from Modbus-enabled equipment

### Protocol Libraries & Analysis
- [pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) — Full Modbus protocol stack in Python; essential for understanding and testing Modbus TCP/RTU communication
- [mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) — Open-source IEC 61850 MMS and GOOSE protocol library; essential for substation automation security work
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Repository of ICS/SCADA protocol packet captures; essential for learning to recognize normal industrial protocol behavior

### Detection & Monitoring
- [zeek/zeek](https://github.com/zeek/zeek) — Network analysis framework with ICS protocol parsers (Modbus, DNP3, EtherNet/IP); foundation for passive OT network monitoring
- [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) — Curated collection of ICS security tools organized by category
- [mitre/caldera-ot](https://github.com/mitre/caldera-ot) — MITRE CALDERA extension for OT adversary emulation

### Firmware & Embedded Analysis
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — Firmware extraction and analysis; first step for analyzing ICS device firmware
- [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) — Automated firmware extraction, vulnerability scanning, and component identification
- [e-m-b-a/emba](https://github.com/e-m-b-a/emba) — Embedded firmware security analyzer covering known vulnerabilities and hardcoded credentials

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **Dragos Platform** | Gold standard ICS security platform; passive industrial network monitoring, deepest OT threat intelligence; Dragos threat groups database is the authoritative source for ICS adversary tracking |
| **Claroty Aegis** | Industrial cybersecurity covering asset discovery, vulnerability management, threat detection, and secure remote access; Team82 publishes prolific ICS vulnerability research |
| **Nozomi Networks** | OT and IoT security combining passive monitoring with AI-based anomaly detection; strong in energy, transportation, and manufacturing |
| **Armis** | Agentless device visibility for unmanaged OT, IoT, and IoMT devices; strong in healthcare and industrial environments |
| **Fortinet OT Security** | Network security adapted for OT environments; FortiGate with OT protocol awareness and integrated SOC capabilities |
| **Honeywell Forge** | ICS security platform from an industrial automation vendor with deep protocol and safety system knowledge; strong in process industries |
| **Tenable OT Security** | Industrial network monitoring and vulnerability management integrated with Tenable's broader platform |
| **Microsoft Defender for IoT** | OT/ICS network monitoring integrated with Microsoft Sentinel; passive protocol analysis across 60+ industrial protocols |

---

## NIST 800-53 Control Alignment

NIST SP 800-82 Rev 3 (Guide to OT Security) adapts 800-53 for industrial environments. Key mappings:

| Control | ID | ICS/OT Relevance |
|---|---|---|
| Access Control | AC-3, AC-17 | Restrict ICS engineering workstation access; enforce MFA for remote access to OT; eliminate shared accounts on HMIs and SCADA servers |
| Audit and Accountability | AU-2, AU-12 | Log historian access, HMI changes, and engineering workstation connections; OT logging is often absent — establishing it is a primary gap to address |
| Configuration Management | CM-7, CM-8 | Maintain OT asset inventory (Level 0–3 devices); disable unnecessary services on PLCs and HMIs; document all authorized communications |
| Identification and Authentication | IA-2, IA-3 | Require authentication for OT system access; avoid default credentials on all ICS devices; implement device-level authentication where feasible |
| System and Communications Protection | SC-7, SC-8 | Network segmentation per zone-conduit model (IEC 62443); iDMZ between Level 3 and Level 4; unidirectional security gateways (data diodes) for high-consequence environments |
| Incident Response | IR-4, IR-6 | OT-specific incident response procedures; define safe shutdown sequences; coordinate with engineering and operations teams during response |
| Risk Assessment | RA-3, RA-5 | OT-specific vulnerability assessment accounting for operational constraints; passive scanning only in production; consequence-based risk scoring |
| Supply Chain Risk Management | SR-3, SR-4 | Firmware integrity verification for ICS devices; vendor remote access controls; hardware bill of materials for critical components |

**Key Standards**: NIST SP 800-82 Rev 3 (OT Security Guide), IEC 62443 (Industrial Automation Security), NERC CIP (Bulk Electric System)

---

## ATT&CK Coverage

ATT&CK for ICS documents techniques used in real campaigns against industrial environments. Key techniques to detect and mitigate:

| Technique | ID | Description | Detection Approach |
|---|---|---|---|
| Unauthorized Command Message | T0855 | Sending unauthorized commands to PLCs/RTUs to alter setpoints, open/close valves, or trip breakers | Allowlist expected command sources and values; alert on commands from unexpected hosts |
| Denial of Control | T0815 | Preventing operators from issuing commands to process equipment; flooding PLC command queues | Monitor for communication anomalies; rate limiting; redundant control paths |
| Man in the Middle | T0830 | Intercepting and potentially modifying ICS protocol communications between components | Encrypted protocols where possible; passive anomaly detection; network segmentation limiting L2 access |
| Network Connection Enumeration | T0840 | Mapping OT network topology and device inventory as reconnaissance | Alert on active scanning in OT networks; passive discovery is expected but active Nmap scans are not |
| Damage to Property | T0879 | Actions resulting in physical damage to equipment or the environment — the ultimate ICS attack objective | Consequence analysis; physical safety systems (SIS) as last resort; process safety interlocks |
| Activate Firmware Update Mode | T0800 | Forcing a device into firmware update mode to deploy malicious firmware or cause disruption | Restrict firmware update capabilities; monitor for unexpected update mode transitions |
| Modify Control Logic | T0833 | Modifying PLC ladder logic, function block diagrams, or other control programs | Integrity monitoring of PLC programs; compare against known-good baselines; engineering workstation audit logs |
| Spearphishing Attachment | T0865 | Initial access via malicious email attachments targeting OT-adjacent staff (engineers, IT admins) | Email security controls at IT boundary; awareness training for engineering and operations staff |

---

## Certifications

- **GICSP** (Global Industrial Cyber Security Professional — GIAC) — The premier ICS security certification; covers ICS/SCADA architecture, protocols, security controls, and incident response for operational technology; widely recognized across critical infrastructure sectors
- **GRID** (GIAC Response and Industrial Defense) — Advanced ICS incident response and threat hunting; active defense in OT environments, TRITON and INDUSTROYER malware analysis
- **CSSA** (Certified SCADA Security Architect) — Dedicated SCADA/ICS security architecture credential; covers zone-conduit architecture, IEC 62443, and OT security program design
- **ISA/IEC 62443 Cybersecurity Certificate Program** — ISA's certificate program covering the international standard for industrial automation and control system security; tiered levels from awareness through expert
- **ICS-CERT Training** (CISA) — Free government-run ICS security training and certificates; 100-400 series courses from CISA/ICS-CERT provide recognized completion credentials with no cost to practitioners
- **CISSP with ICS/OT focus** — Governance credential increasingly expected for senior ICS security program leadership; pairs well with GICSP for practitioners moving into management

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) | Free framework | Definitive adversary behavior framework for ICS; 12 tactics with real campaign mappings |
| [CISA ICS-CERT Advisories](https://www.cisa.gov/ics-advisories) | Free advisories | Primary source for ICS vulnerability advisories and critical infrastructure alerts |
| [Dragos Year in Review](https://www.dragos.com/year-in-review/) | Free annual report | Most actionable ICS threat intelligence report; covers tracked threat groups |
| [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/3/final) | Free standard | Guide to OT Security; adapts 800-53 for industrial environments |
| [IEC 62443 Standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) | Standard | International security standard for industrial automation; governance framework for ICS programs |
| [NERC CIP Standards](https://www.nerc.com/pa/Stand/Pages/CIPStandards.aspx) | Standard | Mandatory cybersecurity standards for the bulk electric system in North America |
| Hacking Exposed ICS (Bodungen et al.) | Book | Foundational ICS penetration testing reference; covers architecture, protocol attacks, and assessment methodology |
| Countdown to Zero Day (Kim Zetter) | Book | Definitive Stuxnet account; required reading for understanding nation-state ICS attacks |
| Industrial Cybersecurity (Pascal Ackerman) | Book | Practical guide to ICS/SCADA security monitoring, network architecture, and defense-in-depth |
| [Idaho National Laboratory Cyber Programs](https://inl.gov/national-security/cyber-security/) | Free training | Free training, research publications, and SCADA test bed resources from DOE's primary ICS research lab |

---

## Related Disciplines

- [Network Security](network-security.md)
- [IoT Security](iot-security.md)
- [Incident Response](incident-response.md)
- [Threat Intelligence](threat-intelligence.md)
- [Hardware Security](hardware-security.md)
- [Governance, Risk & Compliance](governance-risk-compliance.md)
