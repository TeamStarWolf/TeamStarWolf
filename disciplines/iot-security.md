# IoT Security

IoT Security is the discipline of securing Internet of Things devices — embedded systems, connected sensors, smart home and building devices, wearables, medical devices, and industrial sensors — that operate with limited compute resources and often lack the security controls available on traditional endpoints. The IoT attack surface is uniquely challenging: devices frequently ship with default credentials, no update mechanism, unencrypted communications, and no runtime security tooling. Once deployed, they may remain in the field for years or decades without patching.

IoT Security is distinct from Hardware Security (which focuses on chip-level and physical attacks on computing hardware) and ICS/OT Security (which covers industrial control systems and operational technology). IoT spans consumer, enterprise, and industrial domains — smart thermostats, hospital infusion pumps, IP cameras, and building management systems all represent IoT attack surfaces. The Mirai botnet demonstrated in 2016 that millions of compromised IoT devices running default credentials could be weaponized for the largest DDoS attacks ever recorded, and the threat landscape has only expanded since.

The discipline encompasses firmware security, hardware interface analysis, network protocol security (MQTT, CoAP, Zigbee, Z-Wave, BLE), cloud API security for IoT backends, mobile companion app security, and supply chain integrity. Practitioners must be comfortable operating across all these layers simultaneously.

---

## Where to Start

IoT security requires breadth across embedded systems, networking, and web security. Start by understanding the OWASP IoT Top 10 and practicing firmware analysis with Binwalk on freely available firmware images. RouterSploit and expliot provide hands-on exploitation practice. Building a simple MQTT-based IoT testbed with a Raspberry Pi gives direct experience with the most common IoT protocol.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | OWASP IoT Top 10, firmware extraction and analysis with Binwalk, default credential risks, IoT network protocols (MQTT, CoAP, Zigbee), NIST IR 8259 baseline | OWASP IoT Project (free), Binwalk documentation, DEFCON IoT Village talks (YouTube), NIST IR 8259 (free) |
| Practitioner | Firmware reverse engineering (FACT, FAT), protocol analysis in Wireshark, exploitation with RouterSploit and expliot, mobile companion app testing with MobSF, Shodan enumeration | Attify IoT Security training, Practical IoT Hacking (book), SANS ICS/IoT courses, RouterSploit labs |
| Advanced | Hardware interface exploitation (JTAG, UART, SPI), supply chain firmware analysis, large-scale IoT fleet security architecture, ETSI EN 303 645 compliance, IEC 62443 for industrial IoT | DEFCON Hardware Hacking Village, Hardwear.io, Riscure training, Claroty/Armis platform deep dives |

---

## IoT Attack Surface

| Attack Vector | Description |
|---|---|
| Default Credentials | Devices ship with hardcoded or default username/password pairs; Shodan-exposed management interfaces are routinely exploited at scale |
| Unencrypted Communications | MQTT brokers, CoAP endpoints, and Zigbee/Z-Wave traffic often transmitted in cleartext; susceptible to MitM interception |
| Missing Update Mechanism | No secure FOTA (firmware over-the-air) capability means vulnerabilities persist indefinitely after disclosure |
| Physical Access | UART, JTAG, and SPI debug interfaces expose firmware extraction and root shell access on physically accessible devices |
| Cloud API Misconfigurations | IoT backend APIs lack authentication, expose device enumeration, or allow unauthorized command injection |
| Mobile App Vulnerabilities | Companion apps store credentials insecurely, trust self-signed certs, or expose API keys in compiled binaries |
| Supply Chain Tampering | Malicious firmware implanted during manufacturing or distribution; third-party components with backdoors |
| Botnet Recruitment | Compromised devices enrolled in Mirai-style botnets for DDoS, cryptomining, or as network pivot points |

---

## Free Training & Standards

- [OWASP IoT Project](https://owasp.org/www-project-internet-of-things/) — OWASP IoT Top 10 vulnerabilities, attack surface mapping, and testing guidance; the standard reference for IoT security assessment methodology; free and community-maintained
- [NIST IR 8259 Baseline IoT Device Cybersecurity](https://doi.org/10.6028/NIST.IR.8259) — NIST baseline cybersecurity activities for IoT device manufacturers; foundational reading for understanding what security capabilities IoT devices should provide
- [NIST SP 800-213 IoT Cybersecurity](https://doi.org/10.6028/NIST.SP.800-213) — NIST guidance for federal agencies on IoT cybersecurity; risk considerations and integration of IoT into organizational security programs
- [ETSI EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/02.01.01_60/en_303645v020101p.pdf) — European standard for consumer IoT security; 13 outcome-focused provisions covering default credentials, update mechanisms, and vulnerability disclosure; increasingly referenced globally
- [DEFCON IoT Village](https://www.iotvillage.org) — Annual IoT security research presentations and hands-on hacking contests; YouTube archive contains years of practical IoT attack technique talks
- [Attify IoT Security Training](https://www.attify.com) — Practical IoT security training covering firmware analysis, hardware hacking, and protocol exploitation; the most accessible commercial training focused specifically on IoT
- [Expliot Framework Documentation](https://expliot.readthedocs.io) — Documentation for the IoT exploitation framework covering supported protocols, plugins, and attack workflows; learn by exploring the tooling

---

## Tools & Repositories

### Firmware Analysis
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — The standard firmware extraction and analysis tool; identifies and extracts file systems, compression, and embedded signatures from firmware images; first tool used in any firmware analysis workflow
- [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) — Firmware Analysis and Comparison Tool from Fraunhofer FKIE; automated firmware unpacking, component analysis, vulnerability detection, and cross-firmware comparison; the most capable open-source firmware analysis platform
- [attify/firmware-analysis-toolkit](https://github.com/attify/firmware-analysis-toolkit) — FAT automates firmware emulation using FirmADyne and Binwalk; enables dynamic analysis and network service testing of extracted firmware without physical hardware
- [craigz28/firmwalker](https://github.com/craigz28/firmwalker) — Simple but effective script for searching extracted firmware for passwords, keys, interesting files, and common vulnerability indicators; fast triage after extraction

### Network & Protocol Analysis
- [shodan.io](https://www.shodan.io) — Internet-wide scanner exposing IoT devices by banner, service, and vulnerability; the primary tool for IoT exposure assessment and threat intelligence
- [censys.io](https://censys.io) — Internet-wide scanning and certificate transparency data; complements Shodan for IoT device discovery and exposure analysis
- [nmap](https://nmap.org) — Port scanning and service detection; NSE scripts cover IoT-specific protocols including BACnet, Modbus, and MQTT
- [eclipse/mosquitto](https://github.com/eclipse/mosquitto) — Open-source MQTT broker for testing IoT messaging security; essential for setting up an MQTT test environment and understanding broker misconfigurations

### Exploitation & Testing
- [threat9/routersploit](https://github.com/threat9/routersploit) — Exploitation framework for embedded devices and routers; modules for credential brute-forcing, CVE exploitation, and network service attacks on IoT and network equipment
- [expliot-framework/expliot](https://github.com/expliot-framework/expliot) — IoT exploitation framework covering BLE, MQTT, CoAP, I2C, SPI, UART, and JTAG attack vectors; designed specifically for IoT security testing
- [IoTSeeker](https://github.com/rapid7/IoTSeeker) — Network scanner for detecting IoT devices using default credentials; fast identification of vulnerable devices on enterprise networks

### Mobile App Analysis
- [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Automated mobile app security analysis for Android and iOS; analyzes IoT companion apps for hardcoded credentials, insecure API calls, and certificate validation flaws
- [frida/frida](https://github.com/frida/frida) — Dynamic instrumentation toolkit for hooking and instrumenting mobile apps and embedded binaries; used for runtime analysis of IoT companion apps and firmware

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **Claroty** | Enterprise IoT and OT security platform; agentless device discovery across IT, OT, and IoT environments; vulnerability management, network segmentation guidance, and threat detection; strong in healthcare and industrial deployments |
| **Armis** | Agentless device security platform specializing in unmanaged and IoT devices; passive traffic analysis for device fingerprinting and behavioral monitoring without requiring agents; strong enterprise IoT visibility |
| **Microsoft Defender for IoT** (formerly CyberX) | Agentless IoT and OT security integrated with Microsoft Sentinel; passive network monitoring for device discovery and threat detection; strong value for organizations on the Microsoft security stack |
| **Forescout** | Network access control and device visibility platform; comprehensive IoT device profiling and policy enforcement; strong for network segmentation and access control of unmanaged IoT devices |
| **Tenable.ot** | Vulnerability management extended to IoT and OT environments; combines Nessus scanning capabilities with passive OT/IoT protocol analysis |

---

## NIST 800-53 Controls

| Control | Description |
|---|---|
| IA-3 | Device Identification and Authentication — authenticate IoT devices before granting network access; certificate-based device identity |
| CM-7 | Least Functionality — disable unnecessary services, ports, and protocols on IoT devices; reduce attack surface |
| SC-8 | Transmission Confidentiality and Integrity — encrypt IoT communications; TLS for MQTT/CoAP, transport security for all device-to-cloud traffic |
| SI-3 | Malware Protection — detect and prevent malicious code; runtime integrity monitoring where device resources permit |
| SA-9 | External Information System Services — security requirements for cloud IoT backends, third-party firmware, and managed IoT platforms |
| MA-3 | Maintenance Tools — control physical maintenance interfaces; secure or disable JTAG/UART debug ports in production devices |

---

## ATT&CK Coverage

MITRE ATT&CK Enterprise, ICS, and Mobile domains all apply to IoT. Key techniques relevant to IoT attack scenarios:

| Technique | ID | Relevance to IoT |
|---|---|---|
| Hardware Additions | T1200 | Rogue IoT devices added to networks; hardware implants in supply chain-compromised devices |
| Resource Hijacking | T1496 | Compromised IoT devices enrolled in cryptomining botnets; Mirai-style resource abuse |
| Network Denial of Service | T1498 | Botnet-driven DDoS using compromised IoT devices; amplification attacks from exposed UDP services |
| Non-Standard Port | T1571 | IoT C2 communications on unusual ports; covert channel exfiltration through IoT devices |
| Defacement | T1491 | Web interface defacement on exposed IoT management panels |
| Exploit Public-Facing Application | T1190 | Exploitation of IoT web management interfaces, MQTT brokers, and cloud APIs exposed to the internet |
| Default Accounts | T1078.001 | Default credential exploitation; the most prevalent IoT initial access technique |

---

## Certifications

- **GICSP** (Global Industrial Cyber Security Professional — GIAC) — The most respected credential for ICS/IoT security; covers industrial control systems, embedded devices, and operational technology security; valued in critical infrastructure and industrial IoT roles
- **CEH** (Certified Ethical Hacker — EC-Council) — Includes an IoT security module covering IoT attack techniques and countermeasures; broad coverage appropriate for general security practitioners
- **EC-Council IoTSP** (IoT Security Practitioner) — EC-Council's dedicated IoT security certification covering IoT architecture, attack surface, and security controls; entry-level IoT-specific credential
- **CompTIA Security+** — Covers IoT security concepts at the foundational level; appropriate starting point before more specialized IoT credentials
- **CISSP** (Certified Information Systems Security Professional — ISC2) — Security engineering and asset security domains address IoT security architecture and risk management

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Practical IoT Hacking | Fotios Chantzis, Ioannis Stais, Paulino Calderon, Evangelos Deirmentzoglou, Beau Woods | The definitive hands-on IoT security book; firmware extraction, hardware hacking, protocol analysis, and cloud backend testing; the first book to read for IoT security practitioners |
| The IoT Hacker's Handbook | Aditya Gupta | Practical guide to IoT penetration testing covering hardware, firmware, radio, and mobile attack surfaces; strong on UART/JTAG exploitation and BLE security |
| Hacking Connected Cars | Alissa Knight | IoT security applied to automotive systems; API security, telematics vulnerabilities, and connected vehicle attack chains; relevant for understanding IoT at scale |

---

## Key Resources

- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/) — The standard IoT vulnerability classification; weak passwords, insecure network services, insecure ecosystem interfaces, and more; the baseline for any IoT security assessment
- [NIST IR 8259 Series](https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program) — NIST IoT cybersecurity program covering device baseline, manufacturer guidance, and federal IoT risk management
- [ETSI EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/02.01.01_60/en_303645v020101p.pdf) — European consumer IoT security standard; practical outcome-based requirements increasingly referenced in IoT procurement and regulation
- [IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) — Industrial IoT and OT security standards series; the authoritative framework for industrial IoT security architecture and lifecycle
- [IoT Security Foundation Best Practice Guidelines](https://www.iotsecurityfoundation.org/best-practice-guidelines/) — Free IoT security best practice framework from the IoT Security Foundation; covers vulnerability disclosure, secure design, and deployment guidance
- [Shodan](https://www.shodan.io) — Internet-wide device search engine; essential for understanding real-world IoT exposure and researching device-specific vulnerabilities
- [DEFCON IoT Village YouTube](https://www.youtube.com/@IoTVillage) — Archive of IoT security research presentations from DEFCON; practical attack technique demonstrations across hardware, firmware, and protocol layers

---

## Related Disciplines

- [Hardware Security](/disciplines/hardware-security) — Chip-level and physical security; JTAG/UART exploitation, fault injection, and side-channel attacks on IoT device hardware
- [ICS / OT Security](/disciplines/ics-ot-security) — Industrial control systems and operational technology security; significant overlap in protocol analysis, asset discovery, and operational constraints
- [Mobile Security](/disciplines/mobile-security) — IoT companion app security; Android/iOS analysis of the mobile interface to IoT backends and device control
- [Network Security](/disciplines/network-security) — IoT network segmentation, protocol security, and traffic analysis; VLAN isolation and network access control for IoT devices
- [Supply Chain Security](/disciplines/supply-chain-security) — Firmware supply chain integrity, third-party component security, and manufacturing-time tampering risks
