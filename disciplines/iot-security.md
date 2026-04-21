# IoT Security

IoT Security is the discipline of securing Internet of Things devices — embedded systems, connected sensors, smart home and building devices, wearables, medical devices, and industrial sensors — that operate with limited compute resources and often lack the security controls available on traditional endpoints. The IoT attack surface is uniquely challenging: devices frequently ship with default credentials, no update mechanism, unencrypted communications, and no runtime security tooling. Once deployed, they may remain in the field for years or decades without patching.

IoT Security is distinct from Hardware Security (which focuses on chip-level and physical attacks on computing hardware) and ICS/OT Security (which covers industrial control systems and operational technology). IoT spans consumer, enterprise, and industrial domains — smart thermostats, hospital infusion pumps, IP cameras, and building management systems all represent IoT attack surfaces. The Mirai botnet demonstrated in 2016 that millions of compromised IoT devices running default credentials could be weaponized for the largest DDoS attacks ever recorded. VPNFilter (2018, attributed to GRU Sandworm) compromised 500,000+ routers and NAS devices for espionage and destructive capability. The threat landscape continues to expand as device counts approach 30 billion.

The discipline encompasses firmware security, hardware interface analysis, network protocol security (MQTT, CoAP, Zigbee, Z-Wave, BLE), cloud API security for IoT backends, mobile companion app security, and supply chain integrity. Practitioners must be comfortable operating across all these layers simultaneously.

---

## Where to Start

IoT security requires breadth across embedded systems, networking, and web security. Start by understanding the OWASP IoT Top 10 and practicing firmware analysis with binwalk on freely available firmware images. RouterSploit and expliot provide hands-on exploitation practice. Building a simple MQTT-based IoT testbed with a Raspberry Pi gives direct experience with the most common IoT protocol.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | OWASP IoT Top 10, firmware extraction with `binwalk -eM`, default credential risks, IoT network protocols (MQTT, CoAP, Zigbee), NIST IR 8259 baseline, Mirai botnet case study | [OWASP IoT Project](https://owasp.org/www-project-internet-of-things/) (free), Binwalk documentation, DEFCON IoT Village talks (YouTube), [NIST IR 8259](https://doi.org/10.6028/NIST.IR.8259) (free) |
| Practitioner | Firmware reverse engineering (FACT, firmwalker), QEMU emulation of extracted firmware, MQTT attack scenarios, protocol analysis in Wireshark, exploitation with RouterSploit and expliot, Shodan enumeration | Attify IoT Security training, Practical IoT Hacking (book), SANS ICS/IoT courses, RouterSploit labs |
| Advanced | Hardware interface exploitation (JTAG, UART, SPI), device identity (X.509 per-device certs, TPM attestation, FIDO Device Onboard), large-scale IoT fleet security architecture, ETSI EN 303 645 compliance, IEC 62443 for industrial IoT | DEFCON Hardware Hacking Village, Hardwear.io, Riscure training, Claroty/Armis deep dives |

---

## OWASP IoT Top 10

The OWASP IoT Top 10 documents the most critical security risks in IoT products.

| # | Vulnerability | Description | Example |
|---|---|---|---|
| I1 | Weak, Guessable, or Hardcoded Passwords | Default credentials, hardcoded passwords, no enforcement of strong passwords | Mirai exploited factory-default telnet credentials on cameras and routers |
| I2 | Insecure Network Services | Unnecessary network services running, unencrypted services, services vulnerable to buffer overflow | Telnet on port 23, unauthenticated HTTP management interfaces |
| I3 | Insecure Ecosystem Interfaces | Insecure web, mobile, cloud, and API interfaces allowing exploitation of connected systems | Unprotected REST APIs allowing unauthenticated device control from the internet |
| I4 | Lack of Secure Update Mechanism | No firmware update capability, unsigned updates, unencrypted update channels, no rollback protection | No FOTA mechanism means vulnerabilities persist indefinitely; unsigned updates allow malicious firmware |
| I5 | Use of Insecure or Outdated Components | Outdated OS versions, libraries with known CVEs, abandoned third-party components | Embedded Linux kernel from 2012, OpenSSL 1.0.1 with Heartbleed, deprecated third-party SDKs |
| I6 | Insufficient Privacy Protection | Personal data stored insecurely, transmitted without encryption, or shared without consent | Smart speaker recordings stored unencrypted; health data transmitted in cleartext |
| I7 | Insecure Data Transfer and Storage | No encryption for sensitive data in transit or at rest; no integrity protection | MQTT credentials transmitted in plaintext; API keys hardcoded in firmware |
| I8 | Lack of Device Management | No support for device inventory, update management, monitoring, or secure decommissioning | No capability to remotely disable compromised devices; no audit trail of configuration changes |
| I9 | Insecure Default Settings | Insecure out-of-box configuration; debug interfaces left enabled; unnecessary features active | JTAG/UART debug ports enabled in production firmware; SSH on default port with weak key |
| I10 | Lack of Physical Hardening | Physical disassembly reveals JTAG/UART debug interfaces; unprotected flash chips; no tamper detection | Exposed JTAG header provides root shell; SPI flash contains plaintext keys readable via direct probe |

---

## Firmware Analysis

Firmware analysis is the process of extracting and examining the software running on an IoT device to identify vulnerabilities, hardcoded credentials, and security weaknesses.

### Extraction with binwalk
```bash
# Recursive extraction of all recognized formats
binwalk -eM firmware.bin

# List signatures found without extracting
binwalk firmware.bin

# Extract specific file system
binwalk --dd='squashfs:squashfs' firmware.bin
```

**binwalk -eM** (`--extract --matryoshka`) recursively extracts embedded file systems, compressed archives, and nested firmware images. After extraction, the `_firmware.bin.extracted/` directory contains the device's root filesystem for manual analysis.

### Post-Extraction Analysis with firmwalker
```bash
# Search extracted filesystem for credentials and interesting files
./firmwalker.sh /path/to/_firmware.bin.extracted/
```

firmwalker searches extracted firmware for:
- Password files (`passwd`, `shadow`)
- SSL private keys and certificates
- Configuration files with credentials
- Hard-coded IP addresses and URLs
- SSH authorized keys
- Web server configurations

### QEMU Emulation
For dynamic analysis, QEMU can emulate the device's processor architecture to run firmware binaries without physical hardware:
```bash
# Install binaries for target architecture (e.g., MIPS)
sudo apt install qemu-user-static

# Emulate a MIPS binary
qemu-mips-static -L /path/to/extracted/rootfs /path/to/binary

# Full system emulation with FAT/FirmADyne
# Enables network service testing of extracted firmware
```

QEMU emulation allows dynamic testing of web servers, MQTT brokers, and other services extracted from firmware without requiring physical devices.

---

## MQTT Attack Scenarios

MQTT (Message Queuing Telemetry Transport) is the dominant IoT messaging protocol. Insecure deployments are pervasive.

### Unauthenticated Broker Discovery and Data Theft
```bash
# Subscribe to ALL topics on an unauthenticated broker
mosquitto_sub -h TARGET_IP -t '#' -v

# Subscribe to specific device topic namespace
mosquitto_sub -h TARGET_IP -t 'home/#' -v
mosquitto_sub -h TARGET_IP -t 'sensor/+/data' -v
```

The `#` wildcard subscribes to every topic, exposing all messages published to the broker — sensor readings, commands, credentials, and device status. Shodan query `port:1883` reveals thousands of internet-exposed MQTT brokers, many without authentication.

### Command Injection via MQTT
```bash
# Publish unauthorized command to a device
mosquitto_pub -h TARGET_IP -t 'home/thermostat/cmd' -m '{"action":"setTemp","value":99}'

# Attempt to publish to control topics after observing normal traffic
mosquitto_pub -h TARGET_IP -t 'actuator/door/control' -m 'UNLOCK'
```

### Credential Theft
Many MQTT brokers require username/password but transmit credentials in plaintext over TCP. A network-level MitM on port 1883 intercepts credentials in the CONNECT packet. Even when TLS is used, certificate validation is frequently disabled in IoT MQTT clients.

**Mitigations**: Enable MQTT authentication and TLS (port 8883), validate certificates in client implementations, use ACLs to restrict topic access per device, consider MQTT 5.0 enhanced authentication.

---

## IoT Botnets

### Mirai (2016)
Mirai achieved its scale by scanning for IoT devices accepting default Telnet credentials from a hardcoded list of 62 username/password pairs. Infected devices ran a Linux-based bot that launched massive UDP and TCP flood DDoS attacks. The September 2016 attacks against Krebs on Security (620 Gbps) and Dyn DNS (disrupting Twitter, Netflix, Amazon) remain among the largest DDoS events recorded. Mirai's source code was released publicly, spawning dozens of successor variants (Satori, Reaper, Mozi).

**Technical mechanism**: Telnet scanner → default credential brute-force → shell command injection → download and execute Mirai binary for device architecture → kill competing malware → connect to C2 → await DDoS commands.

### VPNFilter (2018)
VPNFilter was attributed to Sandworm (GRU Unit 74455) and compromised 500,000+ home and small-office routers across 54 countries. Unlike Mirai, VPNFilter was a sophisticated multi-stage modular malware designed for espionage and sabotage — not just DDoS:
- **Stage 1**: Persistent loader surviving reboots; contacted Photobucket for C2 infrastructure (DNS/Tor fallback)
- **Stage 2**: Core intelligence collection; Modbus SCADA protocol sniffer; destructive "kill" capability to brick devices
- **Stage 3**: Pluggable modules including packet sniffer, credential harvester, and Tor anonymization

VPNFilter demonstrated that nation-state adversaries treat compromised IoT/router infrastructure as persistent intelligence collection platforms, not just botnets.

---

## Device Identity

Secure device identity is the foundation of IoT security — without it, any device can impersonate any other.

| Mechanism | Description | Maturity |
|---|---|---|
| **X.509 Per-Device Certificates** | Each device receives a unique X.509 certificate at manufacture; used for TLS mutual authentication to cloud backends; certificate revocation enables remote disable | Widely deployed in enterprise IoT; AWS IoT, Azure IoT Hub, GCP IoT Core all support |
| **TPM Attestation** | Trusted Platform Module (TPM 2.0) stores device identity keys in hardware; remote attestation proves device identity and firmware integrity to servers | Growing adoption in higher-security IoT; used in automotive and industrial contexts |
| **FIDO Device Onboard (FDO)** | FIDO Alliance standard for automated IoT device provisioning; cryptographic device identity established at manufacture; zero-touch provisioning to cloud platforms without manual configuration | Emerging; Intel Open FDO is the reference implementation; designed to solve supply chain onboarding at scale |
| **Symmetric Keys (PSK)** | Pre-shared keys provisioned per device; simpler than PKI but key compromise affects only one device if keys are truly unique; common in resource-constrained devices | Widely used; inferior to PKI for revocation but acceptable for very constrained devices |

---

## Free Training & Standards

- [OWASP IoT Project](https://owasp.org/www-project-internet-of-things/) — OWASP IoT Top 10, attack surface mapping, and testing guidance; standard reference for IoT security assessment methodology
- [NIST IR 8259: Baseline IoT Device Cybersecurity](https://doi.org/10.6028/NIST.IR.8259) — NIST baseline cybersecurity activities for IoT device manufacturers; foundational reading for device security requirements
- [NIST SP 800-213: IoT Cybersecurity](https://doi.org/10.6028/NIST.SP.800-213) — NIST guidance for federal agencies on IoT cybersecurity; risk considerations and integration into organizational security programs
- [ETSI EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/02.01.01_60/en_303645v020101p.pdf) — European standard for consumer IoT security; 13 outcome-focused provisions covering default credentials, update mechanisms, and vulnerability disclosure
- [DEFCON IoT Village](https://www.iotvillage.org) — Annual IoT security research presentations and hands-on contests; YouTube archive of practical attack technique talks
- [Attify IoT Security Training](https://www.attify.com) — Practical IoT security training covering firmware analysis, hardware hacking, and protocol exploitation
- [Expliot Framework Documentation](https://expliot.readthedocs.io) — Documentation for the IoT exploitation framework

---

## Tools & Repositories

### Firmware Analysis
- [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) — Standard firmware extraction and analysis tool; identifies and extracts file systems from firmware images; first tool in any firmware analysis workflow
- [craigz28/firmwalker](https://github.com/craigz28/firmwalker) — Searches extracted firmware for passwords, keys, interesting files, and vulnerability indicators; fast triage after extraction
- [fkie-cad/FACT_core](https://github.com/fkie-cad/FACT_core) — Firmware Analysis and Comparison Tool from Fraunhofer FKIE; automated unpacking, component analysis, vulnerability detection, and cross-firmware comparison
- [attify/firmware-analysis-toolkit](https://github.com/attify/firmware-analysis-toolkit) — FAT automates QEMU-based firmware emulation; enables dynamic analysis and network service testing without physical hardware

### Network & Protocol Analysis
- [shodan.io](https://www.shodan.io) — Internet-wide scanner exposing IoT devices; primary tool for IoT exposure assessment and device-specific vulnerability research
- [eclipse/mosquitto](https://github.com/eclipse/mosquitto) — Open-source MQTT broker; essential for MQTT security testing and understanding broker misconfigurations
- [IoTSeeker](https://github.com/rapid7/IoTSeeker) — Network scanner for detecting IoT devices using default credentials; rapid identification of vulnerable devices on enterprise networks

### Exploitation & Testing
- [threat9/routersploit](https://github.com/threat9/routersploit) — Exploitation framework for embedded devices and routers; modules for credential brute-forcing, CVE exploitation, and network service attacks
- [expliot-framework/expliot](https://github.com/expliot-framework/expliot) — IoT exploitation framework covering BLE, MQTT, CoAP, I2C, SPI, UART, and JTAG; designed specifically for IoT security testing

### Mobile App Analysis
- [MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Automated mobile app security analysis for Android and iOS; analyzes IoT companion apps for hardcoded credentials and insecure API calls
- [frida/frida](https://github.com/frida/frida) — Dynamic instrumentation toolkit for hooking mobile apps and embedded binaries; runtime analysis of IoT companion apps and firmware

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **Claroty** | Enterprise IoT and OT security; agentless device discovery, vulnerability management, network segmentation guidance, and threat detection; strong in healthcare and industrial |
| **Armis** | Agentless device security specializing in unmanaged and IoT devices; passive traffic analysis for device fingerprinting and behavioral monitoring |
| **Microsoft Defender for IoT** | Agentless IoT and OT security integrated with Microsoft Sentinel; passive network monitoring for device discovery and threat detection |
| **Forescout** | Network access control and device visibility; comprehensive IoT device profiling and policy enforcement for network segmentation |
| **Tenable.ot** | Vulnerability management extended to IoT and OT environments; combines Nessus capabilities with passive OT/IoT protocol analysis |

---

## NIST 800-53 Control Alignment

| Control | ID | IoT Security Relevance |
|---|---|---|
| Device Identification and Authentication | IA-3 | Authenticate IoT devices before granting network access; X.509 per-device certificates, TPM attestation, and FIDO Device Onboard provide cryptographic device identity; prevents rogue device enrollment |
| Least Functionality | CM-7 | Disable unnecessary services, ports, and protocols on IoT devices; disable debug interfaces (JTAG/UART) in production firmware; reduce attack surface to what is operationally required |
| Malware Protection | SI-3 | Detect and prevent malicious code on IoT devices; runtime integrity monitoring and secure boot where device resources permit; network-level inspection as compensating control for constrained devices |
| External Information System Services | SA-4 | Security requirements for IoT supply chain: firmware integrity signing, vulnerability disclosure programs, and security documentation as acquisition requirements for IoT procurement |
| Transmission Confidentiality and Integrity | SC-8 | Encrypt IoT communications; TLS for MQTT (port 8883) and CoAP (DTLS); transport security for all device-to-cloud traffic; prevent credential interception and command injection |
| Information System Monitoring | SI-4 | Network monitoring for IoT traffic anomalies; detect unexpected device communications, command and control beaconing, and botnet recruitment behaviors |
| Maintenance Tools | MA-3 | Control physical maintenance interfaces; disable or physically protect JTAG and UART debug ports in production devices; document and control all hardware debug access |
| Supply Chain Risk Management | SR-3 | Firmware supply chain integrity verification; hardware bill of materials (HBOM) for critical IoT components; manufacturer security attestation in procurement requirements |

**Key Standards**: NIST IR 8259 (IoT Device Baseline), NIST SP 800-213 (Federal IoT Security), ETSI EN 303 645 (Consumer IoT), IEC 62443 (Industrial IoT)

---

## ATT&CK Coverage

MITRE ATT&CK Enterprise, ICS, and Mobile domains all apply to IoT. Key techniques:

| Technique | ID | IoT Relevance | Detection Approach |
|---|---|---|---|
| Hardware Additions | T1200 | Rogue IoT devices added to networks; hardware implants in supply chain-compromised devices | Network access control (802.1X); device certificate enrollment gates network access |
| Resource Hijacking | T1496 | Compromised IoT devices enrolled in cryptomining botnets; Mirai-style DDoS resource abuse | Monitor for unusual outbound traffic volume; detect known C2 infrastructure |
| Network Denial of Service | T1498 | Botnet-driven DDoS using compromised IoT; amplification attacks from exposed UDP services (DNS, NTP, SSDP) | ISP-level filtering; network anomaly detection; SSDP/NTP amplification blocking |
| Non-Standard Port | T1571 | IoT C2 communications on unusual ports; covert channel exfiltration through IoT devices | Egress filtering to permitted destinations only; alert on unexpected port/protocol combinations |
| Exploit Public-Facing Application | T1190 | Exploitation of IoT web management interfaces, MQTT brokers, and cloud APIs exposed to internet | Network segmentation; IoT devices behind NAT; avoid internet exposure of management interfaces |
| Default Accounts | T1078.001 | Default credential exploitation; most prevalent IoT initial access technique; automated by Mirai scanner | Enforce credential change at provisioning; credential scanning during deployment |
| Firmware Corruption | T0839 | Malicious firmware update to compromise device or destroy functionality; VPNFilter kill stage | Signed firmware updates; secure boot chain; FOTA integrity verification before application |
| Modify Firmware | T0821 | Attacker replaces or modifies device firmware to establish persistence or add malicious capability | Firmware integrity monitoring; compare running firmware hash against manufacturer baseline |

---

## Certifications

- **GICSP** (Global Industrial Cyber Security Professional — GIAC) — Most respected credential for ICS/IoT security; covers industrial control systems, embedded devices, and operational technology; valued in critical infrastructure and industrial IoT roles
- **CEH** (Certified Ethical Hacker — EC-Council) — Includes an IoT security module covering attack techniques and countermeasures
- **EC-Council IoTSP** (IoT Security Practitioner) — EC-Council's dedicated IoT security certification covering IoT architecture, attack surface, and security controls
- **CompTIA Security+** — Covers IoT security concepts at the foundational level; appropriate starting point before specialized IoT credentials
- **CISSP** (ISC2) — Security engineering and asset security domains address IoT security architecture and risk management

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/) | Free reference | Standard IoT vulnerability classification; baseline for any IoT security assessment |
| [NIST IR 8259 Series](https://www.nist.gov/programs-projects/nist-cybersecurity-iot-program) | Free standard | NIST IoT cybersecurity program: device baseline, manufacturer guidance, federal IoT risk management |
| [NIST SP 800-213](https://doi.org/10.6028/NIST.SP.800-213) | Free standard | NIST guidance for integrating IoT into organizational security programs |
| [ETSI EN 303 645](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/02.01.01_60/en_303645v020101p.pdf) | Free standard | European consumer IoT security standard; practical outcome-based requirements |
| [IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) | Standard | Industrial IoT and OT security standards series; authoritative framework for industrial IoT security |
| Practical IoT Hacking (Chantzis et al.) | Book | Definitive hands-on IoT security book: firmware extraction, hardware hacking, protocol analysis, cloud backend testing |
| The IoT Hacker's Handbook (Aditya Gupta) | Book | Practical IoT penetration testing covering hardware, firmware, radio, and mobile attack surfaces |
| [DEFCON IoT Village YouTube](https://www.youtube.com/@IoTVillage) | Free videos | Archive of IoT security research from DEFCON; practical attack demonstrations |
| [Shodan](https://www.shodan.io) | Tool | Internet-wide device search engine; essential for understanding real-world IoT exposure |

---

## Related Disciplines

- [Hardware Security](hardware-security.md)
- [ICS / OT Security](ics-ot-security.md)
- [Mobile Security](mobile-security.md)
- [Network Security](network-security.md)
- [Supply Chain Security](supply-chain-security.md)
