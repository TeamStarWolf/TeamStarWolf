# Network Security

Monitoring, analyzing, and defending network traffic to detect intrusions, investigate anomalies, and enforce policy across wired, wireless, and cloud-connected environments.

---

## Where to Start

Network security begins with understanding what normal looks like. You cannot detect an intrusion you cannot describe, and you cannot describe it without baseline knowledge of how protocols behave. Start with Wireshark: the ability to read a packet capture is a prerequisite for everything else. Learn TCP/IP deeply — not just the OSI model on a diagram but how handshakes, fragmentation, and protocol negotiation actually look in a capture. Then layer in network security monitoring (NSM) with a tool like Zeek or Security Onion to understand how to extract signal from traffic at scale. Wireless security and protocol-level attacks build naturally from there.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | TCP/IP protocol analysis, Wireshark, packet reading, OSI model | Wireshark University (free), TryHackMe networking rooms, BTFM |
| Practitioner | Zeek scripting, Snort/Suricata rules, NSM architecture, beaconing detection | Security Onion labs, Antisyphon SOC Core Skills, BHIS webcasts |
| Advanced | Network forensics, IDS/IPS tuning, NDR platforms, wireless attack and defense | GCIA, GCFE, SEC503 |

---

## Free Training

- [Antisyphon: SOC Core Skills with John Strand](https://www.antisyphontraining.com/product/soc-core-skills-with-john-strand/) — Pay-what-you-can ($0+); network-based threat detection, Zeek, and NSM fundamentals
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on network defense, beaconing detection, Active Countermeasures tooling, and wireless attacks
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — Extensive network security content from the team behind RITA, BeaKer, and Active Countermeasures
- [Active Countermeasures (Free)](https://www.activecountermeasures.com/free-tools/) — Free tools and training from the RITA/Zeek team; network threat hunting focused
- [IppSec](https://www.youtube.com/@ippsec) — Network enumeration, pivoting, and protocol abuse in HTB walkthroughs; essential for understanding what attackers do on the wire
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Network pentesting techniques and reconnaissance methodology
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; network enumeration, traffic analysis, and pivoting modules
- [TryHackMe](https://tryhackme.com) — Network fundamentals and Wireshark analysis paths
- [Security Onion Documentation](https://docs.securityonion.net) — Free; the most comprehensive NSM setup and operation guide available
- [Wireshark University](https://www.wireshark.org/learn/) — Free sample captures and protocol analysis resources from the Wireshark project

---

## Tools & Repositories

### Packet Analysis
- [wireshark](https://github.com/wireshark/wireshark) — The standard network protocol analyzer; essential for any network investigation
- [tcpdump](https://github.com/nmap/tcpdump) — Command-line packet capture; the universal first-response tool

### Network Scanning & Enumeration
- [masscan](https://github.com/robertdavidgraham/masscan) — The fastest internet-scale port scanner; scans the entire internet in minutes
- [ntopng](https://github.com/ntop/ntopng) — High-speed network traffic monitoring and analysis
- [dnscan](https://github.com/rbsec/dnscan) — DNS subdomain wordlist-based scanner
- [sslscan](https://github.com/rbsec/sslscan) — TLS/SSL cipher suite and certificate enumeration

### Network Security Monitoring
- [zeek](https://github.com/zeek/zeek) — Network analysis framework and scriptable protocol logger; the foundation of NSM
- [snort3](https://github.com/snort3/snort3) — The industry standard IDS/IPS; deep packet inspection and rule-based detection
- [suricata](https://github.com/OISF/suricata) — High-performance IDS/IPS/NSM with multi-threading and EVE JSON output
- [scirius](https://github.com/StamusNetworks/scirius) — Suricata rule management interface by Stamus Networks

### Beaconing & C2 Detection
- [rita](https://github.com/activecm/rita) — Detect C2 beaconing through statistical analysis of Zeek logs
- [BeaKer](https://github.com/activecm/BeaKer) — Beaconing visualization with Zeek logs and Elasticsearch
- [zeek-open-connections](https://github.com/activecm/zeek-open-connections) — Detect long-duration open connections with Zeek
- [zeek-log-transport](https://github.com/activecm/zeek-log-transport) — Zeek log forwarding and transport tooling
- [passer](https://github.com/activecm/passer) — Passive network discovery using Zeek logs
- [espy](https://github.com/activecm/espy) — Network-based EDR sensor for endpoint correlation

### Wireless Security
- [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) — 802.11 WEP and WPA/WPA2 auditing toolkit; the standard wireless security framework
- [bettercap](https://github.com/bettercap/bettercap) — Network attack and monitoring framework with WiFi, BLE, and HID capabilities
- [wifite2](https://github.com/derv82/wifite2) — Automated wireless network auditing
- [wifipumpkin3](https://github.com/P0cL4bs/wifipumpkin3) — Rogue AP framework for wireless security testing
- [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) — Multi-use wireless auditing script
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x) — WPS brute-force attack tool
- [WiFiChallengeLab](https://github.com/r4ulcl/WiFiChallengeLab-docker) — Dockerized wireless security challenge lab

### Bluetooth & RF
- [blue_hydra](https://github.com/dallaswinger/blue_hydra) — Bluetooth device discovery and tracking
- [urh](https://github.com/jopohl/urh) — Universal Radio Hacker; RF protocol analysis and reverse engineering

### Network Libraries & Protocol Tools
- [SMBLibrary](https://github.com/TalAloni/SMBLibrary) — Pure .NET SMB/CIFS client and server implementation
- [PacketSniffer](https://github.com/EONRaider/Packet-Sniffer) — Lightweight Python packet sniffer for learning and analysis

### Threat Hunting via Network
- [threat-hunting-labs](https://github.com/activecm/threat-hunting-labs) — Network-based threat hunting exercises using Zeek and RITA
- [ThreatHunting](https://github.com/GossiTheDog/ThreatHunting) — Network hunting queries from Kevin Beaumont

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Practice of Network Security Monitoring | Richard Bejtlich | The foundational NSM text; everything from sensor placement to Zeek analysis |
| Applied Network Security Monitoring | Sanders & Smith | Hands-on NSM with Zeek, Snort, and Security Onion; lab-first approach |
| Network Security Assessment | Chris McNab | Methodical external and internal network assessment from first principles |
| Silence on the Wire | Michal Zalewski | Passive OS fingerprinting and covert channel analysis; deep protocol intuition |
| The TCP/IP Guide | Charles Kozierok | The comprehensive free reference for every TCP/IP protocol; read it as needed |

---

## Certifications

- **GCIA** (GIAC Certified Intrusion Analyst) — Network traffic analysis, IDS signature development, and anomaly detection; the specialist network security certification
- **GCFE** (GIAC Certified Forensic Examiner) — Covers network forensics artifacts and evidence handling
- **CompTIA Network+** — Vendor-neutral networking foundation required for everything above it
- **CompTIA Security+** — Includes network defense, IDS/IPS, and monitoring fundamentals
- **Cisco CyberOps Associate** — Network monitoring and SOC-focused; free Cisco NetAcad materials available

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Network defense, beaconing detection, and Active Countermeasures tooling; the team behind RITA and Zeek-based threat hunting
- [13Cubed](https://www.youtube.com/@13Cubed) — Network forensics, packet analysis, and DFIR with network evidence
- [SANS Internet Storm Center](https://www.youtube.com/@SansInstitute) — Network threat analysis and packet-level walkthroughs
- [Professor Messer](https://www.youtube.com/@professormesser) — Free CompTIA Network+ and Security+ study content; excellent networking foundations
- [David Bombal](https://www.youtube.com/@davidbombal) — Networking, Wireshark, and practical network security labs

---

## Who to Follow

- [@MalwareTechBlog](https://x.com/MalwareTechBlog) — Marcus Hutchins; network analysis and malware C2 infrastructure
- [@GossiTheDog](https://x.com/GossiTheDog) — Kevin Beaumont; network threat hunting and detection
- [@jaredhaight](https://x.com/jaredhaight) — Active Countermeasures; network threat detection and RITA
- [@ncatteau](https://x.com/ncatteau) — Stamus Networks; Suricata and enterprise NDR
- [@zeekurity](https://x.com/zeekurity) — Zeek network security monitor project
- [@SecurityOnion](https://x.com/SecurityOnion) — Security Onion platform updates and threat hunting content
- [@DougBurks](https://x.com/DougBurks) — Security Onion creator

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map network-based ATT&CK techniques (Command and Control, Lateral Movement, Exfiltration) to detection coverage, Sigma rules, and Zeek/Suricata detection content
- [Security Onion](https://securityonionsolutions.com) — Free NSM and threat hunting platform; the fastest way to stand up a full detection stack with Zeek, Suricata, and Elasticsearch
- [Active Countermeasures](https://www.activecountermeasures.com) — Free RITA tool and network threat hunting resources; the most actionable free NSM toolkit
- [Zeek Documentation](https://docs.zeek.org) — The authoritative Zeek scripting and deployment reference
- [SANS NSM Resources](https://isc.sans.edu) — Network monitoring guidance and daily threat reports
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Free PCAP library covering dozens of protocols; essential for analysis practice
