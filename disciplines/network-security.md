# Network Security

Network security encompasses the tools, techniques, and disciplines used to monitor, defend, and investigate network traffic. It spans network security monitoring (NSM), intrusion detection and prevention (IDS/IPS), traffic analysis and packet capture, wireless security, and the detection of adversary behaviors in network data — command-and-control beaconing, lateral movement, data exfiltration, and protocol abuse. Network security practitioners work with raw packet data, flow records, DNS logs, and proxy logs to reconstruct adversary activity that endpoint tools never see, and to detect threats in environments where agents cannot be deployed.

The discipline has expanded significantly with the rise of encrypted traffic, cloud networking, and east-west lateral movement that never crosses a perimeter. Modern network security requires understanding TLS inspection, cloud VPC flow logs, DNS-over-HTTPS implications for detection, and the network behavior signatures of sophisticated threat actors who specifically design their tools to blend into normal business traffic.

---

## Where to Start

Network security rewards people who understand how protocols actually work. Spend time with Wireshark before learning any detection tools — understand what normal HTTP, DNS, SMB, and Kerberos traffic looks like at the packet level before trying to detect anomalies in it. The free Wireshark University videos and Chris Sanders' Applied NSM content are the right starting points. From there, learn Zeek for structured log generation, then Suricata for signature-based detection.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | TCP/IP stack, Wireshark packet analysis, DNS/HTTP/SMB protocol internals, network topology, basic IDS/IPS concepts | Wireshark University (free), TryHackMe Network Fundamentals, Chris Sanders NSM blog, Antisyphon Network Analysis (PWYW) |
| Practitioner | Zeek log analysis, Suricata rules, network flow analysis, beaconing detection, protocol anomaly identification, wireless security | Security Onion documentation, Zeek documentation, Emerging Threats Suricata rules, RITA project |
| Advanced | Encrypted traffic analysis, cloud network security (VPC flow logs, AWS GuardDuty), network forensics, sensor architecture design | SANS FOR572, SANS SEC503 previews, Corelight research blog, ExtraHop threat research |

---

## Free Training

- [Antisyphon Network Analysis and Threat Hunting (PWYW)](https://www.antisyphontraining.com) — Pay-what-you-can course covering network analysis, threat hunting from network data, and NSM methodology from John Strand and BHIS practitioners
- [Chris Sanders Applied NSM Resources](https://chrissanders.org) — Free blog content and resources from the author of Applied Network Security Monitoring; the practitioner's foundational NSM methodology reference
- [Security Onion Documentation](https://docs.securityonion.net) — Free documentation for the leading open-source NSM platform; covers Zeek, Suricata, Elasticsearch, and analyst workflows in a single integrated environment
- [SANS Network Security Summit Talks](https://www.youtube.com/@SansInstitute) — Annual summit recordings covering advanced network detection, encrypted traffic analysis, and network forensics methodology
- [TryHackMe Network Security Paths](https://tryhackme.com) — Guided paths covering network analysis fundamentals, Wireshark, Snort/Suricata, and traffic investigation with browser-based labs
- [Wireshark University](https://www.wireshark.org) — Free Wireshark documentation and sample capture files; the authoritative learning resource for the world's most deployed packet analysis tool
- [Zeek Documentation](https://docs.zeek.org) — Free documentation for the leading network analysis framework; scripting reference, protocol analyzer docs, and log format specification
- [Emerging Threats Open Rules](https://rules.emergingthreats.net/open/) — Free Suricata and Snort signature library from Proofpoint; thousands of community-maintained network detection rules
- [BHIS Network Security Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on network monitoring, traffic analysis, and network-based threat detection
- [Hack The Box Academy Network Path](https://academy.hackthebox.com) — Free Student tier covering network traffic analysis, Wireshark, and network forensics fundamentals

---

## Tools & Repositories

### Packet Analysis & Capture
- [wireshark/wireshark](https://github.com/wireshark/wireshark) — The universal packet analysis tool; required proficiency for every network security practitioner; captures and dissects hundreds of protocols with a GUI and tshark CLI for automation
- [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) — The foundational command-line packet capture tool; the basis for live capture in resource-constrained environments, remote capture sessions, and scripted packet collection
- [the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap) — The portable C/C++ packet capture library underlying Wireshark, tcpdump, Zeek, Suricata, and most other capture tools; understanding it helps when writing custom capture tooling
- [nmap/nmap](https://github.com/nmap/nmap) — Network mapping and port scanning; the universal host discovery and service fingerprinting tool; essential for asset inventory and network reconnaissance

### Network Security Monitoring (NSM)
- [zeek/zeek](https://github.com/zeek/zeek) — The leading network analysis framework; generates rich structured logs from live traffic or pcap across dozens of protocols; the backbone of every serious NSM deployment and the primary data source for network-based detection rules
- [OISF/suricata](https://github.com/OISF/suricata) — High-performance IDS, IPS, and network security monitoring engine; processes millions of packets per second, supports Lua scripting for custom detection, and outputs EVE JSON for SIEM integration
- [Security-Onion-Solutions/securityonion](https://github.com/Security-Onion-Solutions/securityonion) — The leading open-source NSM platform integrating Zeek, Suricata, Elasticsearch, Kibana, and analyst workflow tools; the fastest way to deploy a full network monitoring capability
- [activecm/rita](https://github.com/activecm/rita) — Real Intelligence Threat Analytics; statistical beaconing detection through Zeek log analysis; one of the most effective open-source tools for identifying C2 communications in network data

### Scanning & Enumeration
- [nmap/nmap](https://github.com/nmap/nmap) — See above; also includes the NSE scripting engine for protocol-specific enumeration and vulnerability detection
- [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) — Fast port scanner in Go with SYN scan support; used in large-scale external attack surface enumeration
- [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) — The fastest internet-scale port scanner; asynchronous transmission handling millions of packets per second; used for internet-wide scan research and large network enumeration

### Beaconing & C2 Detection
- [activecm/rita](https://github.com/activecm/rita) — See above; the primary open-source tool specifically designed for detecting beaconing and long-connection C2 patterns in Zeek data
- [fox-it/flow.record](https://github.com/fox-it/flow.record) — Fox IT's network flow analysis framework for investigating network traffic patterns during incident response
- [salesforce/ja3](https://github.com/salesforce/ja3) — JA3 TLS fingerprinting method and implementation; fingerprints TLS client behavior to identify malware and anomalous TLS configurations without decrypting traffic

### Wireless & RF Security
- [aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) — Suite of wireless network security tools covering capture, analysis, and password recovery for WEP/WPA/WPA2/WPA3; the standard wireless security assessment toolkit
- [vanhoefm/krackattacks-scripts](https://github.com/vanhoefm/krackattacks-scripts) — KRACK (Key Reinstallation Attack) proof-of-concept scripts; essential reference for understanding WPA2 protocol-level vulnerabilities
- [kismetwireless/kismet](https://github.com/kismetwireless/kismet) — Wireless network detector, sniffer, and IDS for 802.11, Bluetooth, and RF monitoring; passive detection of rogue access points and wireless threats

### Bluetooth & RF
- [greatscottgadgets/ubertooth](https://github.com/greatscottgadgets/ubertooth) — Open-source Bluetooth experimentation platform; packet capture and analysis for classic Bluetooth and BLE for security assessment
- [jopohl/urh](https://github.com/jopohl/urh) — Universal Radio Hacker; analyze, demodulate, and decode unknown wireless protocols for RF security research

### Protocol Libraries
- [secdev/scapy](https://github.com/secdev/scapy) — Python-based interactive packet manipulation library; craft, send, receive, and dissect packets across hundreds of protocols; the network security practitioner's Swiss Army knife for custom protocol testing
- [boundary-project/boundary](https://github.com/hashicorp/boundary) — HashiCorp's identity-based network access; relevant for zero-trust network architecture implementation

---

## Commercial & Enterprise Platforms

Network security has a mature commercial market with specialized vendors for NDR (Network Detection and Response), full packet capture, and network forensics.

| Platform | Strength |
|---|---|
| **Darktrace** | AI-powered NDR using unsupervised machine learning to detect anomalous network behavior; self-learning models for each environment; strongest for detecting novel and slow-burn threats that signature-based tools miss; also covers email, cloud, and OT networks |
| **ExtraHop Reveal(x)** | Cloud-native NDR with full-stream reassembly and ML-based threat detection; decrypts TLS traffic at the sensor; exceptional for east-west visibility in enterprise environments; strong cloud and container network monitoring |
| **Corelight** | Enterprise Zeek platform; commercial version of Zeek with encrypted traffic analytics, Smart PCAP, and managed sensor infrastructure; the platform of choice for organizations that want Zeek at scale with commercial support |
| **Vectra AI** | AI-driven NDR focusing on attacker behavior detection in network traffic; Cognito platform detects lateral movement, C2, and privilege escalation using behavioral models; strong integration with Microsoft Sentinel and CrowdStrike |
| **Palo Alto Networks NGFW / Cortex XDR Network** | Market-leading next-generation firewall with App-ID, User-ID, and threat prevention; Cortex XDR Network adds behavioral analytics across network, endpoint, and cloud telemetry |
| **Cisco Stealthwatch (Secure Network Analytics)** | Flow-based network analytics and anomaly detection at enterprise scale; integrates with Cisco network infrastructure for visibility across campus, data center, and cloud environments |
| **Gigamon** | Network visibility and traffic intelligence platform; deep packet inspection, metadata extraction, and inline decryption for feeding security tools |
| **Rapid7 InsightIDR** | SIEM with built-in network detection using Insight Network Sensor; combines network traffic analysis with log management for unified detection |
| **Claroty (OT/IT convergence)** | Industrial network monitoring that also covers IT/OT convergence points; relevant for organizations with operational technology environments connected to enterprise networks |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Applied Network Security Monitoring | Sanders & Smith | The foundational NSM text; covers sensor placement, data collection, analysis workflow, and the analyst mindset; required reading for anyone building a network monitoring capability |
| The Practice of Network Security Monitoring | Richard Bejtlich | Companion to Applied NSM; covers NSM philosophy, collection strategy, and the practitioner approach to network-based threat detection |
| Network Forensics: Tracking Hackers Through Cyberspace | Davidoff & Ham | The definitive network forensics reference; covers pcap analysis, protocol reconstruction, and evidence extraction from network data |
| Hacking: The Art of Exploitation | Jon Erickson | Network protocol exploitation at the C and assembly level; foundational for understanding what network attacks look like at the packet level |

---

## Certifications

- **GNFA** (GIAC Network Forensic Analyst) — Network forensics, protocol analysis, and investigation methodology; the most directly relevant GIAC certification for network security analysts; pairs with SANS FOR572
- **GCIA** (GIAC Certified Intrusion Analyst) — IDS/IPS analysis, network traffic investigation, and signature development; pairs with SANS SEC503; the gold standard for network intrusion analysis
- **Network+** (CompTIA) — Vendor-neutral networking fundamentals covering protocols, topology, and troubleshooting; the baseline networking credential before specializing in network security
- **CCNA** (Cisco Certified Network Associate) — Cisco networking fundamentals; practical networking knowledge that underpins network security architecture decisions
- **Cisco CyberOps Associate** — Security operations focused Cisco certification covering network monitoring, intrusion analysis, and incident response from a network perspective

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Network analysis, threat hunting from network data, and NSM methodology from John Strand and practitioners
- [Chris Sanders](https://www.youtube.com/@ChrisSandersNSM) — Applied Network Security Monitoring content; NSM methodology and practical network forensics
- [Security Onion](https://www.youtube.com/@SecurityOnionSolutions) — NSM platform walkthroughs, Zeek and Suricata tutorials, and network security analyst workflow demonstrations
- [13Cubed](https://www.youtube.com/@13Cubed) — Network forensics content alongside Windows forensics; pcap analysis and network artifact investigation
- [SANS Network Security](https://www.youtube.com/@SansInstitute) — FOR572/SEC503 summit talks and network security research from SANS instructors

---

## Who to Follow

- [@chrissanders88](https://x.com/chrissanders88) — Chris Sanders; Applied Network Security Monitoring co-author; NSM methodology and network-based threat detection
- [@Security_Onion](https://x.com/Security_Onion) — Security Onion platform updates, NSM content, and community resources
- [@bro_ids](https://x.com/bro_ids) — Zeek project updates and network analysis framework development
- [@EmergingThreats](https://x.com/EmergingThreats) — Suricata and Snort rule releases; threat intelligence feeds for network detection
- [@CISAgov](https://x.com/CISAgov) — Network security advisories and critical infrastructure threat bulletins
- [@corelight_inc](https://x.com/corelight_inc) — Enterprise Zeek research, network detection content, and encrypted traffic analysis
- [@ExtraHop](https://x.com/ExtraHop) — NDR research and network threat detection methodology
- [@DarktraceCyber](https://x.com/DarktraceCyber) — AI-based network anomaly detection research and threat reports
- [@VectraAI](https://x.com/VectraAI) — Network behavior-based threat detection research and attacker behavior analysis

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Command-and-Control, Lateral Movement, and Exfiltration technique analysis with detection coverage visualization; identify which network-observable ATT&CK techniques have Sigma and Suricata coverage
- [Security Onion Documentation](https://docs.securityonion.net) — The most comprehensive free NSM platform documentation; covers deployment, configuration, and analyst workflows for a complete network monitoring stack
- [Zeek Documentation](https://docs.zeek.org) — The reference for the leading network analysis framework; protocol analyzers, log format specification, and scripting reference
- [Emerging Threats Open Ruleset](https://rules.emergingthreats.net/open/) — The most widely deployed free Suricata/Snort network detection rule library
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Free pcap library for practicing packet analysis; covers dozens of protocols and attack scenarios
- [RITA Project](https://github.com/activecm/rita) — The leading open-source beaconing detection tool; essential for C2 identification in Zeek data
- [JA3 TLS Fingerprinting](https://github.com/salesforce/ja3) — Free TLS fingerprinting method for identifying malware and anomalous TLS configurations without decryption
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net) — Free pcap files from real malware infections and C2 traffic; the best resource for practicing malicious traffic identification
---

## Network Attack Techniques

#### Reconnaissance

**Passive**
- Shodan (`shodan search net:TARGET_CIDR`), Censys, FOFA for internet-facing infrastructure

**Active scanning**
- nmap SYN scan: `nmap -sS -T4 -p- TARGET`
- Masscan: `masscan -p1-65535 TARGET --rate=10000`
- Service fingerprinting: Banner grabbing (`nc -nv IP PORT`), nmap version scan (`nmap -sV`)

#### Man-in-the-Middle Attacks

- ARP spoofing: `arpspoof -i eth0 -t VICTIM GATEWAY` + `arpspoof -i eth0 -t GATEWAY VICTIM`
- Responder (LLMNR/NBNS/mDNS poisoning): `responder -I eth0 -rdw` — captures NTLMv2 hashes
- IPv6 attacks: mitm6 (`mitm6 -d domain.local`) — Windows prefers IPv6 DNS, enables WPAD injection
- DHCP starvation: Exhaust DHCP pool then serve rogue DHCP → control default gateway

#### Protocol-Specific Attacks

- SMB relay: `ntlmrelayx.py -tf targets.txt -smb2support` — relay captured NTLM to other targets
- Kerberoasting (network perspective): Requires domain account, tickets captured from DC
- DNS poisoning: Cache poisoning (Kaminsky attack), DNS zone transfer (`dig axfr @DNS_SERVER domain.com`)
- SSL stripping: `sslstrip -l 8080` + arpspoof — downgrades HTTPS to HTTP
- VLAN hopping: Double tagging, DTP negotiation abuse

#### Wireless Attacks

- WPA2 cracking: `airmon-ng start wlan0` → `airodump-ng wlan0mon` → capture 4-way handshake → hashcat
- Evil twin AP: `hostapd-wpe` for WPA2-Enterprise credential harvesting
- PMKID attack: `hcxdumptool -o capture.pcapng` — no client needed
- Deauth flood: `aireplay-ng -0 0 -a BSSID wlan0mon`

---

## Network Monitoring and Defense

#### Network Security Monitoring (NSM) Architecture

- Visibility points: Internet perimeter, internal segment taps, out-of-band SPAN ports
- Full packet capture: Security Onion, Arkime/Moloch for PCAP + index
- Flow analysis: NetFlow/IPFIX → ELK or Splunk for anomaly detection
- Protocol analysis: Zeek/Bro — automatic parsing of 35+ protocols into structured logs

#### Intrusion Detection Systems

- Suricata: Multi-threaded, higher performance than Snort, supports AF_PACKET + DPDK
- Snort 3: Rebuilt architecture, improved rule syntax
- Zeek (IDS mode): Anomaly detection via scripting, not signature-based
- Rule sources: ET Open (Emerging Threats), CISA/US-CERT advisories, Mandiant FLARE

#### Zero Trust Networking

- Microsegmentation: Software-defined perimeter, deny-by-default east-west traffic
- ZTNA (Zero Trust Network Access): Application-level access, no implicit trust after VPN
- Tools: Zscaler Private Access, Cloudflare Access, HashiCorp Boundary, Tailscale (mesh VPN)

#### Firewall and Network Controls

- Next-gen firewall (NGFW): Application-layer inspection, user/group policies, SSL inspection
- Network ACLs: Ingress + egress filtering (egress filtering prevents C2 callback from internal hosts)
- DNS security: RPZ (Response Policy Zones), Quad9, Cloudflare Gateway, DNS-over-HTTPS
- BGP security: RPKI (Route Origin Validation), MANRS compliance

#### Key Network Security Tools

| Tool | Type | Use Case |
|---|---|---|
| Zeek (Bro) | OSS | Network traffic analysis and protocol parsing |
| Suricata | OSS | High-performance IDS/IPS |
| Security Onion | OSS | Full NSM platform (Zeek + Suricata + Elastic) |
| Arkime | OSS | Full packet capture and indexing |
| Wireshark | OSS | Protocol analysis and PCAP inspection |
| tcpdump | CLI | Live capture and PCAP analysis |
| nmap | OSS | Port scanning and service enumeration |
| Masscan | OSS | High-speed port scanning |
| Responder | OSS | LLMNR/NBT-NS/MDNS poisoning |
| mitm6 | OSS | IPv6-based MitM attacks |
| CrackMapExec | OSS | Network-level SMB/LDAP enumeration and attacks |
| Impacket | Python | SMB/Kerberos/LDAP protocol attacks |
