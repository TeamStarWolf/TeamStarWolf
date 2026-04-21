# Open Source Security Toolkit

> A curated bookmarks reference for security professionals — free and open source tools organized by discipline.
> Companion to [TOOLS.md](TOOLS.md) (enterprise/commercial coverage) and [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md).
> All tools listed here are free to use unless noted as **[free tier]** or **[commercial, listed for reference]**.

---

## Reconnaissance & OSINT

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| theHarvester | [github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) | Harvest emails, subdomains, hosts, and names from public sources |
| Subfinder | [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | Fast passive subdomain enumeration via OSINT APIs |
| Amass | [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) | In-depth DNS enumeration, network mapping, and OSINT |
| Shodan CLI | [cli.shodan.io](https://cli.shodan.io/) | Query Shodan's internet-wide scan database from the terminal |
| Nuclei | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Template-driven vulnerability and recon scanning at scale |
| httpx | [github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | Fast HTTP probing, tech fingerprinting, and status checks |
| waybackurls | [github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | Fetch all URLs the Wayback Machine knows about for a domain |
| gau | [github.com/lc/gau](https://github.com/lc/gau) | Enumerate known URLs from AlienVault OTX, Wayback, and Common Crawl |
| katana | [github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana) | Next-generation web crawler with JavaScript rendering support |
| dnsx | [github.com/projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) | Multi-purpose DNS toolkit for bulk resolution and brute-forcing |
| SpiderFoot | [github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | Automated OSINT collection with 200+ data source modules |
| Recon-ng | [github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) | Full-featured modular OSINT framework with web interface |

---

## Web Application Security

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Burp Suite Community | [portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload) | Intercept proxy and manual web app testing platform (free tier) |
| OWASP ZAP | [github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Full-featured automated and manual web app vulnerability scanner |
| sqlmap | [github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) | Automated detection and exploitation of SQL injection flaws |
| ffuf | [github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer for directories, files, parameters, and headers |
| gobuster | [github.com/OJ/gobuster](https://github.com/OJ/gobuster) | Directory, DNS, and vhost brute-forcing tool |
| Nikto | [github.com/sullo/nikto](https://github.com/sullo/nikto) | Web server misconfiguration and known-vulnerability scanner |
| dalfox | [github.com/hahwul/dalfox](https://github.com/hahwul/dalfox) | Fast parameter analysis and XSS scanning tool |
| wfuzz | [github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz) | Web application fuzzer for finding hidden resources and injection points |
| feroxbuster | [github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster) | Recursive content discovery using wordlists, written in Rust |
| Caido | [caido.io](https://caido.io/) | Modern web proxy and security auditing toolkit (free tier available) |
| Arjun | [github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun) | HTTP parameter discovery suite |
| WPScan | [github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | WordPress vulnerability scanner |

---

## Network Scanning & Analysis

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| nmap | [nmap.org](https://nmap.org/) | The gold-standard network discovery and security auditing scanner |
| masscan | [github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) | Internet-scale TCP port scanner, up to 10M packets/sec |
| naabu | [github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) | Fast and reliable port scanner with nmap integration |
| Wireshark | [wireshark.org](https://www.wireshark.org/) | World's most widely used network protocol analyzer with GUI |
| tcpdump | [tcpdump.org](https://www.tcpdump.org/) | Command-line packet capture and filtering tool |
| Zeek | [zeek.org](https://zeek.org/) | Network analysis framework and traffic metadata generator |
| netcat (ncat) | [nmap.org/ncat](https://nmap.org/ncat/) | Networking Swiss army knife for reading/writing TCP/UDP connections |
| Zmap | [github.com/zmap/zmap](https://github.com/zmap/zmap) | Single-packet internet-wide network scanner |
| netdiscover | [github.com/netdiscover-scanner/netdiscover](https://github.com/netdiscover-scanner/netdiscover) | Active/passive ARP network address scanner |
| hping3 | [github.com/antirez/hping](https://github.com/antirez/hping) | TCP/IP packet assembler and analyzer for network testing |

---

## Password & Credentials

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| hashcat | [hashcat.net](https://hashcat.net/) | World's fastest GPU-based password recovery and hash cracking tool |
| John the Ripper | [github.com/openwall/john](https://github.com/openwall/john) | Versatile password cracker supporting hundreds of hash types |
| Hydra | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) | Parallelized login cracker supporting 50+ protocols |
| CrackMapExec | [github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Swiss army knife for Windows/AD network pentesting |
| Responder | [github.com/lgandx/Responder](https://github.com/lgandx/Responder) | LLMNR, NBT-NS, and MDNS poisoner for credential capture |
| Impacket | [github.com/fortra/impacket](https://github.com/fortra/impacket) | Python library and toolset for Windows network protocol interactions |
| sprayhound | [github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound) | Password spraying tool with BloodHound integration |
| Default Credentials Cheat Sheet | [github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet) | Lookup table of default credentials for common devices and services |

---

## Exploitation Frameworks

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Metasploit Framework | [github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) | The most widely used penetration testing and exploit development framework |
| Sliver | [github.com/BishopFox/sliver](https://github.com/BishopFox/sliver) | Open source cross-platform adversary simulation C2 framework |
| Havoc C2 | [github.com/HavocFramework/Havoc](https://github.com/HavocFramework/Havoc) | Modern and malleable post-exploitation C2 framework |
| Covenant | [github.com/cobbr/Covenant](https://github.com/cobbr/Covenant) | Collaborative .NET C2 framework for red team operations |
| Cobalt Strike | [cobaltstrike.com](https://www.cobaltstrike.com/) | Industry-standard adversary simulation platform **[commercial, listed for reference]** |
| SILENTTRINITY | [github.com/byt3bl33d3r/SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) | IronPython-based post-exploitation agent and C2 |
| PoshC2 | [github.com/nettitude/PoshC2](https://github.com/nettitude/PoshC2) | Proxy-aware C2 framework with Python3 implants and PowerShell |

---

## Post-Exploitation

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| BloodHound | [github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound) | Graph-based Active Directory attack path analysis |
| SharpHound | [github.com/BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound) | C# data collector (ingestor) for BloodHound |
| Mimikatz | [github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) | Windows credential extraction — LSASS, Kerberos, hashes |
| Rubeus | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) | C# Kerberos abuse toolkit for Windows environments |
| evil-winrm | [github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm) | WinRM shell for pentesting with upload/download and script loading |
| PowerSploit | [github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) | PowerShell post-exploitation framework (legacy, widely referenced) |
| PEASS-ng | [github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng) | Privilege escalation scripts for Windows, Linux, and macOS |
| Seatbelt | [github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt) | Windows host security checks and situational awareness tool |
| LaZagne | [github.com/AlessandroZ/LaZagne](https://github.com/AlessandroZ/LaZagne) | Retrieve locally stored credentials from dozens of applications |
| SharpUp | [github.com/GhostPack/SharpUp](https://github.com/GhostPack/SharpUp) | C# port of PowerUp for local privilege escalation checks |

---

## Active Directory

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| BloodHound / AzureHound | [github.com/BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) | Graph-based AD and Azure attack path discovery |
| Impacket suite | [github.com/fortra/impacket](https://github.com/fortra/impacket) | Python tools for SMB, Kerberos, DCSync, secretsdump, and more |
| CrackMapExec | [github.com/byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Network-wide AD enumeration and lateral movement toolset |
| Kerbrute | [github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute) | Brute-force and enumerate valid AD accounts via Kerberos |
| Rubeus | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) | Kerberoasting, AS-REP roasting, pass-the-ticket, ticket forgery |
| ldapdomaindump | [github.com/dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) | Dump AD information via LDAP to readable HTML and JSON |
| ADRecon | [github.com/sense-of-security/ADRecon](https://github.com/sense-of-security/ADRecon) | Comprehensive AD information gathering and report generation |
| NetExec | [github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) | CrackMapExec successor, actively maintained AD pentesting suite |

---

## Cloud Security

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Pacu | [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS exploitation framework for offensive security testing |
| ScoutSuite | [github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud security auditing and misconfiguration assessment |
| Prowler | [github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | AWS, Azure, and GCP security best practices and compliance checks |
| AzureHound | [github.com/BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) | Azure AD and resource attack path data collection for BloodHound |
| ROADtools | [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) | Azure AD enumeration, token manipulation, and graph exploration |
| Trivy | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) | All-in-one scanner for containers, IaC, OS packages, and secrets |
| checkov | [github.com/bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Static analysis of IaC (Terraform, CloudFormation, K8s, etc.) |
| CloudFox | [github.com/BishopFox/cloudfox](https://github.com/BishopFox/cloudfox) | Enumerate cloud environment attack surface and privilege paths |
| aws-nuke | [github.com/rebuy-de/aws-nuke](https://github.com/rebuy-de/aws-nuke) | Remove all resources from an AWS account (use in lab environments) |
| CartographyHound | [github.com/lyft/cartography](https://github.com/lyft/cartography) | Graph-based multi-cloud infrastructure relationship mapping |

---

## Container Security

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Trivy | [github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Scan container images, filesystems, and IaC for vulnerabilities and secrets |
| kube-bench | [github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) | Run CIS Kubernetes Benchmark checks against cluster nodes |
| kube-hunter | [github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) | Hunt for security weaknesses in Kubernetes clusters |
| Falco | [github.com/falcosecurity/falco](https://github.com/falcosecurity/falco) | Cloud-native runtime security and anomaly detection using eBPF |
| OPA Gatekeeper | [github.com/open-policy-agent/gatekeeper](https://github.com/open-policy-agent/gatekeeper) | Policy enforcement for Kubernetes using Open Policy Agent |
| cosign | [github.com/sigstore/cosign](https://github.com/sigstore/cosign) | Container image signing, verification, and supply-chain security |
| Grype | [github.com/anchore/grype](https://github.com/anchore/grype) | Vulnerability scanner for container images and filesystems |
| Syft | [github.com/anchore/syft](https://github.com/anchore/syft) | Generate SBOMs from container images and filesystems |
| CDK | [github.com/cdk-team/CDK](https://github.com/cdk-team/CDK) | Container and Kubernetes environment escape and exploitation tool |
| Dockle | [github.com/goodwithtech/dockle](https://github.com/goodwithtech/dockle) | Container image linter and security best-practice checker |

---

## Detection & Blue Team

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Sigma | [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Generic SIEM detection rule format, convertible to any platform |
| YARA | [github.com/VirusTotal/yara](https://github.com/VirusTotal/yara) | Pattern-matching language for malware identification and classification |
| Velociraptor | [github.com/Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) | DFIR and threat hunting platform with live response capabilities |
| Zeek | [github.com/zeek/zeek](https://github.com/zeek/zeek) | Network traffic analysis framework generating rich metadata logs |
| Suricata | [github.com/OISF/suricata](https://github.com/OISF/suricata) | High-performance network IDS, IPS, and NSM engine |
| Elastic SIEM | [github.com/elastic/detection-rules](https://github.com/elastic/detection-rules) | Elastic Security detection rules repository (community + official) |
| OpenBAS | [github.com/OpenBAS-Platform/openbas](https://github.com/OpenBAS-Platform/openbas) | Open breach and attack simulation platform |
| Atomic Red Team | [github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) | ATT&CK-mapped small and portable detection test library |
| Wazuh | [github.com/wazuh/wazuh](https://github.com/wazuh/wazuh) | Open source XDR and SIEM with FIM, compliance, and threat hunting |
| Caldera | [github.com/mitre/caldera](https://github.com/mitre/caldera) | MITRE's automated adversary emulation and red-team automation platform |

---

## Malware Analysis

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Cuckoo Sandbox | [github.com/cuckoosandbox/cuckoo](https://github.com/cuckoosandbox/cuckoo) | Automated malware analysis sandbox (legacy; see CAPE fork) |
| CAPE Sandbox | [github.com/kevoreilly/CAPEv2](https://github.com/kevoreilly/CAPEv2) | Active malware analysis with config extraction and unpacking |
| Ghidra | [github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's powerful open source software reverse engineering suite |
| radare2 | [github.com/radareorg/radare2](https://github.com/radareorg/radare2) | Portable reverse engineering framework and hex editor |
| FLOSS | [github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss) | Automatically extract obfuscated strings from malware binaries |
| Detect-It-Easy | [github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | File type and compiler/packer detection tool (DIE) |
| PEStudio | [winitor.com](https://www.winitor.com/) | Static analysis of Windows PE files for suspicious indicators |
| YARA | [github.com/VirusTotal/yara](https://github.com/VirusTotal/yara) | Pattern matching to classify and identify malware families |
| VirusTotal CLI | [github.com/VirusTotal/vt-cli](https://github.com/VirusTotal/vt-cli) | Command-line interface to VirusTotal's analysis API |
| DRAKVUF | [github.com/tklengyel/drakvuf](https://github.com/tklengyel/drakvuf) | Agentless dynamic malware analysis system using VM introspection |

---

## Reverse Engineering

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Ghidra | [github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA open source SRE suite — disassembler, decompiler, scripting |
| radare2 | [github.com/radareorg/radare2](https://github.com/radareorg/radare2) | Portable multi-arch disassembly and binary analysis framework |
| Cutter | [github.com/rizinorg/cutter](https://github.com/rizinorg/cutter) | GUI frontend for Rizin/radare2 with decompiler integration |
| x64dbg | [github.com/x64dbg/x64dbg](https://github.com/x64dbg/x64dbg) | Open source x64/x32 Windows debugger for malware and vulnerability research |
| Binary Ninja | [binary.ninja](https://binary.ninja/) | Interactive binary analysis platform with Python API **[commercial, free personal tier]** |
| IDA Free | [hex-rays.com/ida-free](https://hex-rays.com/ida-free/) | Freeware version of the IDA Pro disassembler **[commercial, listed for reference]** |
| pwndbg | [github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | GDB plugin that makes exploit development and RE much easier |
| GEF | [github.com/hugsy/gef](https://github.com/hugsy/gef) | GDB Enhanced Features — multi-arch exploit development plugin |
| rizin | [github.com/rizinorg/rizin](https://github.com/rizinorg/rizin) | UNIX-like RE framework and command-line toolset (radare2 fork) |
| angr | [github.com/angr/angr](https://github.com/angr/angr) | Python binary analysis framework supporting symbolic execution |

---

## Forensics

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Autopsy | [github.com/sleuthkit/autopsy](https://github.com/sleuthkit/autopsy) | GUI-based digital forensics platform built on The Sleuth Kit |
| Volatility 3 | [github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework for analyzing RAM dump artifacts |
| plaso / log2timeline | [github.com/log2timeline/plaso](https://github.com/log2timeline/plaso) | Super-timeline creation from hundreds of artifact types |
| KAPE | [ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md) | Rapid triage collection and processing of forensic artifacts (free) |
| Chainsaw | [github.com/WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast Windows Event Log hunting and forensic analysis |
| Eric Zimmerman Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) | Suite of Windows forensic tools (Registry, prefetch, shellbags, etc.) |
| TheHive | [github.com/TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) | Scalable SOAR and IR case management platform |
| Timesketch | [github.com/google/timesketch](https://github.com/google/timesketch) | Collaborative timeline analysis and forensic investigation tool |
| Velociraptor | [github.com/Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) | Live endpoint forensics collection with VQL query language |

---

## Threat Intelligence

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| MISP | [github.com/MISP/MISP](https://github.com/MISP/MISP) | Open source threat intelligence and sharing platform |
| OpenCTI | [github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) | Structured cyber threat intelligence management and visualization |
| TheHive | [github.com/TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) | IR case management with MISP and Cortex integration |
| Cortex | [github.com/TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) | Observable analysis and active response engine (TheHive companion) |
| TAXII/STIX tools | [github.com/oasis-open/cti-taxii-client](https://github.com/oasis-open/cti-taxii-client) | OASIS reference implementations for STIX/TAXII threat sharing |
| IntelOwl | [github.com/intelowlproject/IntelOwl](https://github.com/intelowlproject/IntelOwl) | Aggregate threat intel from dozens of analyzers in a single API |
| Yeti | [github.com/yeti-platform/yeti](https://github.com/yeti-platform/yeti) | Centralized repository for observables, TTPs, and campaign tracking |

---

## Wireless & RF

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Aircrack-ng | [github.com/aircrack-ng/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) | 802.11 WEP and WPA/WPA2-PSK cracking toolkit |
| Kismet | [github.com/kismetwireless/kismet](https://github.com/kismetwireless/kismet) | Wireless network detector, sniffer, WIDS, and wardriving tool |
| Wifite | [github.com/kimocoder/wifite2](https://github.com/kimocoder/wifite2) | Automated wireless auditing tool targeting multiple WEP/WPA attack vectors |
| HackRF toolchain | [github.com/greatscottgadgets/hackrf](https://github.com/greatscottgadgets/hackrf) | Software-defined radio toolchain for the HackRF One device |
| GNU Radio | [github.com/gnuradio/gnuradio](https://github.com/gnuradio/gnuradio) | Flow-graph-based SDR toolkit for signal processing and protocol RE |
| Proxmark firmware | [github.com/Proxmark/proxmark3](https://github.com/Proxmark/proxmark3) | RFID/NFC research and emulation firmware for Proxmark hardware |
| GQRX | [github.com/gqrx-sdr/gqrx](https://github.com/gqrx-sdr/gqrx) | SDR receiver and spectrum analyzer with Qt GUI |
| gr-gsm | [github.com/ptrkrysik/gr-gsm](https://github.com/ptrkrysik/gr-gsm) | GNU Radio blocks for receiving and decoding GSM transmissions |

---

## Hardware & Embedded

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Binwalk | [github.com/ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware extraction, analysis, and embedded file-system identification |
| Firmwalker | [github.com/craigz28/firmwalker](https://github.com/craigz28/firmwalker) | Script to search extracted firmware for sensitive files and strings |
| OpenOCD | [openocd.org](https://openocd.org/) | Open On-Chip Debugger supporting JTAG/SWD for embedded targets |
| Flashrom | [github.com/flashrom/flashrom](https://github.com/flashrom/flashrom) | Identify, read, write, verify, and erase flash chips |
| Bus Pirate firmware | [github.com/BusPirate/Bus_Pirate](https://github.com/BusPirate/Bus_Pirate) | Firmware for the Bus Pirate hardware hacking multi-tool |
| Ghidra | [github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | Reverse engineer firmware with processor support for dozens of architectures |
| QEMU | [github.com/qemu/qemu](https://github.com/qemu/qemu) | Emulate embedded systems for dynamic firmware analysis |
| EMBA | [github.com/e-m-b-a/emba](https://github.com/e-m-b-a/emba) | Automated firmware security analysis for embedded Linux systems |

---

## Vulnerability Scanning

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| OpenVAS / Greenbone | [github.com/greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | Full-featured open source network vulnerability assessment scanner |
| Nuclei | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Template-based scanning with a community library of 10,000+ checks |
| Nessus Essentials | [tenable.com/products/nessus/nessus-essentials](https://www.tenable.com/products/nessus/nessus-essentials) | Free up to 16 IPs; professional Nessus engine **[free tier]** |
| osv-scanner | [github.com/google/osv-scanner](https://github.com/google/osv-scanner) | Scan dependencies against Google's Open Source Vulnerability database |
| Grype | [github.com/anchore/grype](https://github.com/anchore/grype) | Vulnerability scanner for container images, filesystems, and SBOMs |
| vulners-scanner | [github.com/vulnersCom/nmap-vulners](https://github.com/vulnersCom/nmap-vulners) | nmap NSE script for CVE-based service vulnerability lookup |
| WPScan | [github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | WordPress plugin, theme, and core vulnerability scanner |

---

## Secret Detection

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| gitleaks | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Scan git repos for hardcoded secrets, API keys, and credentials |
| truffleHog | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | Deep secret scanning across git history, S3, Jira, Slack, and more |
| Semgrep | [github.com/returntocorp/semgrep](https://github.com/returntocorp/semgrep) | Static analysis for secrets, bugs, and security anti-patterns |
| detect-secrets | [github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | Yelp's entropy-based secret detection tool with baseline management |
| whispers | [github.com/Skyscanner/whispers](https://github.com/Skyscanner/whispers) | Identify hardcoded secrets and dangerous behaviors in source code |
| git-secrets | [github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets) | AWS Labs tool to prevent committing secrets and credentials to git |

---

## Privacy & Anonymity

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| Tor Browser | [torproject.org](https://www.torproject.org/) | Browser bundle routing traffic through the Tor anonymity network |
| Tails OS | [tails.boum.org](https://tails.boum.org/) | Amnesic live OS routing all traffic through Tor with no local persistence |
| Whonix | [whonix.org](https://www.whonix.org/) | VM-based Tor workstation and gateway for strong anonymity |
| ProxyChains-ng | [github.com/rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng) | Force any TCP connection through SOCKS4/5 or HTTP proxies |
| OnionShare | [github.com/onionshare/onionshare](https://github.com/onionshare/onionshare) | Securely share files, host sites, and chat over Tor onion services |
| I2P | [geti2p.net](https://geti2p.net/) | Anonymous overlay network for internal peer-to-peer communication |
| Dangerzone | [github.com/freedomofpress/dangerzone](https://github.com/freedomofpress/dangerzone) | Convert potentially malicious documents to safe PDFs in isolation |

---

## CTF & Labs

| Tool | Repo / Link | Purpose |
|------|-------------|---------|
| pwntools | [github.com/Gallopsled/pwntools](https://github.com/Gallopsled/pwntools) | CTF framework and exploit development library for Python |
| angr | [github.com/angr/angr](https://github.com/angr/angr) | Binary analysis platform with symbolic execution for solving CTF challenges |
| ROPgadget | [github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | Search for ROP gadgets in binaries to build exploit chains |
| pwndbg | [github.com/pwndbg/pwndbg](https://github.com/pwndbg/pwndbg) | GDB plugin for exploit development with heap visualization and PEDA-style layout |
| GEF | [github.com/hugsy/gef](https://github.com/hugsy/gef) | GDB Enhanced Features plugin for multi-architecture exploit development |
| checksec | [github.com/slimm609/checksec.sh](https://github.com/slimm609/checksec.sh) | Check security properties (NX, RELRO, PIE, canary) of ELF binaries |
| CyberChef | [github.com/gchq/CyberChef](https://github.com/gchq/CyberChef) | GCHQ's "Cyber Swiss Army Knife" for encoding, decoding, and data transformation |
| one_gadget | [github.com/david942j/one_gadget](https://github.com/david942j/one_gadget) | Find one-gadget RCE addresses in libc for heap/stack exploits |
| seccomp-tools | [github.com/david942j/seccomp-tools](https://github.com/david942j/seccomp-tools) | Analyze and disassemble seccomp BPF programs in CTF/RE challenges |
| DogBolt / Decompiler Explorer | [dogbolt.org](https://dogbolt.org/) | Compare outputs of multiple decompilers (Hex-Rays, Ghidra, BN, etc.) side by side |

---

## Online Resources & Bookmarks

### Vulnerability Databases

| Resource | Link | Notes |
|----------|------|-------|
| NVD (National Vulnerability Database) | [nvd.nist.gov](https://nvd.nist.gov/) | NIST's authoritative CVE enrichment database with CVSS scores |
| MITRE CVE | [cve.mitre.org](https://cve.mitre.org/) | Canonical CVE identifiers and descriptions |
| VulDB | [vuldb.com](https://vuldb.com/) | Community vulnerability database with timeline and threat data |
| Exploit-DB | [exploit-db.com](https://www.exploit-db.com/) | Offensive Security's archive of public exploits and vulnerable software |
| Packet Storm | [packetstormsecurity.com](https://packetstormsecurity.com/) | Security advisories, exploits, tools, and papers archive |
| OSV | [osv.dev](https://osv.dev/) | Google's open source vulnerability database with ecosystem coverage |
| vulners.com | [vulners.com](https://vulners.com/) | Aggregated vulnerability intelligence, searchable across sources |

### Standards & Frameworks

| Resource | Link | Notes |
|----------|------|-------|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org/) | Adversary tactics, techniques, and procedures (TTPs) knowledge base |
| OWASP | [owasp.org](https://owasp.org/) | Web application security guidelines, Top 10, testing guide |
| NIST CSF | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) | Cybersecurity Framework for risk management |
| CIS Benchmarks | [cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks) | Free hardening guidance for OS, cloud, network, and software |
| MITRE D3FEND | [d3fend.mitre.org](https://d3fend.mitre.org/) | Defensive countermeasure knowledge graph (complement to ATT&CK) |
| MITRE ATLAS | [atlas.mitre.org](https://atlas.mitre.org/) | Adversarial threat landscape for AI systems |
| OWASP WSTG | [owasp.org/www-project-web-security-testing-guide](https://owasp.org/www-project-web-security-testing-guide/) | Comprehensive web security testing methodology |

### Practice Platforms

| Platform | Link | Notes |
|----------|------|-------|
| HackTheBox | [hackthebox.com](https://www.hackthebox.com/) | Online penetration testing labs and CTF-style machines |
| TryHackMe | [tryhackme.com](https://tryhackme.com/) | Guided learning paths and hands-on security rooms for all levels |
| PentesterLab | [pentesterlab.com](https://pentesterlab.com/) | Web application security exercises with free and pro tracks |
| VulnHub | [vulnhub.com](https://www.vulnhub.com/) | Free downloadable vulnerable VMs for offline practice |
| PicoCTF | [picoctf.org](https://picoctf.org/) | Carnegie Mellon's beginner-friendly CTF competition platform |
| pwn.college | [pwn.college](https://pwn.college/) | ASU's free in-browser binary exploitation and systems security dojo |
| PortSwigger Web Academy | [portswigger.net/web-security](https://portswigger.net/web-security) | Free, hands-on labs for every OWASP/web vulnerability category |
| SANS Cyber Aces | [cyberaces.org](https://www.cyberaces.org/) | Free foundational cybersecurity courses from SANS |

### CTF & Cheat Sheet Resources

| Resource | Link | Notes |
|----------|------|-------|
| CTFtime | [ctftime.org](https://ctftime.org/) | CTF event calendar, team rankings, and writeup archive |
| HackTricks | [book.hacktricks.xyz](https://book.hacktricks.xyz/) | Comprehensive pentest and CTF technique reference by Carlos Polop |
| PayloadsAllTheThings | [github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Curated list of payloads and bypasses for web application testing |
| GTFOBins | [gtfobins.github.io](https://gtfobins.github.io/) | Unix binary abuse for privilege escalation and sandbox escapes |
| LOLBAS | [lolbas-project.github.io](https://lolbas-project.github.io/) | Living Off the Land Binaries for Windows abuse techniques |
| RevShells | [revshells.com](https://www.revshells.com/) | Interactive reverse shell payload generator for common languages |
| CrackStation | [crackstation.net](https://crackstation.net/) | Free online hash lookup and password cracking service |
| CyberChef (online) | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) | Browser-based data encoding, decoding, and transformation tool |

---

> **Note:** Always obtain proper written authorization before conducting any security testing.
> Use these tools only on systems you own or have explicit permission to test.
> Many tools listed here are dual-use — understanding offensive techniques is essential for building effective defenses.

*Last updated: April 2026 — contributions welcome via PR.*

---

## Windows Hardening and Assessment

| Tool | Use Case | Notes |
|---|---|---|
| [Hardentools](https://github.com/securitywithoutborders/hardentools) | Disable risky Windows features | One-click disable macros, autorun, PowerShell, etc. |
| [HardeningKitty](https://github.com/0x6d69636b/windows_hardening) | CIS Benchmark assessment + scoring | PowerShell; exports CSV results |
| [Microsoft LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) | Local admin password management | Now built into Windows 11/Server 2022 |
| [PingCastle](https://www.pingcastle.com/) | AD security assessment | Fast; generates risk score; maps attack paths |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | AD attack path mapping | Community edition; JavaScript rewrite of original |
| [Plextrac / Ghostwriter](https://github.com/GhostManager/Ghostwriter) | Pentest reporting | OSS reporting platforms |
| [SysinternalsSuite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) | Windows investigation toolkit | ProcMon, ProcessExplorer, Autoruns, TCPView, etc. |
| [LGPO.exe](https://www.microsoft.com/en-us/download/details.aspx?id=55319) | Import/export local GPO | Microsoft tool for deploying GPO baselines |
| [PolicyAnalyzer](https://www.microsoft.com/en-us/download/details.aspx?id=55319) | Compare GPOs and baselines | Microsoft Security Compliance Toolkit |

---

## Deception and Honeypots

| Tool | Use Case |
|---|---|
| [OpenCanary](https://github.com/thinkst/opencanary) | Multi-protocol honeypot daemon (SSH, HTTP, SMB, MySQL, Telnet) |
| [Cowrie](https://github.com/cowrie/cowrie) | SSH/Telnet honeypot with full session recording |
| [Canarytokens.org](https://canarytokens.org/) | Free web-based honey tokens (URL, file, AWS key, email, DNS) |
| [Dionaea](https://github.com/DinoTools/dionaea) | Malware capture honeypot; SMB, HTTP, FTP exploits |
| [Conpot](https://github.com/mushorg/conpot) | ICS/SCADA protocol honeypot (Modbus, IEC 104, S7) |
| [HoneyDB](https://honeydb.io/) | Honeypot data aggregation and threat intelligence feeds |
| [Wordpot](https://github.com/gbrindisi/wordpot) | WordPress honeypot; detect WordPress scanners |

---

## Vulnerability Management and Attack Surface Management

| Tool | Use Case |
|---|---|
| [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) | Full-featured vulnerability scanner (free Greenbone Community Edition) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Fast, template-based vulnerability/misconfiguration scanner (ProjectDiscovery) |
| [Nessus Essentials](https://www.tenable.com/products/nessus/nessus-essentials) | Free tier of Nessus; up to 16 IPs; best UX in free scanners |
| [OWASP ZAP](https://www.zaproxy.org/) | DAST for web applications; good CI/CD integration |
| [Amass](https://github.com/owasp-amass/amass) | Attack surface enumeration; subdomain discovery; graph output |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Fast passive subdomain enumeration |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP toolkit; probe alive hosts; get titles/status codes |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS enumeration and resolution toolkit |
| [Shodan CLI](https://cli.shodan.io/) | Internet-exposed asset discovery and monitoring |
| [Censys CLI](https://github.com/censys/censys-python) | Certificate and asset intelligence |
