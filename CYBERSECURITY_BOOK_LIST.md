# 📚 Cybersecurity Master Book List
> Books paired with hands-on GitHub repos from your starred collection for practical reinforcement.

---

## ⭐ Core / Must-Read (High Signal)

* **The Web Application Hacker's Handbook** — Stuttard & Pinto
* **Penetration Testing** — Georgia Weidman
* **The Hacker Playbook 3** — Peter Kim
* **Practical Malware Analysis** — Sikorski & Honig
* **Serious Cryptography** — Jean-Philippe Aumasson
* **Security Engineering** — Ross Anderson

**Hands-on repos:**
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — The go-to reference for every technique covered across all core books
- [awesome-security](https://github.com/sbilly/awesome-security) — Curated megalist of tools, papers, and resources
- [Awesome-Hacking-Resources](https://github.com/vitalysim/Awesome-Hacking-Resources) — Broad hacking resource collection

---

## 💻 Offensive Security & Pentesting

* **Metasploit: The Penetration Tester's Guide**
* **Black Hat Python** — Justin Seitz
* **Hacking: The Art of Exploitation** — Jon Erickson
* **Attacking Network Protocols** — James Forshaw
* **Real-World Bug Hunting** — Peter Yaworski
* **Advanced Penetration Testing** — Wil Allsopp
* **Red Team Field Manual (RTFM)**
* **The Hacker Playbook 2 & 3** — Peter Kim
* **Bug Bounty Bootcamp** — Vickie Li
* **Web Hacking 101** — Peter Yaworski

**Hands-on repos:**
- [metasploit-payloads](https://github.com/rapid7/metasploit-payloads) — Official Metasploit payloads (pairs directly with Metasploit book)
- [NetExec](https://github.com/Pennyw0rth/NetExec) — Modern network pentesting Swiss army knife
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) — Classic network pentesting framework
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) — WinRM shell for pentesting
- [Responder](https://github.com/lgandx/Responder) — LLMNR/NBT-NS poisoner (essential for internal pentests)
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng) — Privilege escalation scripts (LinPEAS/WinPEAS)
- [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) — Living Off The Land Binaries and Scripts
- [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) — Unix binary exploitation for privilege escalation
- [Seatbelt](https://github.com/GhostPack/Seatbelt) — Host situational awareness / safety checks
- [SharpUp](https://github.com/GhostPack/SharpUp) — Windows privilege escalation checks
- [BloodHound](https://github.com/SpecterOps/BloodHound) — Active Directory attack path mapping
- [Snaffler](https://github.com/SnaffCon/Snaffler) — Find credentials/sensitive files in network shares
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) — SET framework
- [pentest_compilation](https://github.com/adon90/pentest_compilation) — Commands and tips from OSCP and real engagements
- [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — Internal pentest / AD cheatsheets
- [Nemesis](https://github.com/SpecterOps/Nemesis) — Offensive data enrichment pipeline
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — Comprehensive technique reference

---

## 🌐 Web Security

* **The Web Application Hacker's Handbook**
* **Bug Bounty Bootcamp** — Vickie Li
* **Web Hacking 101** — Peter Yaworski
* **Browser Hackers Handbook** — Wade Alcorn

**Hands-on repos:**
- [zaproxy](https://github.com/zaproxy/zaproxy) — OWASP ZAP web app scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) — Fast vulnerability scanner with community templates
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — Community CVE/vuln detection templates
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap) — SSRF fuzzer and exploitation tool
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) — GraphQL pentesting engine
- [Arjun](https://github.com/s0md3v/Arjun) — HTTP parameter discovery
- [OWASP WSTG](https://github.com/OWASP/wstg) — Web Security Testing Guide
- [OWASP ASVS](https://github.com/OWASP/ASVS) — Application Security Verification Standard
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — Subdomain takeover guide
- [bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) — Payloads and tips
- [Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups) — Real-world bug writeups by type
- [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) — Prototype pollution gadgets
- [HowToHunt](https://github.com/KathanP19/HowToHunt) — Web vuln methodology and test cases
- [akto](https://github.com/akto-api-security/akto) — API security testing platform
- [dirsearch](https://github.com/maurosoria/dirsearch) — Web path scanner
- [ffuf](https://github.com/ffuf/ffuf) — Fast web fuzzer
- [gobuster](https://github.com/OJ/gobuster) — Directory/DNS/VHost busting

---

## 🧠 Reverse Engineering & Malware

* **Practical Malware Analysis**
* **Practical Binary Analysis** — Dennis Andriesse
* **The Ghidra Book**
* **Malware Analyst's Cookbook**
* **Rootkits and Bootkits** — Alex Matrosov
* **Reversing: Secrets of Reverse Engineering** — Eldad Eilam

**Hands-on repos:**
- [pe-bear](https://github.com/hasherezade/pe-bear) — PE file reversing tool with GUI (by @hasherezade)
- [pe-sieve](https://github.com/hasherezade/pe-sieve) — Scan processes for injected/malicious implants
- [malware_training_vol1](https://github.com/hasherezade/malware_training_vol1) — Windows malware analysis training materials
- [capa](https://github.com/mandiant/capa) — FLARE tool to identify executable capabilities
- [flare-vm](https://github.com/mandiant/flare-vm) — Windows malware analysis VM setup scripts
- [flare-floss](https://github.com/mandiant/flare-floss) — Automatically extract obfuscated strings from malware
- [flare-fakenet-ng](https://github.com/mandiant/flare-fakenet-ng) — Dynamic network analysis tool
- [flare-ida](https://github.com/mandiant/flare-ida) — IDA Pro utilities from FLARE team
- [dnSpy](https://github.com/dnSpy/dnSpy) — .NET debugger and assembly editor
- [cutter](https://github.com/rizinorg/cutter) — Free RE platform powered by Rizin
- [radare2](https://github.com/radareorg/radare2) — UNIX-like RE framework
- [yara](https://github.com/VirusTotal/yara) — Pattern matching for malware identification
- [yarGen](https://github.com/Neo23x0/yarGen) — YARA rule generator
- [signature-base](https://github.com/Neo23x0/signature-base) — YARA/IOC database from @cyb3rops
- [volatility](https://github.com/volatilityfoundation/volatility) — Memory forensics framework
- [volatility3](https://github.com/volatilityfoundation/volatility3) — Volatility 3.0
- [CAPEv2](https://github.com/kevoreilly/CAPEv2) — Malware configuration and payload extraction sandbox
- [PMAT-labs](https://github.com/HuskyHacks/PMAT-labs) — Labs for Practical Malware Analysis & Triage course
- [learning-malware-analysis](https://github.com/jstrosch/learning-malware-analysis) — Sample programs mimicking real malware
- [Malware-analysis-and-Reverse-engineering](https://github.com/Dump-GUY/Malware-analysis-and-Reverse-engineering) — Public malware analysis writeups
- [Gepetto](https://github.com/JusticeRage/Gepetto) — IDA Pro + LLM plugin for RE
- [Manalyze](https://github.com/JusticeRage/Manalyze) — Static analyzer for PE executables
- [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) — File type and packer detector
- [pafish](https://github.com/a0rtega/pafish) — VM/sandbox detection testing tool
- [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) — Curated malware analysis resources
- [awesome-reversing](https://github.com/tylerha97/awesome-reversing) — Curated reversing resources

---

## 🔐 Cryptography

* **Serious Cryptography** — Aumasson
* **Cryptography Engineering** — Ferguson, Schneier, Kohno
* **Understanding Cryptography** — Paar & Pelzl

**Hands-on repos:**
- [sigstore](https://github.com/sigstore/sigstore) — Code signing and supply chain security (applied crypto)
- [cosign](https://github.com/sigstore/cosign) — Container/binary signing
- [getsops/sops](https://github.com/getsops/sops) — Secrets management with envelope encryption
- [hashicorp/vault](https://github.com/hashicorp/vault) — Secrets management platform
- [awesome-ethereum-security](https://github.com/crytic/awesome-ethereum-security) — Crypto/blockchain security (applied cryptography)

---

## 🛡️ Blue Team / Defense / SOC

* **Blue Team Field Manual (BTFM)**
* **Incident Response & Computer Forensics**
* **The Practice of Network Security Monitoring** — Richard Bejtlich
* **Security Operations Center** — Joseph Muniz
* **Applied Network Security Monitoring**

**Hands-on repos:**
- [sigma](https://github.com/SigmaHQ/sigma) — Generic detection rule format (essential for SOC)
- [pySigma](https://github.com/SigmaHQ/pySigma) — Python library for Sigma rule conversion
- [hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma-based Windows event log threat hunting
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) — Windows event log threat hunting (SANS)
- [detection-rules](https://github.com/elastic/detection-rules) — Elastic Security detection content
- [security_content](https://github.com/splunk/security_content) — Splunk Security detections
- [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) — Keywords and artifacts for threat hunting
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — Community threat hunting playbooks
- [signature-base](https://github.com/Neo23x0/signature-base) — YARA/IOC signatures
- [Loki](https://github.com/Neo23x0/Loki) — IOC and YARA scanner
- [rita](https://github.com/activecm/rita) — Detect C2 beaconing through network analysis
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) — Visualize malicious Windows logon activity
- [HELK](https://github.com/Cyb3rWard0g/HELK) — Hunting ELK stack
- [TheHive](https://github.com/TheHive-Project/TheHive) — Collaborative case management for IR
- [adversary_emulation_library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) — ATT&CK-based emulation plans
- [attack-navigator](https://github.com/mitre-attack/attack-navigator) — ATT&CK matrix visualization
- [caldera](https://github.com/mitre/caldera) — Automated adversary emulation platform
- [uac](https://github.com/mthcht/uac) — Live response collection for IR
- [awesome-incident-response](https://github.com/meirwah/awesome-incident-response) — IR tools and resources
- [awesome-detection-engineering](https://github.com/infosecB/awesome-detection-engineering) — Detection engineering resources
- [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection) — Threat detection resources

---

## 🕵️ OSINT / Privacy / Social Engineering

* **OSINT Techniques** — Michael Bazzell
* **Extreme Privacy** — Michael Bazzell
* **Social Engineering: The Science of Human Hacking** — Christopher Hadnagy
* **People Hacker** — Jenny Radcliffe

**Hands-on repos:**
- [awesome-osint](https://github.com/jivoi/awesome-osint) — Massive curated OSINT list
- [osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) — 300+ online OSINT tools
- [spiderfoot](https://github.com/smicallef/spiderfoot) — Automated OSINT and attack surface mapping
- [theHarvester](https://github.com/laramies/theHarvester) — Email, subdomain, and name harvesting
- [GHunt](https://github.com/mxrch/GHunt) — Google account OSINT framework
- [maigret](https://github.com/soxoj/maigret) — Username OSINT across 3000+ sites
- [holehe](https://github.com/megadose/holehe) — Check if email is registered on sites
- [phoneinfoga](https://github.com/sundowndev/phoneinfoga) — Phone number intelligence gathering
- [social-analyzer](https://github.com/qeeqbox/social-analyzer) — Profile finder across 1000+ sites
- [h8mail](https://github.com/khast3x/h8mail) — Email OSINT and breach hunting
- [gitrob](https://github.com/michenriksen/gitrob) — GitHub organization recon
- [gitscraper](https://github.com/BuildHackSecure/gitscraper) — Scrape GitHub for credentials/secrets
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) — SET (phishing, pretexting)
- [gophish](https://github.com/gophish/gophish) — Open-source phishing toolkit

---

## ☁️ Cloud Security

* **CCSP Official Study Guide**
* **AWS Certified Solutions Architect Study Guide**
* **AWS Security Handbook**
* **Cloud Security and Privacy** — Tim Mather

**Hands-on repos:**
- [pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework
- [prowler](https://github.com/prowler-cloud/prowler) — Cloud security posture assessment (AWS/Azure/GCP)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — Multi-cloud security auditing
- [cloudmapper](https://github.com/duo-labs/cloudmapper) — AWS environment analysis and visualization
- [MicroBurst](https://github.com/NetSPI/MicroBurst) — Azure security assessment scripts
- [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) — Entra ID attack and defense scenarios
- [AzureADAssessment](https://github.com/AzureAD/AzureADAssessment) — Azure AD tenant assessment
- [AADInternals](https://github.com/Gerenios/AADInternals) — Azure AD / M365 PowerShell toolkit
- [ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD offensive/defensive toolkit
- [checkov](https://github.com/bridgecrewio/checkov) — IaC security scanning
- [trivy](https://github.com/aquasecurity/trivy) — Container and cloud vulnerability scanner
- [open-cvdb](https://github.com/wiz-sec/open-cvdb) — Public cloud vulnerabilities database
- [untitledgoosetool](https://github.com/cisagov/untitledgoosetool) — CISA Azure/M365 IR tool
- [terrascan](https://github.com/tenable/terrascan) — IaC compliance and security scanning
- [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) — Microsoft Sentinel rules and templates
- [kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes benchmark checks
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) — Kubernetes security weakness hunter

---

## 🧩 Certifications & Foundations

* **CISSP Official Study Guide**
* **CISSP Official Practice Tests**
* **CEH Certified Ethical Hacker Study Guide**
* **CompTIA Network+ Guide**
* **CompTIA Security+ Guide**
* **CompTIA PenTest+ Guide**

**Hands-on repos:**
- [Free-Certifications](https://github.com/cloudcommunity/Free-Certifications) — Free courses with certs to supplement paid certs
- [Security-101](https://github.com/microsoft/Security-101) — Microsoft's 8-lesson cybersecurity curriculum
- [awesome-hacking](https://github.com/carpedm20/awesome-hacking) — Hacking tutorials and resources for foundations

---

## ⚙️ Systems / Low-Level / Exploit Dev

* **Hacking: The Art of Exploitation**
* **The Shellcoder's Handbook**
* **Linux Hardening in Hostile Networks**
* **Windows Internals (Part 1 & 2)**
* **The Art of Memory Forensics**

**Hands-on repos:**
- [pwndbg](https://github.com/pwndbg/pwndbg) — GDB/LLDB plugin for exploit dev and RE
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF framework and exploit development library
- [gef](https://github.com/hugsy/gef) — GDB Enhanced Features for exploit devs
- [peda](https://github.com/longld/peda) — Python Exploit Development Assistance for GDB
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — ROP chain gadget finder
- [angr](https://github.com/angr/angr) — Binary analysis platform
- [unicorn](https://github.com/unicorn-engine/unicorn) — CPU emulator framework
- [volatility3](https://github.com/volatilityfoundation/volatility3) — Memory forensics (pairs with Art of Memory Forensics)
- [MalConfScan](https://github.com/JPCERTCC/MalConfScan) — Volatility plugin for malware config extraction
- [Windows Internals - Detours](https://github.com/microsoft/Detours) — MS API monitoring/instrumentation
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) — Directory Services Internals PowerShell module
- [kernel-exploits](https://github.com/lucyoa/kernel-exploits) — Kernel exploit collection for practice

---

## 🎭 Hacker Culture / History / Real-World Ops

* **Ghost in the Wires** — Kevin Mitnick
* **The Art of Invisibility** — Kevin Mitnick
* **The Art of Intrusion** — Kevin Mitnick
* **The Cuckoo's Egg** — Clifford Stoll
* **Sandworm** — Andy Greenberg
* **This Is How They Tell Me the World Ends** — Nicole Perlroth
* **Permanent Record** — Edward Snowden
* **Kingpin** — Kevin Poulsen

**Hands-on repos:**
- [APTnotes](https://github.com/kbandla/APTnotes) — Public APT campaign documents (real-world ops context)
- [red_team_tool_countermeasures](https://github.com/mandiant/red_team_tool_countermeasures) — Detection rules for real-world red team tools
- [malware-indicators](https://github.com/citizenlab/malware-indicators) — Citizen Lab real-world spyware IOCs (context for Sandworm/Perlroth)

---

## 🧪 Research / Exploit Culture / Fuzzing

* **POC || GTFO**
* **POC || GTFO II**
* **The Art of Software Security Assessment**
* **Fuzzing for Software Security Testing**

**Hands-on repos:**
- [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) — AFL++ coverage-guided fuzzer
- [honggfuzz](https://github.com/google/honggfuzz) — Security-oriented fuzzer from Google
- [oss-fuzz](https://github.com/google/oss-fuzz) — Continuous fuzzing for open source
- [clusterfuzz](https://github.com/google/clusterfuzz) — Google's scalable fuzzing infrastructure
- [winafl](https://github.com/googleprojectzero/winafl) — AFL for Windows binaries (Project Zero)
- [Jackalope](https://github.com/googleprojectzero/Jackalope) — Binary coverage-guided fuzzer (Project Zero)
- [boofuzz](https://github.com/jtpereyda/boofuzz) — Network protocol fuzzer
- [codeql](https://github.com/github/codeql) — Code analysis queries used for vuln research
- [google/security-research](https://github.com/google/security-research) — Google security advisories with PoCs
- [Fuzzing-Against-the-Machine](https://github.com/PacktPublishing/Fuzzing-Against-the-Machine) — Book companion repo

---

## 📈 Networking (Critical Foundation)

* **Computer Networking: A Top-Down Approach**
* **Network+ Certification Guide**
* **TCP/IP Illustrated (Vol 1)**

**Hands-on repos:**
- [wireshark](https://github.com/wireshark/wireshark) — The standard packet analyzer
- [zeek](https://github.com/zeek/zeek) — Network analysis framework
- [suricata](https://github.com/OISF/suricata) — Network IDS/IPS/NSM engine
- [snort3](https://github.com/snort3/snort3) — Snort 3 IDS
- [bettercap](https://github.com/bettercap/bettercap) — Network MITM and recon tool
- [masscan](https://github.com/robertdavidgraham/masscan) — Ultra-fast port scanner
- [ntopng](https://github.com/ntop/ntopng) — Web-based network traffic monitoring
- [maltrail](https://github.com/stamparm/maltrail) — Malicious traffic detection system
- [rita](https://github.com/activecm/rita) — C2 beaconing detection through network analysis
- [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) — WiFi security auditing suite
- [bettercap](https://github.com/bettercap/bettercap) — 802.11, BLE, IPv4/IPv6 MITM framework

---

## 🧠 Programming for Hackers

* **Black Hat Python**
* **Violent Python**
* **Gray Hat Python**
* **Python for Offensive Security**

**Hands-on repos:**
- [red-python-scripts](https://github.com/davidbombal/red-python-scripts) — Python scripts for red teaming
- [pwntools](https://github.com/Gallopsled/pwntools) — Python exploit development library
- [PyExfil](https://github.com/ytisf/PyExfil) — Python data exfiltration techniques
- [Arjun](https://github.com/s0md3v/Arjun) — Python HTTP parameter discovery
- [impacket](https://github.com/fortra/impacket) — Python library for network protocols (AD attacks)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — Go-based scanner (learn offensive tooling in Go)
- [Black Hat Python companion - Mr-Un1k0d3r scripts](https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts) — PowerShell red team scripts

---

## 🎯 Bonus: Vulnerable Practice Environments

> Not in the original list but essential for hands-on practice with all the above books.

- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [WebGoat](https://github.com/WebGoat/WebGoat) — Deliberately insecure web app (OWASP)
- [vulhub](https://github.com/vulhub/vulhub) — Pre-built vulnerable Docker environments
- [HackTricks labs / CTFd](https://github.com/CTFd/CTFd) — CTF platform for self-hosted challenges
- [ctf-katana](https://github.com/JohnHammond/ctf-katana) — CTF challenge suggestions
- [PMAT-labs](https://github.com/HuskyHacks/PMAT-labs) — Malware analysis practice labs
- [learning-malware-analysis](https://github.com/jstrosch/learning-malware-analysis) — Safe malware-mimicking samples
- [WiFiChallengeLab](https://github.com/r4ulcl/WiFiChallengeLab-docker) — Virtualized WiFi pentesting lab

---

## 📊 Coverage Summary

| Area | Books | Key Repos |
|------|-------|-----------|
| Offensive / Pentest | 10 | Metasploit, NetExec, BloodHound, PEASS-ng, LOLBAS |
| Web Security | 4 | ZAP, Nuclei, OWASP WSTG, ffuf |
| Malware / RE | 6 | FLARE-VM, Capa, pe-bear, Volatility, YARA |
| Blue Team / SOC | 5 | Sigma, Hayabusa, RITA, TheHive, Caldera |
| OSINT | 4 | SpiderFoot, theHarvester, Maigret, GHunt |
| Cloud Security | 4 | Pacu, Prowler, ScoutSuite, Trivy |
| Exploit Dev | 5 | pwntools, pwndbg, ROPgadget, angr, AFL++ |
| Fuzzing / Research | 4 | AFL++, OSS-Fuzz, CodeQL, Winafl |
| Networking | 3 | Wireshark, Zeek, Suricata |
| Programming | 4 | pwntools, Impacket, red-python-scripts |
