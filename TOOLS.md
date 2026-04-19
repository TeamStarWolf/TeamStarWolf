# Security Tools Reference

A quick-reference matrix of commonly used security tools organized by function. Each entry links to the project homepage. OSS = open source; COM = commercial.

For deeper context on how tools map to NIST 800-53 controls and ATT&CK techniques, see the [Controls Mapping](CONTROLS_MAPPING.md) and [ATT&CK Navigator layers](navigator/).

---

## Endpoint & Detection

### EDR / XDR
| Tool | Type | Primary Use | Platform |
|---|---|---|---|
| [CrowdStrike Falcon](https://www.crowdstrike.com/) | COM | EDR, XDR, threat hunting | Win/Mac/Linux |
| [SentinelOne Singularity](https://www.sentinelone.com/) | COM | EDR, AI behavioral detection, DFIR | Win/Mac/Linux |
| [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint) | COM | EDR, ASR, vulnerability management | Win/Mac/Linux/iOS/Android |
| [Wazuh](https://wazuh.com/) | OSS | SIEM, EDR, FIM, compliance | Cross-platform |
| [Velociraptor](https://www.velocidex.com/) | OSS | DFIR, live response, threat hunting | Win/Mac/Linux |
| [OSQuery](https://www.osquery.io/) | OSS | Host telemetry, SQL-based queries | Cross-platform |

### Vulnerability Scanning
| Tool | Type | Primary Use |
|---|---|---|
| [Tenable Nessus / Tenable.io](https://www.tenable.com/) | COM | Network and host vulnerability scanning |
| [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) | COM | Cloud-based VM, patch orchestration |
| [OpenVAS / Greenbone](https://www.greenbone.net/en/community-edition/) | OSS | Network vulnerability scanning |
| [Trivy](https://github.com/aquasecurity/trivy) | OSS | Container, IaC, OS, language package scanning |
| [Grype](https://github.com/anchore/grype) | OSS | Container and filesystem vulnerability scanning |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | OSS | Template-based web and network scanning |

---

## SIEM, Logging & Detection

### SIEM Platforms
| Tool | Type | Primary Use |
|---|---|---|
| [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html) | COM | Enterprise SIEM, correlation search, dashboards |
| [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/) | COM | Cloud-native SIEM/SOAR, Azure-native |
| [Elastic Security](https://www.elastic.co/security) | OSS/COM | SIEM, detection rules, threat hunting |
| [Wazuh](https://wazuh.com/) | OSS | SIEM, host IDS, compliance, FIM |
| [OpenSearch Security Analytics](https://opensearch.org/) | OSS | Log analytics and detection rules |
| [Graylog](https://www.graylog.org/) | OSS/COM | Log management and alerting |

### Detection Engineering
| Tool | Type | Primary Use |
|---|---|---|
| [Sigma](https://sigmahq.io/) | OSS | Generic SIEM detection rule format |
| [YARA](https://virustotal.github.io/yara/) | OSS | Malware pattern matching rules |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | OSS | ATT&CK-mapped detection validation tests |
| [Caldera](https://caldera.mitre.org/) | OSS | Automated adversary emulation, BAS |
| [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | OSS | Coverage visualization and layer management |
| [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) | OSS | Advanced ATT&CK workbench with CVE and intel integrations |

### SOAR
| Tool | Type | Primary Use |
|---|---|---|
| [Splunk SOAR (Phantom)](https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html) | COM | Enterprise SOAR, playbook automation |
| [Palo Alto XSOAR (Cortex)](https://www.paloaltonetworks.com/cortex/cortex-xsoar) | COM | SOAR, case management, threat intelligence |
| [TheHive](https://thehive-project.org/) | OSS | Case management and IR coordination |
| [Shuffle](https://shuffler.io/) | OSS | Workflow automation, SOAR-lite |

---

## Threat Intelligence

| Tool | Type | Primary Use |
|---|---|---|
| [MISP](https://www.misp-project.org/) | OSS | Threat sharing platform, IOC management |
| [OpenCTI](https://www.opencti.io/) | OSS | Structured threat intel, STIX 2.1 |
| [Maltego](https://www.maltego.com/) | OSS/COM | OSINT and relationship graphing |
| [SpiderFoot](https://www.spiderfoot.net/) | OSS | Automated OSINT reconnaissance |
| [AlienVault OTX](https://otx.alienvault.com/) | Free | Community threat intelligence feeds |
| [Shodan](https://www.shodan.io/) | COM | Internet-exposed device and service search |
| [URLhaus](https://urlhaus.abuse.ch/) | Free | Malicious URL database |
| [AbuseIPDB](https://www.abuseipdb.com/) | Free | IP reputation and abuse reporting |

---

## Offensive Security & Red Teaming

### Frameworks & C2
| Tool | Type | Primary Use |
|---|---|---|
| [Metasploit Framework](https://www.metasploit.com/) | OSS | Exploitation framework, C2, post-exploitation |
| [Cobalt Strike](https://www.cobaltstrike.com/) | COM | Adversary simulation, C2, team server |
| [Sliver](https://github.com/BishopFox/sliver) | OSS | Modern C2 framework, mTLS/HTTP2/DNS |
| [Havoc](https://github.com/HavocFramework/Havoc) | OSS | C2 framework with evasion features |
| [Empire](https://github.com/BC-SECURITY/Empire) | OSS | PowerShell/Python C2 post-exploitation |
| [Covenant](https://github.com/cobbr/Covenant) | OSS | .NET C2 framework with collaborative features |

### Web Application Testing
| Tool | Type | Primary Use |
|---|---|---|
| [Burp Suite Pro](https://portswigger.net/burp/pro) | COM | Web app and API security testing |
| [OWASP ZAP](https://www.zaproxy.org/) | OSS | Web application scanner and proxy |
| [ffuf](https://github.com/ffuf/ffuf) | OSS | Fast web fuzzer (dirs, params, headers) |
| [feroxbuster](https://github.com/epi052/feroxbuster) | OSS | Fast, recursive content discovery |
| [sqlmap](https://sqlmap.org/) | OSS | Automated SQL injection detection and exploitation |
| [nikto](https://cirt.net/Nikto2) | OSS | Web server misconfiguration scanner |

### Network Scanning & Enumeration
| Tool | Type | Primary Use |
|---|---|---|
| [Nmap](https://nmap.org/) | OSS | Port scanning, service detection, OS fingerprinting |
| [Masscan](https://github.com/robertdavidgraham/masscan) | OSS | High-speed port scanning |
| [Nessus (attack mode)](https://www.tenable.com/) | COM | Credentialed network enumeration |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | OSS | SMB/AD/LDAP enumeration and lateral movement |
| [Impacket](https://github.com/fortra/impacket) | OSS | Python network protocol toolkit (SMB, Kerberos, NTLM) |

### Active Directory Attack Tools
| Tool | Type | Primary Use |
|---|---|---|
| [BloodHound / BloodHound CE](https://bloodhoundenterprise.io/) | OSS/COM | AD attack path mapping |
| [SharpHound](https://github.com/BloodHoundAD/SharpHound) | OSS | BloodHound data collection agent |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | OSS | Credential extraction (LSASS, Kerberos) |
| [Rubeus](https://github.com/GhostPack/Rubeus) | OSS | Kerberos attack toolkit |
| [Responder](https://github.com/lgandx/Responder) | OSS | LLMNR/NBNS/mDNS poisoning, credential capture |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit) | OSS | AD enumeration via PowerShell |

---

## Network Security

### Traffic Analysis
| Tool | Type | Primary Use |
|---|---|---|
| [Wireshark](https://www.wireshark.org/) | OSS | Packet capture and protocol analysis |
| [Zeek](https://zeek.org/) | OSS | Network traffic analysis and logging |
| [Suricata](https://suricata.io/) | OSS | Network IDS/IPS, file extraction |
| [Snort](https://www.snort.org/) | OSS | Network IDS/IPS, rule-based detection |
| [tcpdump](https://www.tcpdump.org/) | OSS | Command-line packet capture |
| [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) | OSS | Passive network forensics, file carving |

### Firewall & Zero Trust
| Tool | Type | Primary Use |
|---|---|---|
| [Palo Alto Networks NGFW](https://www.paloaltonetworks.com/network-security/next-generation-firewall) | COM | Next-gen firewall, URL filtering, WildFire |
| [Fortinet FortiGate](https://www.fortinet.com/products/next-generation-firewall) | COM | NGFW, SD-WAN, UTM |
| [Zscaler ZIA/ZPA](https://www.zscaler.com/) | COM | Cloud proxy, Zero Trust Network Access |
| [Cloudflare Access](https://www.cloudflare.com/zero-trust/products/access/) | COM | Zero Trust access, Magic Transit |
| [pfSense](https://www.pfsense.org/) | OSS | Open source firewall and router |
| [OPNsense](https://opnsense.org/) | OSS | Open source firewall with IDS integration |

### DNS Security
| Tool | Type | Primary Use |
|---|---|---|
| [Cisco Umbrella](https://umbrella.cisco.com/) | COM | DNS security, cloud-delivered threat prevention |
| [Pi-hole](https://pi-hole.net/) | OSS | DNS sinkhole, ad/malware blocking |
| [BIND](https://www.isc.org/bind/) | OSS | DNS server with RPZ (response policy zones) |

---

## Identity & Access

| Tool | Type | Primary Use |
|---|---|---|
| [Microsoft Entra ID (Azure AD)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id) | COM | Identity provider, SSO, Conditional Access |
| [Okta](https://okta.com/) | COM | Identity platform, SSO, MFA, lifecycle management |
| [CyberArk PAM](https://www.cyberark.com/) | COM | Privileged access management, vault |
| [BeyondTrust](https://www.beyondtrust.com/) | COM | PAM, least-privilege, remote access |
| [HashiCorp Vault](https://www.vaultproject.io/) | OSS | Secrets management, dynamic credentials |
| [Keycloak](https://www.keycloak.org/) | OSS | Open source IAM, SSO, OAuth2/OIDC |
| [Duo Security](https://duo.com/) | COM | MFA, device trust, zero trust access |
| [Yubico YubiKey](https://www.yubico.com/) | COM | Hardware MFA, FIDO2/WebAuthn |
| [Semperis](https://www.semperis.com/) | COM | AD forest recovery, identity security |

---

## Cloud Security

### CSPM / CNAPP
| Tool | Type | Primary Use |
|---|---|---|
| [Wiz](https://wiz.io/) | COM | CNAPP, cloud graph, CSPM, secrets, CIEM |
| [Orca Security](https://orca.security/) | COM | Agentless CSPM/CWPP/DSPM |
| [Prisma Cloud (Palo Alto)](https://www.paloaltonetworks.com/prisma/cloud) | COM | CNAPP, IaC scanning, runtime protection |
| [Microsoft Defender for Cloud](https://azure.microsoft.com/en-us/products/defender-for-cloud/) | COM | Multi-cloud CSPM and CWPP |
| [Prowler](https://github.com/prowler-cloud/prowler) | OSS | AWS/Azure/GCP security audit and CSPM |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | OSS | Multi-cloud security auditing |
| [Checkov](https://www.checkov.io/) | OSS | IaC security scanning (Terraform, CF, Helm) |

### DSPM & DLP
| Tool | Type | Primary Use |
|---|---|---|
| [Varonis](https://www.varonis.com/) | COM | DSPM, data access governance, threat detection |
| [Microsoft Purview](https://www.microsoft.com/en-us/security/business/microsoft-purview) | COM | DLP, information protection, compliance |
| [Forcepoint DLP](https://www.forcepoint.com/) | COM | Enterprise DLP, insider threat |
| [Netskope](https://www.netskope.com/) | COM | CASB, SSE, DLP, cloud visibility |

---

## DFIR & Forensics

### Memory & Disk Forensics
| Tool | Type | Primary Use |
|---|---|---|
| [Volatility 3](https://www.volatilityfoundation.org/) | OSS | Memory forensics, artifact extraction |
| [Autopsy](https://www.autopsy.com/) | OSS | Disk forensics GUI (Sleuth Kit frontend) |
| [Sleuth Kit](https://www.sleuthkit.org/) | OSS | Disk image analysis tools |
| [FTK (Forensic Toolkit)](https://www.exterro.com/ftk) | COM | Enterprise disk and email forensics |
| [X-Ways Forensics](https://www.x-ways.net/) | COM | Lightweight professional forensics |
| [REMnux](https://remnux.org/) | OSS | Linux distro for malware and artifact analysis |

### Live Response & IR
| Tool | Type | Primary Use |
|---|---|---|
| [Velociraptor](https://www.velocidex.com/) | OSS | Endpoint visibility, live forensics, hunt |
| [KAPE (Kroll Artifact Parser)](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) | OSS | Fast triage artifact collection |
| [GRR Rapid Response](https://github.com/google/grr) | OSS | Remote live forensics at scale |
| [TheHive](https://thehive-project.org/) | OSS | IR case management |
| [Cortex](https://github.com/TheHive-Project/Cortex) | OSS | Observable analysis and active response |
| [IRIS](https://github.com/dfir-iris/iris-web) | OSS | Collaborative IR management platform |

---

## Malware Analysis

### Static Analysis
| Tool | Type | Primary Use |
|---|---|---|
| [Ghidra](https://ghidra-sre.org/) | OSS | Reverse engineering and disassembly (NSA) |
| [IDA Pro / IDA Free](https://hex-rays.com/) | COM/Free | Industry-standard disassembler and debugger |
| [Binary Ninja](https://binary.ninja/) | COM | Modern binary analysis platform |
| [YARA](https://virustotal.github.io/yara/) | OSS | Pattern-based malware classification rules |
| [CyberChef](https://gchq.github.io/CyberChef/) | OSS | Data transformation, deobfuscation, encoding |
| [pestudio](https://www.winitor.com/) | Free | PE static analysis (imports, entropy, strings) |

### Dynamic Analysis / Sandboxes
| Tool | Type | Primary Use |
|---|---|---|
| [Any.run](https://any.run) | COM/Free | Interactive cloud sandbox |
| [Cuckoo Sandbox](https://cuckoosandbox.org/) | OSS | Self-hosted automated malware analysis |
| [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) | OSS | Config and payload extraction sandbox |
| [Joe Sandbox](https://www.joesecurity.org/) | COM | Deep behavioral analysis |
| [Hatching Triage](https://tria.ge/) | COM/Free | Multi-platform sandbox with family detection |

---

## AppSec & DevSecOps

### SAST / DAST / SCA
| Tool | Type | Primary Use |
|---|---|---|
| [Semgrep](https://semgrep.dev/) | OSS/COM | SAST, custom rules, 30+ languages |
| [SonarQube](https://www.sonarqube.org/) | OSS/COM | SAST, code quality, security hotspots |
| [CodeQL](https://codeql.github.com/) | Free | Semantic code analysis, GitHub integration |
| [Snyk](https://snyk.io/) | COM/Free | SCA, container, IaC security |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | OSS | SCA, known CVE detection |
| [Trivy](https://github.com/aquasecurity/trivy) | OSS | Comprehensive SCA + secrets + IaC |

### Secrets Detection
| Tool | Type | Primary Use |
|---|---|---|
| [GitLeaks](https://github.com/gitleaks/gitleaks) | OSS | Secrets scanning in git repos and CI |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | OSS | Deep secret scanning with entropy analysis |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | OSS | Pre-commit hooks for secrets prevention |
| [GitGuardian](https://www.gitguardian.com/) | COM/Free | Real-time secrets detection in git |

---

## Cryptography & PKI

| Tool | Type | Primary Use |
|---|---|---|
| [OpenSSL](https://www.openssl.org/) | OSS | TLS, certs, key management, cipher ops |
| [HashiCorp Vault](https://www.vaultproject.io/) | OSS | Secrets, PKI CA, dynamic credentials |
| [Certbot / ACME](https://certbot.eff.org/) | OSS | Automated Let's Encrypt certificate issuance |
| [cfssl](https://github.com/cloudflare/cfssl) | OSS | Cloudflare PKI toolkit, cert signing |
| [step-ca](https://smallstep.com/docs/step-ca/) | OSS | Private ACME-enabled CA |
| [EJBCA](https://www.ejbca.org/) | OSS | Enterprise-grade Java PKI/CA |
| [Thales Luna HSM](https://cpl.thalesgroup.com/encryption/hardware-security-modules) | COM | Hardware security module |
| [Entrust nShield](https://www.entrust.com/digital-security/hsm/) | COM | HSM, key management, code signing |

---

## GRC & Compliance

| Tool | Type | Primary Use |
|---|---|---|
| [Wazuh](https://wazuh.com/) | OSS | Compliance monitoring (PCI-DSS, HIPAA, GDPR) |
| [OpenRMF](https://www.openrmf.io/) | OSS | STIG/RMF compliance automation |
| [OSCAL](https://pages.nist.gov/OSCAL/) | OSS | Machine-readable compliance content standard |
| [Drata](https://drata.com/) | COM | Automated SOC 2, ISO 27001, HIPAA compliance |
| [Vanta](https://www.vanta.com/) | COM | Continuous compliance monitoring |
| [ServiceNow GRC](https://www.servicenow.com/products/governance-risk-and-compliance.html) | COM | Enterprise GRC, risk register, policy management |
| [RSA Archer](https://www.archerirm.com/) | COM | Integrated risk management platform |

---

---

## OSINT & Reconnaissance

| Tool | Language | Type | Description |
|---|---|---|---|
| [Amass](https://www.owasp.org/index.php/OWASP_Amass_Project) | Go | OSS | DNS enumeration and network mapping tool suite: scraping, recursive brute forcing, crawling web |
| [Argus](https://github.com/jasonxtn/Argus) | Python | OSS | All-in-one toolkit for information gathering and reconnaissance |
| [Ars0n Framework](https://github.com/R-s0n/ars0n-framework) | JavaScript | OSS | Bug bounty hunting framework to automate the reconnaissance in a WebUI |
| [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) | JavaScript | OSS | Bug bounty hunting framework to automate the reconnaissance in a WebUI |
| [Asnlookup](https://github.com/yassineaboukir/Asnlookup) | Python | OSS | Leverage ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconna |
| [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) | Python | OSS | Subdomain enumerator |
| [AutoRecon](https://github.com/Tib3rius/AutoRecon) | Python | OSS | Multi-threaded network reconnaissance tool which performs automated enumeration of services |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | Python | OSS | OSINT framework; subdomain enumeration, port scanning, web screenshots, vulnerability scanning |
| [Belati](https://github.com/aancw/Belati) | Python | OSS | OSINT tool, collect data and document actively or passively |
| [Bitcrook](https://github.com/ax-i-om/bitcrook) | Go | OSS | Reconnaissance Apparatus; Information gathering, conglomerate of tools including custom algorit |
| [Censys](https://search.censys.io/) |  | OSS | Search devices connected to the internet; helps find information about desktops, servers, IoT d |
| [Certstream](https://certstream.calidog.io/) | Elixir | OSS | Intelligence feed that gives real-time updates from the Certificate Transparency Log network |
| [DNSDumpster](https://dnsdumpster.com/) |  | OSS | Domain research tool that can discover hosts related to a domain |
| [DNSRecon](https://github.com/darkoperator/dnsrecon) | Python | OSS | DNS reconnaissance tool: AXFR, DNS records enumeration, TLD expansion, wildcard resolution, sub |
| [Darkshot](https://github.com/mxrch/darkshot) | Python | OSS | Lightshot scraper with multi-threaded OCR and auto categorizing screenshots |
| [Domainim](https://github.com/pptx704/domainim) | Nim | OSS | Domain reconnaissance for organizational network scanning |
| [EagleEye](https://github.com/ThoughtfulDev/EagleEye) | Python | OSS | Image recognition on instagram, facebook and twitter |
| [Espionage](https://github.com/iAbdullahMughal/espionage) | Python | OSS | Domain information gathering: whois, history, dns records, web technologies, records |
| [FOCA](https://github.com/ElevenPaths/FOCA) | Csharp | OSS | OSINT framework and metadata analyser |
| [FULLHUNT](https://fullhunt.io/) |  | OSS | Search devices connected to the internet; helps find information about desktops, servers, IoT d |
| [Facebook_OSINT_Dump](https://github.com/TheCyberViking/Facebook_OSINT_Dump) | Shell | OSS | OSINT tool, facebook profile dumper, windows and chrome only |
| [FinalRecon](https://github.com/thewhiteh4t/FinalRecon) | Python | OSS | Web reconnaissance script |
| [Findomain](https://github.com/Edu4rdSHL/findomain) | Rust | OSS | Fast subdomain enumerator |
| [GHunt](https://github.com/mxrch/GHunt) | Python | OSS | Investigate Google accounts with emails and find name, usernames, Youtube Channel, probable loc |
| [Geolocation Estimation](https://labs.tib.eu/geoestimation/) |  | OSS | Automatic GEOINT using deep learning |

---

## Password Cracking & Hash Analysis

| Tool | Language | Type | Description |
|---|---|---|---|
| [BEWGor](https://github.com/berzerk0/BEWGor) | Python | OSS | Bull's Eye Wordlist Generator, password wordlist generator based on target information |
| [Bopscrk](https://github.com/R3nt0n/bopscrk) | Python | OSS | Before Outset PaSsword CRacKing, password wordlist generator with exclusive features like lyric |
| [CUPP](https://github.com/Mebus/cupp) | Python | OSS | Common User Passwords Profiler, wordlist generator based on user profiling |
| [CeWL](https://github.com/digininja/CeWL) | Ruby | OSS | Custom wordlist generator based on website crawling |
| [ComPP](https://github.com/sec-it/ComPP) | Python | OSS | Company Passwords Profiler helps making a bruteforce wordlist for a targeted company |
| [CrackQ](https://github.com/f0cker/crackq) | Python | OSS | Hashcat cracking queue system, API and WebUI |
| [CrackStation](https://crackstation.net/) | PHP | OSS | Pre-computed lookup tables to crack password hashes |
| [Cracken](https://github.com/shmuelamar/cracken) | Rust | OSS | Password wordlist generator, Smartlist creation and password hybrid-mask |
| [CrackerJack](https://github.com/ctxis/crackerjack) | Python | OSS | Hashcat WebUI; session management, mask generation, API, notifications, local and LDAP authenti |
| [Cracklord](http://jmmcatee.github.io/cracklord/) | Go | OSS | Scalable, pluggable, and distributed system for hash cracking, supports Hashcat |
| [Duplicut](https://github.com/nil0x42/duplicut) | C | OSS | Remove duplicates from massive wordlist, without sorting it (for dictionary-based password crac |
| [Fitcrack](https://fitcrack.fit.vutbr.cz/) | C | OSS | Hashcat-based distributed password cracking system with WebUI |
| [GAU](https://github.com/lc/gau) | Go | OSS | Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and |
| [GeoWordlists](https://github.com/p0dalirius/GeoWordlists) | Python | OSS | Generate wordlists of passwords containing cities at a defined distance around the client city |
| [GoCrack](https://github.com/fireeye/gocrack) | Go | OSS | Management frontend for hash cracking tools, supporting hashcat |
| [HashKitty](https://github.com/ScriptSathi/HashKitty) | TypeScript | OSS | Web interface for Hashcat |
| [Hashcat](https://hashcat.net/hashcat/) | C | OSS | Hash cracking tool |
| [Hashpass](https://github.com/dj-zombie/hashpass) | Ruby | OSS | Hashcat WebUI; queuing, local authentication, SMS and email notifications, map integration |
| [Hashtopolis](https://github.com/s3inlc/hashtopolis) | PHP | OSS | Hashcat wrapper for distributed hashcracking |
| [Hashview](http://www.hashview.io/) | Python | OSS | Web-UI for managing, organizing, automating Hashcat commands/tasks |

---

## Wireless Security

| Tool | Language | Type | Description |
|---|---|---|---|
| [Aircrack-Ng](http://www.aircrack-ng.org/) | C | OSS | Suite of tools to assess WiFi network security (cracking WEP and WPA PSK) |
| [BtleJack](https://github.com/virtualabs/btlejack) | Python | OSS | Bluetooth Low Energy Swiss-army knife |
| [Crunch-Cracker](https://github.com/KURO-CODE/Crunch-Cracker) | Shell | OSS | Wordlist generator and Wi-Fi cracker |
| [Fluxion](https://fluxionnetwork.github.io/fluxion/) | Shell | OSS | MITM WPA attack tool |
| [FruityWiFi](https://github.com/xtr4nge/FruityWifi) | PHP | OSS | Wireless network auditing tool controlled by a web interface |
| [Hijacker](https://github.com/chrisk44/Hijacker) | Java | OSS | Android GUI for Aircrack, Airodump, Aireplay, MDK3 and Reaver |
| [Infernal-Wireless](https://github.com/entropy1337/infernal-twin) | Python | OSS | Automated wireless hacking tool  |
| [Kismet](https://www.kismetwireless.net/) | CPlusPlus | OSS | Sniffer, WIDS, and wardriving tool for Wi-Fi, Bluetooth, Zigbee, RF |
| [MDK3-master](https://github.com/wi-fi-analyzer/mdk3-master) | C | OSS | PoC tool to exploit common IEEE 802.11 protocol weaknesses |
| [MDK4](https://github.com/aircrack-ng/mdk4) | C | OSS | PoC tool to exploit common IEEE 802.11 protocol weaknesses |
| [Modmobjam](https://github.com/Synacktiv/Modmobjam) | Python | OSS | Cellular networks jamming PoC for mobile equipments |
| [Modmobmap](https://github.com/Synacktiv/Modmobmap) | Python | OSS | Tool to retrieve information of cellular networks |
| [Oasis](https://github.com/RCayre/oasis) | C | OSS | Framework allowing to write, build and patch instrumentation modules for Bluetooth Low Energy ( |
| [QCSuper](https://github.com/P1sec/QCSuper) | Python | OSS | Communicate with Qualcomm-based phones and modems, allowing to capture raw 2G/3G/4G radio frame |
| [RF Swift](https://github.com/penthertz/rf-swift) | Go | OSS | Toolbox for HAM radio enthusiasts and RF professionals |

---

## Binary Exploitation

| Tool | Language | Type | Description |
|---|---|---|---|
| [ASLRay](https://github.com/cryptolok/ASLRay) | Shell | OSS | Tool for ASLR bypass with stack-spraying |
| [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | Python | OSS | Framework for ROP exploitation |
| [heaphopper](https://github.com/angr/heaphopper) | Python | OSS | Bounded model checking framework for Heap-implementations |
| [libformatstr](https://github.com/hellman/libformatstr) | Python | OSS | Library to simplify format string exploitation |
| [pwntools](https://github.com/Gallopsled/pwntools) | Python | OSS | Framework and exploit development library |
| [pwntools-ruby](https://github.com/peter50216/pwntools-ruby) | Ruby | OSS | Framework and exploit development library, ported onto ruby |

---

## Steganography

| Tool | Language | Type | Description |
|---|---|---|---|
| [Aperi'Solve](https://aperisolve.fr/) | Python | OSS | Steganalysis web platform with layer, zsteg, steghide and exiftool analysis |
| [Audacity](http://www.audacityteam.org/) |  | OSS | Tool to edit and analyze audio tracks |
| [Depix](https://github.com/spipm/Depix) | Python | OSS | Recover plaintext from pixelized screenshots |
| [ExifTool](http://www.sno.phy.queensu.ca/~phil/exiftool/) | Perl | OSS | Library and CLI tool to read and write meta information (EXIF, GPS, IPTC, XMP, JFIF, …) in file |
| [Exiv2](http://www.exiv2.org/index.html) | CPlusPlus | OSS | Library and CLI tool to read and write meta information (Exif, IPTC & XMP metadata and ICC Prof |
| [ImageMagick](http://www.imagemagick.org) | C | OSS | Software suite and library to create, edit, compose, or convert images |
| Outguess |  | OSS | Tool to hide messages in files (website down since 2004) |
| [SHIT](https://github.com/qll/shit) | Python | OSS | Stego Helper Identification Tool, multi-purpose image steganography tool |
| [SmartDeblur](https://github.com/Y-Vladimir/SmartDeblur) | CPlusPlus | OSS | To to restore defocused and blurred images (update binary only for Windows, Mac OS binary out o |
| [Sonic Visualiser](http://www.sonicvisualiser.org/) |  | OSS | Tool to edit and analyze audio tracks |
| [StegOnline](https://georgeom.net/StegOnline) | JavaScript | OSS | Stego image toolsuite in the browser |
| StegSolve | Java | OSS | GUI tool to analyse images |

---

## Practice & Intentionally Vulnerable Applications

| Tool | Language | Type | Description |
|---|---|---|---|
| [Bodhi](https://github.com/amolnaik4/bodhi) | Python | OSS | Client-side vulnerability playground, CTF style application, a bot program which simulates the  |
| [Bust-A-Kube](https://www.bustakube.com/) | PHP | OSS | Intentionally-vulnerable Kubernetes cluster, intended to help people self-train on attacking an |
| [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | Python | OSS | Damn Vulnerable GraphQL Application, insecure webapp for GraphQL security trainings |
| [DVIA](http://damnvulnerableiosapp.com/) | Swift | OSS | Damn Vulnerable iOS App, insecure webapp for mobile security trainings |
| [DVWA](https://github.com/ethicalhack3r/DVWA) | PHP | OSS | Damn Vulnerable Web Application, insecure webapp for security trainings |
| [Google Gruyere](http://google-gruyere.appspot.com) | Python | OSS | Codelab for white-box and black-box hacking |
| [Hackazon](https://github.com/rapid7/hackazon) | PHP | OSS | Intentionally vulnerable web shopping application using modern technologies and containing conf |
| [Metasploitable](https://github.com/rapid7/metasploitable3) |  | OSS | VM that is built from the ground up with a large amount of security vulnerabilities |
| [OWASP Juice Shop](http://owasp-juice.shop) | JavaScript | OSS | Insecure web application with >85 challenges; supports CTFs, custom themes, tutorial mode etc. |
| [OWASP Mutillidae II](https://www.owasp.org/index.php/OWASP_Mutillidae_2_Project) | PHP | OSS | Intentionally vulnerable web-application containing some OWASP Top Ten vulnerabilities, with hi |
| [OWASP WebGoat](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project) | Java | OSS | Deliberately insecure web application to teach web application security lessons |
| [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) | JavaScript | OSS | Intentionally vulnerable e-commerce application built with Next.js and React, REST API, solutio |
| [VAmPI](https://github.com/erev0s/VAmPI) | Python | OSS | Vulnerable REST API with OWASP top 10 vulnerabilities for security testing  |
| [XVNA](https://github.com/vegabird/xvna) | JavaScript | OSS | Extreme Vulnerable Node Application, insecure webapp for security trainings |
### Additional Reverse Engineering Tools
| Tool | Language | Type | Description |
|---|---|---|---|
| [ANY RUN](https://any.run/) |  | OSS | Online virtual machine for malware hunting, sandbox with interactive access, real-time data-flo |
| [Apk2Gold](https://github.com/lxdvs/apk2gold) | Shell | OSS | Android decompiler (wrapper for apktool, dex2jar, and jd-gui) |
| [Apktool](https://ibotpeaches.github.io/Apktool/) | Java | OSS | Android disassembler and rebuilder |
| [BOF launcher](https://github.com/The-Z-Labs/bof-launcher) | Zig | OSS | Beacon Object File (BOF) launcher; library for executing BOF files in C/C++/Zig applications |
| [Barf](https://github.com/programa-stic/barf-project) | Python | OSS | Binary Analysis and Reverse engineering Framework |
| [BinCAT](https://github.com/airbus-seclab/bincat) | OCaml | OSS | Binary code static analyser, with IDA integration; performs value and taint analysis, type reco |
| [BinDiff](https://github.com/google/bindiff) | CPlusPlus | OSS | Binary diffing for many architectures compatible with IDA Pro, Binary Ninja and Ghidra |
| [CFF Explorer](http://www.ntcore.com/exsuite.php) |  | OSS | PE Editor |
| [Cerberus](https://github.com/h311d1n3r/Cerberus) | CPlusPlus | OSS | Unstrip Rust and Go binaries (ELF and PE) for static analysis; based on hashing and scoring sys |
| [Cuckoo 3](https://github.com/cert-ee/cuckoo3) | Python | OSS | Python 3 port of Cuckoo, automated malware analysis system |
| [Cutter](https://cutter.re/) | CPlusPlus | OSS | Qt and C++ GUI for rizin |
| [DRAKVUF Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox) | Python | OSS | Automated black-box hypervisor-level malware analysis system |
### Additional Web Testing Tools
| Tool | Language | Type | Description |
|---|---|---|---|
| [0d1n](https://github.com/CoolerVoid/0d1n) | C | OSS | Automate customized attacks against web applications |
| [1u.ms](http:/1u.ms) | Go | OSS | zero-configuration DNS utilities for assisting in detection and exploitation of SSRF-related vu |
| [230-OOB](http://xxe.sh/) | Python | OSS | FTP server for OOB XXE attacks |
| [API-fuzzer](https://github.com/Fuzzapi/API-fuzzer) | Ruby | OSS | Library to fuzz request attributes using common pentesting techniques and lists vulnerabilities |
| [Acunetix](https://www.acunetix.com/) |  | OSS | Web application security scanner |
| [Afuzz](https://github.com/RapidDNS/Afuzz) | Python | OSS | Web directory and file scanner (wordlist bruteforce) |
| [Aquatone](https://michenriksen.com/blog/aquatone-now-in-go/) | Go | OSS | Domain flyover tool; visual inspection of websites across a large amount of hosts and is conven |
| [Arachni](http://www.arachni-scanner.com/) | Ruby | OSS | Web application security scanner framework |
| [Arjun](https://github.com/s0md3v/Arjun) | Python | OSS | HTTP parameter discovery suite |
| [AssassinGo](https://github.com/AmyangXYZ/AssassinGo) | Go | OSS | Web pentest framework for information gathering and vulnerability scanning |
| [Astra](https://github.com/flipkart-incubator/astra) | Python | OSS | REST API penetration testing tool |
| [Atlas](https://github.com/m4ll0k/Atlas) | Python | OSS | Tool that suggests sqlmap tampers to bypass WAF/IDS/IPS based on status codes |
### Additional Threat Intelligence Tools
| Tool | Language | Type | Description |
|---|---|---|---|
| [Hudson Rock Cybercrime Intelligence Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) |  | OSS | Cybercrime intelligence toolset to check if a specific digital asset was compromised in global  |
| [Intelligence X](https://intelx.io/) |  | OSS | Threat intelligence search engine: email addresses, domains, URLs, IPs, CIDRs, Bitcoin addresse |
| [IsMalicious](https://ismalicious.com) |  | OSS | Malicious IP address and domain detection, classification and monitoring |
| [Netglub](https://www.netglub.org/) |  | OSS | Maltego alternative |
| [PatrowlHears](https://patrowlhears.io/) | Python | OSS | Provides a unified source of vulnerability, exploit and threat Intelligence feeds; comprehensiv |
| [Pulsedive](https://pulsedive.com/) |  | OSS | CTI platform to search, scan, and enrich IPs, URLs, domains and other IOCs from OSINT feeds or  |
| [Redirect Tracker](https://www.redirecttracker.com/) |  | OSS | Track the HTTP redirect chains; 301 and 302, JavaScript and Meta fresh redirects |
| [ThreatIngestor](https://inquest.readthedocs.io/projects/threatingestor/) | Python | OSS | Extract and aggregate threat intelligence (IOCs from threat feeds) |
## Related Resources
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — tools mapped to NIST controls and pipeline stages
- [Controls Mapping](CONTROLS_MAPPING.md) — full vendor → NIST 800-53 → ATT&CK chain
- [ATT&CK Navigator](navigator/) — technique coverage visualization
- [Starred Repositories](STARRED_REPOS.md) — curated GitHub tool repositories
- [Hands-On Labs](LABS.md) — practice environments for each category
