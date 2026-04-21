# Black Hat Arsenal Crosswalk



This page shows how the [official Black Hat Arsenal tools repository](https://github.com/toolswatch/blackhat-arsenal-tools) can strengthen the TeamStarWolf educational library.



The goal is not to mirror Arsenal entry-for-entry. The goal is to turn a conference tool index into useful next steps for starring repos, following maintainers, finding demo videos, and pairing books with hands-on tooling.



## Source Snapshot



- Source repo: [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools)

- Generated dataset: [data/blackhat_arsenal_tools.csv](data/blackhat_arsenal_tools.csv)

- Builder script: [scripts/build_blackhat_arsenal_dataset.py](scripts/build_blackhat_arsenal_dataset.py)

- Current snapshot in this repo: 103 tool pages across 19 Arsenal categories

- GitHub-backed entries: 97

- Entries with Twitter/X handles: 85

- Entries with direct YouTube links: 5



| Arsenal category | Tools |

|---|---:|

| `network_defense` | 11 |

| `frameworks` | 10 |

| `exploitation` | 8 |

| `malware_research` | 8 |

| `network_attacks` | 8 |

| `vulnerability_assessment` | 8 |

| `webapp_security` | 7 |

| `hardware_iot` | 6 |

| `mobile_hacking` | 6 |

| `red_team` | 6 |

| `cryptography` | 4 |

| `cloud` | 3 |

| `code_assessment` | 3 |

| `forensics` | 3 |

| `hardening` | 3 |

| `osint` | 3 |

| `phishing` | 2 |

| `ics_scada` | 1 |

| `reverse_engineering` | 3 |



## Where It Fits In This Repo



| TeamStarWolf page | Best use of Arsenal data |

|---|---|

| [CURATED_STARS_LISTS.md](CURATED_STARS_LISTS.md) | Expand list descriptions with tool-first examples that come from a known conference catalog instead of random repo browsing |

| [../STARRED_REPOS.md](../STARRED_REPOS.md) | Maintain a clear review queue of strong Arsenal repos that are not yet part of the starred index |

| [../TWITTER_FOLLOW_LIST.md](../TWITTER_FOLLOW_LIST.md) | Pull in maintainer and project feeds tied directly to tools, not just general commentary accounts |

| [../YOUTUBE_CHANNELS.md](../YOUTUBE_CHANNELS.md) | Build a short watch path from Arsenal-linked channels, playlists, and demos |

| [../CYBERSECURITY_BOOK_LIST.md](../CYBERSECURITY_BOOK_LIST.md) | Pair books with concrete tools so the reading list becomes easier to lab against |



## High-Signal Review Queue



These are good candidates to review for future starring because they appear in Black Hat Arsenal but are not currently listed in [../STARRED_REPOS.md](../STARRED_REPOS.md).



| Area | Candidate repos |

|---|---|

| Cloud labs and assessment | [AWSGoat](https://github.com/ine-labs/AWSGoat), [AzureGoat](https://github.com/ine-labs/AzureGoat) |

| Offensive and post-exploitation | [Merlin](https://github.com/Ne0nd0g/merlin), [MailSniper](https://github.com/dafthack/MailSniper) |

| Mobile testing | [Needle](https://github.com/mwrlabs/needle) |

| Malware and DFIR | [FLOSS](https://github.com/fireeye/flare-floss), [inVtero.net](https://github.com/ShaneK2/inVtero.net), [siembol](https://github.com/G-Research/siembol) |

| AppSec and exposure work | [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck), [OWTF](https://github.com/owtf/owtf), [CrowdSec](https://github.com/crowdsecurity/crowdsec) |

| Embedded, hardware, and OT | [EMBA](https://github.com/e-m-b-a/emba), [JTAGulator](https://github.com/grandideastudio/jtagulator), [DYODE](https://github.com/wavestone-cdt/dyode) |



## Maintainers And Project Feeds



These are useful tool-first accounts to follow when you want more signal from builders and operators.



- [@Ne0nd0g](https://twitter.com/Ne0nd0g) - Merlin C2 and operator tradecraft

- [@dafthack](https://twitter.com/dafthack) - MailSniper and Microsoft-focused offensive tooling

- [@patrickwardle](https://twitter.com/patrickwardle) - Objective-See tooling and macOS security

- [@ajinabraham](https://twitter.com/ajinabraham) - MobSF maintainer and mobile testing

- [@leonjza](https://twitter.com/leonjza) - objection maintainer and mobile instrumentation

- [@securefirmware](https://twitter.com/securefirmware) - EMBA and firmware analysis

- [@joegrand](https://twitter.com/joegrand) - hardware tooling including JTAGulator

- [@williballenthin](https://twitter.com/williballenthin) - FLOSS and reverse engineering support tooling

- [@qtc_de](https://twitter.com/qtc_de) - Remote Method Guesser and Java/RMI attack surface work

- [@Crowd_Security](https://twitter.com/Crowd_Security) - CrowdSec project feed

- [@faradaysec](https://twitter.com/faradaysec) - Faraday collaborative pentest platform

- [@zaproxy](https://twitter.com/zaproxy) - ZAP project feed

- [@owtfp](https://twitter.com/owtfp) - OWTF offensive web testing



## Direct Video Trail



Arsenal entries only expose a handful of direct YouTube links, so this list stays intentionally small.



- [Black Hat Official YouTube](https://www.youtube.com/@BlackHatOfficialYT) - best starting point for searching Arsenal session titles from the dataset

- [Faraday channel](https://www.youtube.com/channel/UCnHpyTi7zRQ9A4U4Ldc65YQ) - collaborative pentest platform walkthroughs

- [OWTF channel](https://www.youtube.com/user/owtfproject) - offensive web testing workflow demos

- [GEF playlist](https://www.youtube.com/playlist?list=PLjAuO31Rg972WeMvdR_57Qu-aVM8T6DkQ) - debugger workflow material tied to GEF

- [MI-X demo](https://www.youtube.com/watch?v=2FsnsJ0mr68) - vulnerability assessment demo from the Arsenal entry

- [Remote Method Guesser demo](https://youtu.be/t_aw1mDNhzI) - focused demo for Java/RMI attack surface work



## Book Pairings



Use these when you want to turn the reading list into a lab track.



| Study area | Read with | Then open |

|---|---|---|

| Cloud security | cloud and infrastructure sections in [../CYBERSECURITY_BOOK_LIST.md](../CYBERSECURITY_BOOK_LIST.md) | [Prowler](https://github.com/prowler-cloud/prowler), [AWSGoat](https://github.com/ine-labs/AWSGoat), [AzureGoat](https://github.com/ine-labs/AzureGoat) |

| Offensive and red team | *The Hacker Playbook 3*, *Advanced Penetration Testing*, *RTFM* | [Merlin](https://github.com/Ne0nd0g/merlin), [MailSniper](https://github.com/dafthack/MailSniper), [Legion](https://github.com/GoVanguard/legion) |

| Web and AppSec | *The Web Application Hacker's Handbook*, *Bug Bounty Bootcamp* | [ZAP](https://github.com/zaproxy/zaproxy), [OWTF](https://github.com/owtf/owtf), [OWASP Dependency-Check](https://github.com/jeremylong/DependencyCheck) |

| Mobile security | the mobile section in [../CYBERSECURITY_BOOK_LIST.md](../CYBERSECURITY_BOOK_LIST.md) plus OWASP MASTG | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF), [objection](https://github.com/sensepost/objection), [Needle](https://github.com/mwrlabs/needle) |

| Malware and DFIR | *Practical Malware Analysis*, *The Art of Memory Forensics* | [FLOSS](https://github.com/fireeye/flare-floss), [inVtero.net](https://github.com/ShaneK2/inVtero.net), [siembol](https://github.com/G-Research/siembol) |

| Hardware, firmware, and OT | the hardware and OT sections in [../CYBERSECURITY_BOOK_LIST.md](../CYBERSECURITY_BOOK_LIST.md) | [EMBA](https://github.com/e-m-b-a/emba), [JTAGulator](https://github.com/grandideastudio/jtagulator), [DYODE](https://github.com/wavestone-cdt/dyode) |



## Notes



- Black Hat Arsenal is a discovery layer, not a quality ranking.

- Some entries are older. Treat the dataset as a starting point, then verify project freshness and maintenance before relying on a tool.

- When a tool has both a GitHub repo and a project page, prefer the project docs first and the repo second.



---



## Arsenal Tool Crosswalk



> Mapping Black Hat USA/Europe/Asia Arsenal tools to TeamStarWolf discipline pages and MITRE ATT&CK techniques.



Use this table to find Arsenal tools by discipline and ATT&CK technique coverage.



| Tool | Arsenal Year | Category | Discipline Page | ATT&CK Techniques | Notes |

|---|---|---|---|---|---|

| Volatility 3 | BH USA 2020 | DFIR / Memory Forensics | [Digital Forensics](../disciplines/digital-forensics.md) | T1055, T1059, T1547 | Memory acquisition and analysis framework |

| Hayabusa | BH USA 2022 | DFIR / Threat Hunting | [Digital Forensics](../disciplines/digital-forensics.md) | T1078, T1059, T1003 | Windows event log fast forensics |

| Velociraptor | BH USA 2019 | DFIR / Endpoint | [Digital Forensics](../disciplines/digital-forensics.md) | T1059, T1078, T1003 | Endpoint visibility and DFIR collection |

| FLOSS | BH USA 2016 | Malware Analysis | [Malware Analysis](../disciplines/malware-analysis.md) | T1027, T1059, T1140 | FireEye FLARE Obfuscated String Solver |

| Semgrep | BH USA 2020 | AppSec / SAST | [DevSecOps](../disciplines/devsecops.md) | T1059, T1190, T1552 | Fast, customizable SAST for 30+ languages |

| Trivy | BH USA 2021 | Container Security | [DevSecOps](../disciplines/devsecops.md) | T1190, T1195, T1552 | All-in-one container + IaC scanner |

| Checkov | BH USA 2021 | IaC Security | [DevSecOps](../disciplines/devsecops.md) | T1190, T1068 | Infrastructure-as-Code policy scanner |

| gitleaks | BH USA 2021 | Secrets Detection | [DevSecOps](../disciplines/devsecops.md) | T1552, T1552.001 | Git history secrets scanning |

| KICS | BH USA 2022 | IaC Security | [DevSecOps](../disciplines/devsecops.md) | T1190, T1068 | Multi-IaC security scanner |

| Falco | BH USA 2019 | Runtime Security | [DevSecOps](../disciplines/devsecops.md) | T1059, T1055, T1543 | CNCF runtime security for containers |

| Cosign | BH USA 2022 | Supply Chain | [Supply Chain Security](../disciplines/supply-chain-security.md) | T1195.002, T1554 | Keyless container signing via Sigstore |

| Syft | BH USA 2022 | Supply Chain / SBOM | [Supply Chain Security](../disciplines/supply-chain-security.md) | T1195, T1195.001 | SBOM generation for containers and filesystems |

| in-toto | BH USA 2018 | Supply Chain | [Supply Chain Security](../disciplines/supply-chain-security.md) | T1195.002 | Software supply chain attestation framework |

| Rekor | BH USA 2021 | Supply Chain | [Supply Chain Security](../disciplines/supply-chain-security.md) | T1195, T1554 | Immutable supply chain transparency log |

| OpenBao | BH USA 2024 | Secrets Management | [Cryptography & PKI](../disciplines/cryptography-pki.md) | T1552, T1528 | Open-source Vault fork for secrets management |

| step-ca | BH USA 2020 | PKI | [Cryptography & PKI](../disciplines/cryptography-pki.md) | T1557, T1040 | Private ACME CA with automated cert issuance |

| testssl.sh | BH USA 2016 | TLS Testing | [Cryptography & PKI](../disciplines/cryptography-pki.md) | T1040, T1557 | Comprehensive TLS/SSL server testing |

| Presidio | BH USA 2022 | Privacy / PII | [Privacy Engineering](../disciplines/privacy-engineering.md) | T1005, T1213 | Microsoft PII detection and anonymization |

| ARX | BH Europe 2018 | Privacy / Anonymization | [Privacy Engineering](../disciplines/privacy-engineering.md) | T1005 | k-anonymity and data de-identification |

| Wazuh | BH USA 2023 | SIEM / XDR | [Security Operations](../disciplines/security-operations.md) | T1078, T1059, T1003 | Open-source XDR and SIEM |

| BloodHound | BH USA 2016 | Identity / AD | [Identity & Access Management](../disciplines/identity-access-management.md) | T1078, T1069, T1087 | Active Directory attack path analysis |

| Impacket | BH USA 2012 | Network / AD | [Identity & Access Management](../disciplines/identity-access-management.md) | T1550, T1558, T1003 | Python framework for Windows network protocols |

| Nuclei | BH USA 2021 | Vulnerability Scanning | [Vulnerability Management](../disciplines/vulnerability-management.md) | T1190, T1210 | Fast, template-based vulnerability scanner |

| OpenVAS / GVM | BH USA 2005 | Vulnerability Scanning | [Vulnerability Management](../disciplines/vulnerability-management.md) | T1190, T1210 | Open-source network vulnerability scanner |

| Zeek (Bro) | BH USA 2002 | Network Security | [Network Security](../disciplines/network-security.md) | T1040, T1071, T1048 | Network traffic analysis framework |

| Suricata | BH USA 2010 | IDS/IPS | [Network Security](../disciplines/network-security.md) | T1071, T1048, T1090 | High-performance network IDS/IPS/NSM |

| Burp Suite (community) | BH USA 2006 | Web AppSec | [Application Security](../disciplines/application-security.md) | T1190, T1059.007 | Web application proxy and scanner |

| Metasploit (modules) | BH USA 2004 | Offensive / Pentesting | [Offensive Security](../disciplines/offensive-security.md) | T1190, T1068, T1059 | Exploitation framework |

| OpenTitan | BH USA 2022 | Hardware Security | [Security Architecture](../disciplines/security-architecture.md) | T1542, T1495 | Open-source silicon root of trust |

| OWASP Threat Dragon | BH USA 2019 | Threat Modeling | [Security Architecture](../disciplines/security-architecture.md) | — | Visual threat modeling tool |



## Sources



- [Black Hat Arsenal](https://www.blackhat.com/arsenal.html) — Official Arsenal archive

- [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools) — Community-maintained Arsenal tool list

- [MITRE ATT&CK](https://attack.mitre.org/) — Technique references
---

## Arsenal Tools by ATT&CK Tactic

This section catalogs notable Black Hat Arsenal and community offensive/defensive tools organized by MITRE ATT&CK tactic. Use it to quickly identify which tool covers a given phase of an attack or assessment, and to find learning resources aligned to specific techniques.

---

### Reconnaissance & OSINT

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| Amass | OWASP | Subdomain enumeration and DNS mapping via passive and active techniques; integrates 50+ data sources | github.com/owasp-amass/amass |
| theHarvester | laramies | Email, hostname, and IP OSINT from search engines, DNS, and certificate transparency | github.com/laramies/theHarvester |
| Recon-ng | LaNMaSteR53 | Modular web reconnaissance framework inspired by Metasploit; supports dozens of data source modules | github.com/lanmaster53/recon-ng |
| SpiderFoot | smicallef | Automated OSINT aggregation across 200+ data sources; supports threat intelligence and attack surface mapping | github.com/smicallef/spiderfoot |
| OWASP Maryam | saeeddhqan | Open-source OSINT and recon framework with extensible module architecture | github.com/saeeddhqan/Maryam |

---

### Initial Access & Phishing

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| GoPhish | gophish | Open-source phishing simulation platform with campaign management, landing pages, and reporting | github.com/gophish/gophish |
| Evilginx2 | kgretzky | Adversary-in-the-middle phishing proxy for capturing session cookies and bypassing MFA | github.com/kgretzky/evilginx2 |
| CredSniper | ustayready | Phishing framework supporting 2FA/MFA bypass through real-time credential capture | github.com/ustayready/CredSniper |
| o365spray | 0xZDH | Username enumeration and password spraying toolkit targeting Microsoft 365 environments | github.com/0xZDH/o365spray |
| Ruler | sensepost | Exchange and Outlook attack toolkit; abuses MAPI/HTTP and Autodiscover for persistence and exploitation | github.com/sensepost/ruler |

---

### Command & Control

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| Sliver | BishopFox | Cross-platform adversary emulation C2 framework supporting mTLS, WireGuard, DNS, and HTTP/S implants | github.com/BishopFox/sliver |
| Havoc | HavocFramework | Modern C2 framework featuring the Demon agent with sleep obfuscation, indirect syscalls, and BOF support | github.com/HavocC2/Havoc |
| Merlin | Ne0nd0g | HTTP/2-based cross-platform C2 server and agent; supports JA3 fingerprint evasion | github.com/Ne0nd0g/merlin |
| Covenant | cobbr | .NET collaborative C2 framework with a web UI; supports Grunt implants and task chaining | github.com/cobbr/Covenant |
| SILENTTRINITY | byt3bl33d3r | Python/Boo language C2 that leverages .NET's DLR for in-memory payload execution | github.com/byt3bl33d3r/SILENTTRINITY |

---

### Credential Access

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| Mimikatz | gentilkiwi | Windows credential extraction -- the gold standard for LSASS dumping, pass-the-hash, and Kerberos attacks | github.com/gentilkiwi/mimikatz |
| Impacket | fortra (SecureAuth) | Python suite for Windows network protocol interaction; includes secretsdump, psexec, wmiexec, and more | github.com/fortra/impacket |
| Rubeus | GhostPack | C# Kerberos abuse toolkit; supports AS-REP roasting, Kerberoasting, ticket manipulation, and S4U abuse | github.com/GhostPack/Rubeus |
| CrackMapExec | mpgn (now byt3bl33d3r) | Swiss army knife for Active Directory environments: enumeration, spraying, execution, and lateral movement | github.com/mpgn/CrackMapExec |
| LaZagne | AlessandroZ | Credential recovery tool that extracts passwords stored by browsers, email clients, databases, and more | github.com/AlessandroZ/LaZagne |

---

### Lateral Movement & Discovery

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| BloodHound | BloodHoundAD | Active Directory attack path mapping using graph theory; identifies shortest path to Domain Admin | github.com/BloodHoundAD/BloodHound |
| PowerView | PowerShellMafia | PowerShell AD enumeration module from PowerSploit; enumerates users, groups, ACLs, and trust relationships | github.com/PowerShellMafia/PowerSploit |
| SharpHound | BloodHoundAD | C# BloodHound data collector; gathers AD object relationships for BloodHound analysis | github.com/BloodHoundAD/SharpHound |
| ADExplorer | Sysinternals | Microsoft Sysinternals AD viewer and snapshot tool; abused for offline AD enumeration | docs.microsoft.com/sysinternals |
| WMImplant | FortyNorthSecurity | WMI-based implant for lateral movement and persistence without writing to disk | github.com/FortyNorthSecurity/WMImplant |

---

### Defense Evasion & Payload Development

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| ScareCrow | optiv | Payload creation framework for bypassing EDR solutions through process injection and loader obfuscation | github.com/optiv/ScareCrow |
| Freeze | optiv | Payload toolkit focusing on AMSI bypass, ETW patching, and unhooking for EDR evasion | github.com/optiv/Freeze |
| Donut | TheWover | Converts .NET assemblies, VBScript, JScript, and EXE files into position-independent shellcode | github.com/TheWover/donut |
| BOF.NET | CCob | Run .NET assemblies within a Cobalt Strike Beacon Object File context without spawning a new process | github.com/CCob/BOF.NET |
| TartarusGate | trickster0 | Syscall-based AV/EDR evasion that dynamically resolves syscall numbers to bypass userland hooks | github.com/trickster0/TartarusGate |

---

### Cloud Attack Tools

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| Pacu | RhinoSecurityLabs | AWS exploitation framework with 45+ modules covering IAM privesc, data exfil, persistence, and more | github.com/RhinoSecurityLabs/pacu |
| ScoutSuite | nccgroup | Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud | github.com/nccgroup/ScoutSuite |
| Prowler | prowler-cloud | AWS, Azure, and GCP security assessments aligned to CIS benchmarks and compliance frameworks | github.com/prowler-cloud/prowler |
| AzureHound | BloodHoundAD | Azure AD and Azure resource attack path data collection for BloodHound analysis | github.com/BloodHoundAD/AzureHound |
| ROADtools | dirkjanm | Azure AD enumeration and attack toolkit; includes ROADrecon for tenant data collection and analysis | github.com/dirkjanm/ROADtools |
| Stratus Red Team | DataDog | Cloud attack technique atomic tests for AWS, Azure, GCP, and Kubernetes -- enables detection validation | github.com/DataDog/stratus-red-team |

---

### Web Application Testing

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| FFUF | ffuf | Fast web fuzzer written in Go; supports directory brute-forcing, parameter fuzzing, and virtual host discovery | github.com/ffuf/ffuf |
| Nuclei | ProjectDiscovery | Template-based fast vulnerability scanner with a community library of 9000+ detection templates | github.com/projectdiscovery/nuclei |
| Dalfox | hahwul | XSS parameter analysis tool with DOM-based and reflected XSS detection; supports blind XSS callback | github.com/hahwul/dalfox |
| SQLmap | sqlmapproject | Automated SQL injection detection and exploitation supporting all major database backends | github.com/sqlmapproject/sqlmap |
| JWT_Tool | ticarpi | JWT testing toolkit covering algorithm confusion, secret cracking, and injection attacks | github.com/ticarpi/jwt_tool |
| Corsy | s0md3v | CORS misconfiguration scanner that tests for origin reflection, null origin, and subdomain abuse | github.com/s0md3v/Corsy |

---

### Detection & Forensics Tools

| Tool | Author/Org | Description | GitHub |
|---|---|---|---|
| Velociraptor | Velocidex | Digital forensics and incident response platform with VQL query language for endpoint telemetry | github.com/Velocidex/velociraptor |
| Volatility 3 | volatilityfoundation | Memory forensics framework for Windows, Linux, and macOS; supports plugin-based analysis | github.com/volatilityfoundation/volatility3 |
| KAPE | EricZimmerman | Triage artifact collection and processing tool; collects Windows forensic artifacts and runs analysis modules | https://www.kroll.com/en/services/cyber-risk/incidents-intrusions-breaches/kroll-artifact-parser-extractor-kape |
| Chainsaw | WithSecureLabs | Fast Windows Event Log hunting and threat detection using Sigma rules and built-in patterns | github.com/WithSecureLabs/chainsaw |
| Hayabusa | Yamato-Security | Windows Event Log fast forensics and threat hunting tool with 4000+ Sigma-based detection rules | github.com/Yamato-Security/hayabusa |
