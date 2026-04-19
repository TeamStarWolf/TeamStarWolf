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

## Related Resources
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — tools mapped to NIST controls and pipeline stages
- [Controls Mapping](CONTROLS_MAPPING.md) — full vendor → NIST 800-53 → ATT&CK chain
- [ATT&CK Navigator](navigator/) — technique coverage visualization
- [Starred Repositories](STARRED_REPOS.md) — curated GitHub tool repositories
- [Hands-On Labs](LABS.md) — practice environments for each category
