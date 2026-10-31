# Security Tools Catalog

A map of the security tool landscape by category, with the named tools in each and links to where this library covers them in depth. It is an orientation and lab-building aid, not an exhaustive or authoritative register: the ecosystem holds thousands of products and projects, and tools move between categories because many serve several functions. Tool names and categories reflect the landscape as of 2026, so verify a product's current name, owner, and capabilities against its vendor before relying on a detail.

Where a tool has a dedicated page here, its name links to it. The deepest coverage lives in [Security platforms](/platforms/README.md) for vendor products, [Command reference](/commands/README.md) for command-line tools, and [Vendor tools](/tools/README.md) for the existing tool pages.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security engineers and analysts orienting across the tool landscape or planning a lab

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 7 min (1,694 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to find the tools in a security category, you are planning a lab or toolchain, or you want to see which tools the library covers in depth

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Tool categories](#tool-categories), [Core enterprise security stack](#core-enterprise-security-stack), [Where the library goes deeper](#where-the-library-goes-deeper)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Security platforms](platforms/README.md), [Command reference](commands/README.md), [Enterprise Technology Inventory](ENTERPRISE_TECHNOLOGY_INVENTORY.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How to read this catalog

Each section groups tools by what they do. A linked name has a page in this library; an unlinked name is listed for completeness and orientation. Licensing is mixed: some entries are commercial platforms, others are open-source projects, command-line utilities, intelligence services, or frameworks. Use the [website](https://teamstarwolf.github.io/TeamStarWolf/) search to jump to any tool that has a page.

## Tool categories

| Domain | Primary purpose |
|---|---|
| Vulnerability management | Discover, assess, prioritize, and remediate vulnerabilities |
| CTEM and exposure management | Continuously discover, validate, and reduce exposure |
| Attack surface management | Identify externally and internally exposed assets |
| Network security | Inspect, segment, and protect network traffic |
| Endpoint security | Protect endpoints and detect malicious behavior |
| SIEM | Centralize, correlate, and analyze security events |
| SOAR | Automate investigations and response workflows |
| Threat intelligence | Collect and operationalize threat information |
| Vulnerability intelligence | Analyze CVEs, exploitation, and vulnerability risk |
| Penetration testing | Identify and validate exploitable weaknesses |
| Red and purple teaming | Simulate adversaries and validate defenses |
| Digital forensics and IR | Collect evidence, investigate, contain, and recover |
| Malware analysis and reverse engineering | Analyze malicious code, binaries, and firmware |
| Application and API security | Secure applications, APIs, and dependencies |
| Cloud, container, and Kubernetes security | Assess and protect cloud workloads and orchestration |
| Identity and Active Directory security | Protect accounts, credentials, privileges, and directories |
| Data security and DLP | Discover, classify, and protect sensitive data |
| Email and web security | Detect phishing and protect web applications |
| OT, ICS, IoT, and mobile | Secure industrial, embedded, and mobile systems |
| Cryptography and PKI | Protect encryption, keys, and certificates |
| GRC and compliance | Manage controls, risk, and audits |
| AI and LLM security | Assess and protect AI systems |

## Vulnerability, exposure, and threat management

| Group | Tools |
|---|---|
| Vulnerability scanners | [Nessus](/platforms/tenable.md), Tenable Security Center, [Qualys VMDR](/platforms/qualys.md), [Rapid7 InsightVM](/platforms/rapid7-insightvm.md), Greenbone and OpenVAS, [Nmap](/commands/nmap.md) NSE, Nuclei, Nikto, GVM |
| Exposure management and CTEM | [Tenable One](/platforms/tenable.md), Qualys Enterprise TruRisk, Rapid7 Exposure Command, XM Cyber, Pentera, Picus Security, Cymulate, SafeBreach, Horizon3.ai NodeZero |
| Attack surface management | Censys, Shodan, runZero, Microsoft Defender EASM, Cortex Xpanse, Bitsight, SecurityScorecard, Detectify, Intruder |
| Asset discovery and CAASM | Axonius, JupiterOne, runZero, Armis, Lansweeper, Device42, NetBox, ServiceNow CMDB |
| Vulnerability intelligence | VulnCheck, VulnDB, NVD, CVE.org, CISA KEV, FIRST EPSS, OSV, GitHub Advisory Database, Snyk Vulnerability DB |
| Remediation and patching | Microsoft Intune, Configuration Manager, Automox, [Tanium](/platforms/tanium.md), Ivanti Neurons, HCL BigFix, Action1, ManageEngine Patch Manager Plus, Ansible |
| Risk-based prioritization | Cisco Vulnerability Management (Kenna), Brinqa, Nucleus Security, Vulcan Cyber, DefectDojo |

See [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [CTEM Reference](/CTEM_REFERENCE.md), and [Scanner Platforms and Findings Catalog](/SCANNER_PLATFORMS_REFERENCE.md).

## Security operations and defense

| Group | Tools |
|---|---|
| SIEM | [Splunk Enterprise Security](/platforms/splunk.md), Microsoft Sentinel, Google SecOps, [IBM QRadar](/platforms/qradar.md), Elastic Security, Wazuh, Sumo Logic Cloud SIEM, LogRhythm, Graylog, OpenSearch Security Analytics |
| EDR and XDR | [CrowdStrike Falcon](/platforms/crowdstrike-falcon.md), [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md), SentinelOne Singularity, Cortex XDR, Sophos Intercept X, [Trend Vision One](/platforms/trend-micro.md), VMware Carbon Black, Elastic Defend, Trellix |
| SOAR | [Cortex XSOAR](/platforms/cortex-xsoar.md), Splunk SOAR, Microsoft Sentinel Playbooks, [Tines](/platforms/tines.md), Torq, Swimlane, Shuffle, Tracecat, Fortinet FortiSOAR |
| NDR, IDS, and IPS | Zeek, Suricata, Snort, Security Onion, Corelight, Vectra AI, Darktrace, ExtraHop Reveal(x), Arkime |
| Detection engineering | Sigma, YARA, ATT&CK Navigator, DeTT&CT, Chainsaw, Hayabusa, Sysmon, osquery, RITA, Zircolite |
| Threat hunting | Velociraptor, GRR Rapid Response, LimaCharlie, Fleet, osquery, Sysmon, KAPE, Elastic Security |
| Case management | TheHive, DFIR-IRIS, ServiceNow Security Incident Response, Jira, RTIR |

See [Detection and response](/hubs/detection-and-response.md) and [Splunk Enterprise Security](/platforms/splunk.md).

## Threat intelligence and adversary analysis

| Group | Tools |
|---|---|
| Threat intelligence platforms | MISP, OpenCTI, ThreatConnect, Anomali, Recorded Future, ThreatQuotient, EclecticIQ, Microsoft Defender Threat Intelligence |
| Threat research services | VirusTotal, AlienVault OTX, GreyNoise, AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox, ANY.RUN, Hybrid Analysis |
| OSINT | Maltego, SpiderFoot, Recon-ng, theHarvester, Sherlock, Maigret, Amass, Shodan, Censys, FOCA |
| Adversary knowledge | MITRE ATT&CK, MITRE D3FEND, MITRE CAPEC, Atomic Red Team, ATT&CK Navigator, CTID resources |
| Dark web intelligence | Flashpoint, Recorded Future, Searchlight Cyber, DarkOwl, Intel 471, KELA |

See [Threat intelligence](/hubs/threat-intelligence.md) and, for the MITRE frameworks, [Frameworks](/mitre/README.md).

## Offensive security and penetration testing

| Group | Tools |
|---|---|
| Network reconnaissance | [Nmap](/commands/nmap.md), Masscan, RustScan, Naabu, ZMap, Netcat, Socat, arp-scan, fping |
| Web testing | Burp Suite, OWASP ZAP, [sqlmap](/commands/sqlmap.md), Nikto, ffuf, [Gobuster](/commands/gobuster.md), Feroxbuster, dirsearch, Wfuzz, WPScan |
| Exploitation frameworks | [Metasploit Framework](/commands/metasploit.md), Core Impact, Immunity CANVAS, ExploitDB, SearchSploit |
| Red team and adversary emulation | MITRE CALDERA, Atomic Red Team, Infection Monkey, Prelude Operator, Sliver, Mythic, Cobalt Strike, Havoc |
| Active Directory assessment | BloodHound, SharpHound, PingCastle, Purple Knight, ADRecon, Certipy, NetExec, Impacket |
| Password auditing | [Hashcat](/commands/hashcat.md), John the Ripper, Hydra, Medusa, Ncrack, CeWL, HashID |
| Wireless auditing | Aircrack-ng, Kismet, Wireshark, Bettercap, hcxdumptool, Wifite, Reaver |
| Protocol analysis | [Wireshark](/commands/tshark.md), tcpdump, TShark, Scapy, mitmproxy, Ettercap, NetworkMiner |

See [Offensive security](/hubs/offensive-security.md). These are documented for authorized testing only.

## Application, API, and software supply chain security

| Group | Tools |
|---|---|
| SAST | Semgrep, Checkmarx, Fortify SCA, Veracode, SonarQube, CodeQL, [Snyk Code](/platforms/snyk.md), Bearer |
| DAST | OWASP ZAP, Burp Suite, [Invicti](/platforms/invicti.md), Acunetix, HCL AppScan, StackHawk, Bright Security |
| SCA | Snyk Open Source, Mend, Black Duck, OWASP Dependency-Check, Dependabot, Renovate, OSV-Scanner |
| API security | 42Crunch, Salt Security, Traceable, Noname Security, Akamai API Security, Wallarm, Postman, Schemathesis, RESTler |
| Secrets scanning | Gitleaks, TruffleHog, GitGuardian, detect-secrets, Talisman |
| SBOM and supply chain | Syft, Grype, CycloneDX, SPDX, Dependency-Track, Sigstore Cosign, in-toto, GUAC |
| Infrastructure as code | Checkov, tfsec, Terrascan, KICS, Trivy, Snyk IaC, CloudFormation Guard |

See [Application Security Testing](/APPSEC_TESTING_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md), and [Snyk](/platforms/snyk.md).

## Cloud, container, and identity security

| Group | Tools |
|---|---|
| CNAPP and CSPM | [Wiz](/platforms/wiz.md), Orca Security, Prisma Cloud, Microsoft Defender for Cloud, Lacework FortiCNAPP, AWS Security Hub, Prowler, ScoutSuite |
| Kubernetes security | Falco, Kubescape, kube-bench, kube-hunter, Trivy, NeuVector, Tetragon, Kyverno, OPA Gatekeeper |
| Cloud threat detection | Amazon GuardDuty, Google Security Command Center, Microsoft Defender for Cloud, AWS Detective |
| IAM and SSO | [Microsoft Entra ID](/platforms/entra-id.md), Okta, Ping Identity, [CyberArk](/platforms/cyberark.md), Keycloak, Auth0, JumpCloud |
| PAM | CyberArk PAM, BeyondTrust, Delinea, HashiCorp Vault, One Identity Safeguard |
| Identity threat detection | Microsoft Defender for Identity, CrowdStrike Falcon Identity Protection, Semperis Directory Services Protector, Silverfort |
| SaaS security | AppOmni, Adaptive Shield, Obsidian Security, Microsoft Defender for Cloud Apps |

See [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md), [kubectl](/commands/kubectl.md), and [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md).

## Forensics, malware, and incident response

| Group | Tools |
|---|---|
| Digital forensics | Autopsy, The Sleuth Kit, FTK, EnCase, Magnet AXIOM, X-Ways Forensics, SIFT Workstation |
| Memory forensics | Volatility 3, Rekall, MemProcFS, WinPmem, LiME |
| Endpoint forensics | KAPE, Velociraptor, Eric Zimmerman Tools, Plaso and log2timeline, Timesketch |
| Malware sandboxes | Cuckoo Sandbox, CAPE Sandbox, ANY.RUN, Joe Sandbox, Hybrid Analysis |
| Reverse engineering | Ghidra, IDA, Binary Ninja, Radare2, Cutter, x64dbg, WinDbg, [GDB](/commands/gdb.md), Frida |
| Malware detection | YARA, ClamAV, LOKI, THOR, capa, FLOSS, PEStudio, Detect It Easy |
| Network forensics | Wireshark, NetworkMiner, Arkime, Zeek, tcpdump, Brim and Zui |

See [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) and the detection-and-response forensics pages.

## Specialized and emerging domains

| Group | Tools |
|---|---|
| OT, ICS, and SCADA | Dragos Platform, Claroty xDome, Nozomi Networks Guardian, Armis Centrix, Tenable OT Security, CISA Malcolm |
| IoT and firmware | Binwalk, Firmwalker, EMBA, FACT, Ghidra, QEMU, Firmware Analysis Toolkit |
| Mobile security | MobSF, Frida, Objection, JADX, apktool, Drozer, Burp Suite |
| AI and LLM security | Garak, PyRIT, Giskard, promptfoo, NVIDIA NeMo Guardrails, Lakera Guard, Protect AI tools |
| Cryptography and PKI | OpenSSL, HashiCorp Vault, Smallstep step-ca, Certbot, acme.sh, Keyfactor, Venafi |
| Data security and DSPM | Microsoft Purview, Varonis, BigID, Cyera, [Forcepoint](/platforms/forcepoint.md) DLP, Symantec DLP |
| GRC and compliance | ServiceNow GRC, Archer, OneTrust, Vanta, Drata, AuditBoard, OpenSCAP, Lynis, CIS-CAT |
| Security training and labs | Hack The Box, TryHackMe, PortSwigger Web Security Academy, OWASP Juice Shop, DVWA, Metasploitable, DetectionLab |

See [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md), [AI Security Reference](/AI_SECURITY_REFERENCE.md), [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md), and [AI and emerging tech](/hubs/ai-and-emerging-tech.md).

## Essential open-source toolkit

A starting set for a security laboratory or research environment, all open source: [Nmap](/commands/nmap.md) for discovery, Wireshark for protocol analysis, Nuclei for template-based scanning, Greenbone for infrastructure assessment, Wazuh for SIEM and endpoint monitoring, Security Onion for network monitoring, MISP and OpenCTI for threat intelligence, MITRE CALDERA for adversary emulation, OWASP ZAP for web testing, Trivy for cloud-native scanning, Velociraptor for endpoint investigation, Ghidra for reverse engineering, Falco for runtime security, and Prowler for cloud assessment.

## Where the library goes deeper

- Vendor platforms, including many above, have dedicated pages in [Security platforms](/platforms/README.md).
- Command-line tools (Nmap, Metasploit, sqlmap, gobuster, hashcat, tshark, GDB, and more) are in [Command reference](/commands/README.md).
- The existing [Vendor tools](/tools/README.md) and [AI tooling](/ai-tooling/README.md) sections carry further tool pages.
- For organizing study and labs around these tools, see the [IT Domains and Specializations](/IT_DOMAINS_REFERENCE.md) map and the [Learning paths](/disciplines/README.md).

## Core enterprise security stack

A large program rarely buys one product per category and stops. It standardizes on a leading option for each capability, then carries deliberate overlap. The common enterprise choices as of 2026, as a representative market view rather than a ranking:

| Capability | Common enterprise choices |
|---|---|
| ITSM and CMDB | ServiceNow |
| Vulnerability management | Tenable, Qualys, Rapid7 |
| Exposure management (CTEM) | Tenable One, XM Cyber, CrowdStrike Falcon Exposure Management |
| Endpoint EDR and XDR | CrowdStrike Falcon, Microsoft Defender, SentinelOne |
| SIEM | Splunk, Microsoft Sentinel, Google Security Operations |
| SOAR | Cortex XSOAR, Splunk SOAR, Tines |
| Network, firewall, and SASE | Palo Alto Networks, Cisco, Fortinet, Zscaler |
| Identity and privileged access | Microsoft Entra ID, Okta, CyberArk |
| Cloud security (CNAPP) | Wiz, Prisma Cloud, Microsoft Defender for Cloud |
| Application security | Snyk, Checkmarx, Veracode |
| Threat intelligence | Recorded Future, Google Threat Intelligence (Mandiant), CrowdStrike |
| Data security and DLP | Microsoft Purview, Varonis, Forcepoint |
| Email security | Microsoft Defender for Office 365, Proofpoint, Abnormal AI |
| OT and ICS | Dragos, Claroty, Nozomi Networks |
| Patch and endpoint management | Microsoft Intune, Tanium, HCL BigFix, Automox |
| GRC and risk | ServiceNow Integrated Risk Management, Archer, AuditBoard |

These layer into an architecture: governance and risk at the top, then asset and exposure, identity, endpoint and network, cloud and application, threat intelligence, data protection, security operations and incident response, and remediation and IT operations at the base. The overlap is the point, because defense in depth means more than one control in the path, which is the model in the [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md).

## Related pages

- [Security platforms](/platforms/README.md)
- [Command reference](/commands/README.md)
- [Vendor tools](/tools/README.md)
- [Enterprise Technology Inventory](/ENTERPRISE_TECHNOLOGY_INVENTORY.md)
- [IT Domains and Specializations](/IT_DOMAINS_REFERENCE.md)
- [Reference Index](/INDEX.md)

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [GRC and security program](/hubs/grc-and-security-program.md)

<!-- related:end -->
