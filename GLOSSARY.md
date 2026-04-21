# Security Glossary

Common terms, acronyms, and concepts across cybersecurity disciplines. Use `Ctrl+F` (or the search bar) to find specific terms.

---

## A

| Term | Definition |
|---|---|
| **ACL** | Access Control List — a list of permissions attached to a resource specifying which users or system processes may access it |
| **AES** | Advanced Encryption Standard — symmetric block cipher (128/192/256-bit keys); FIPS-approved |
| **APT** | Advanced Persistent Threat — a prolonged, targeted cyberattack where an attacker gains unauthorized access and remains undetected |
| **ASM** | Attack Surface Management — continuous discovery and inventory of an organization's exposed assets |
| **ATO** | Authority to Operate — US federal authorization granted by an Authorizing Official (AO) after RMF assessment |
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge — MITRE framework documenting adversary behavior |
| **AXFR** | DNS Zone Transfer — DNS query type used to replicate DNS records; can expose full internal DNS when misconfigured |

---

## B

| Term | Definition |
|---|---|
| **BAS** | Breach and Attack Simulation — automated tools that test security controls by simulating adversary techniques (see Caldera, AttackIQ) |
| **BEC** | Business Email Compromise — social engineering attacks targeting organizations via fraudulent emails, typically requesting wire transfers or credential changes |
| **BGP** | Border Gateway Protocol — the routing protocol of the internet; BGP hijacking redirects internet traffic |
| **BYOD** | Bring Your Own Device — policy allowing personal devices to access corporate resources |

---

## C

| Term | Definition |
|---|---|
| **C2 / C&C** | Command and Control — infrastructure used by threat actors to communicate with compromised systems |
| **CA** | Certificate Authority — entity that issues digital certificates; part of PKI |
| **CASB** | Cloud Access Security Broker — security control point between users and cloud services, enforcing policy |
| **CERT** | Computer Emergency Response Team — team handling cybersecurity incidents; also used as a generic term for CERTs/CSIRTs |
| **CIEM** | Cloud Infrastructure Entitlement Management — tools for managing and rightsizing cloud identities and permissions |
| **CNAPP** | Cloud-Native Application Protection Platform — unified platform combining CSPM, CWPP, CIEM, and DSPM |
| **CSIRT** | Computer Security Incident Response Team — the team responsible for responding to security incidents |
| **CSPM** | Cloud Security Posture Management — continuous monitoring and remediation of cloud resource misconfigurations |
| **CTI** | Cyber Threat Intelligence — processed, analyzed intelligence about threats to inform defensive decisions |
| **CVE** | Common Vulnerabilities and Exposures — public database of known security vulnerabilities (NVD/MITRE) |
| **CVSS** | Common Vulnerability Scoring System — standardized scoring of vulnerability severity (0.0–10.0) |
| **CWPP** | Cloud Workload Protection Platform — security for cloud-hosted workloads (VMs, containers, serverless) |

---

## D

| Term | Definition |
|---|---|
| **DAST** | Dynamic Application Security Testing — testing running applications for vulnerabilities (OWASP ZAP, Burp Suite) |
| **DLP** | Data Loss Prevention — tools and policies that detect and prevent unauthorized data exfiltration |
| **DMZ** | Demilitarized Zone — network segment between internal network and the internet, hosting public-facing services |
| **DNS** | Domain Name System — translates domain names to IP addresses; DNS security includes DNSSEC, DNS sinkholes, RPZ |
| **DNSSEC** | DNS Security Extensions — cryptographic signing of DNS records to prevent spoofing |
| **DoS / DDoS** | Denial of Service / Distributed Denial of Service — attack that makes a service unavailable by overwhelming it |
| **DKIM** | DomainKeys Identified Mail — email authentication using cryptographic signatures to verify sender domain |
| **DMARC** | Domain-based Message Authentication, Reporting and Conformance — email policy that builds on SPF and DKIM |
| **DSPM** | Data Security Posture Management — discovery and classification of data across cloud environments, with risk assessment |

---

## E

| Term | Definition |
|---|---|
| **EDR** | Endpoint Detection and Response — security solution for monitoring, detecting, and responding to endpoint threats |
| **EPSS** | Exploit Prediction Scoring System — probability score (0–1) predicting likelihood a CVE will be exploited in the wild |
| **EternalBlue** | NSA-developed exploit for SMBv1 (CVE-2017-0144); used in WannaCry and NotPetya ransomware |
| **ELK / ELK Stack** | Elasticsearch, Logstash, Kibana — open source log aggregation and analytics stack (now OpenSearch/Elastic) |

---

## F

| Term | Definition |
|---|---|
| **FIDO2** | Fast Identity Online 2 — open standard for passwordless authentication using public key cryptography (WebAuthn, hardware tokens) |
| **FIM** | File Integrity Monitoring — detecting unauthorized changes to files and directories |
| **FISMA** | Federal Information Security Modernization Act — US law requiring federal agencies to implement information security programs |
| **FedRAMP** | Federal Risk and Authorization Management Program — US government cloud security authorization program |
| **FOFA** | Cyberspace search engine (similar to Shodan/Censys) widely used in Asia-Pacific threat intelligence |

---

## G

| Term | Definition |
|---|---|
| **GRC** | Governance, Risk, and Compliance — umbrella term for organizational cybersecurity governance programs |
| **GDPR** | General Data Protection Regulation — EU privacy law governing personal data processing (effective May 2018) |

---

## H

| Term | Definition |
|---|---|
| **HSM** | Hardware Security Module — physical device that safeguards and manages cryptographic keys |
| **HIPAA** | Health Insurance Portability and Accountability Act — US law protecting patient health information (PHI) |
| **HoneyPot / HoneyToken** | Decoy assets (servers, credentials, files) deployed to detect and study attacker behavior |
| **HTTP Strict Transport Security (HSTS)** | Web policy forcing HTTPS connections to prevent downgrade attacks |

---

## I

| Term | Definition |
|---|---|
| **IAM** | Identity and Access Management — framework for managing digital identities and controlling access |
| **ICS** | Industrial Control System — systems controlling physical processes (SCADA, DCS, PLCs) |
| **IDS / IPS** | Intrusion Detection/Prevention System — monitors network/host traffic; IPS also blocks threats |
| **IOC** | Indicator of Compromise — artifact (IP, domain, hash, URL) associated with malicious activity |
| **IOA** | Indicator of Attack — behavioral patterns indicating an attack in progress (vs. IOC which is post-compromise) |
| **ISMS** | Information Security Management System — systematic approach to managing information security risks (ISO 27001) |

---

## J

| Term | Definition |
|---|---|
| **JIT** | Just-In-Time — access provisioning model granting access only when needed and removing it afterward |
| **JWT** | JSON Web Token — compact, self-contained token format used for authentication and information exchange |

---

## K

| Term | Definition |
|---|---|
| **KEV** | Known Exploited Vulnerabilities — CISA catalog of CVEs known to be exploited in the wild (must-patch list) |
| **Kerberoasting** | Attack technique requesting Kerberos service tickets and cracking them offline to recover service account passwords (T1558.003) |
| **KMS** | Key Management Service — service for creating, managing, and controlling cryptographic keys |

---

## L

| Term | Definition |
|---|---|
| **LAPS** | Local Administrator Password Solution — Microsoft tool that randomizes and rotates local admin passwords |
| **LDAP** | Lightweight Directory Access Protocol — protocol for accessing and managing directory services (Active Directory) |
| **Lateral Movement** | Techniques used by attackers to progressively move through a network after initial compromise (ATT&CK TA0008) |
| **LOLBAS** | Living Off the Land Binaries And Scripts — using legitimate system tools for malicious purposes to evade detection |
| **LSASS** | Local Security Authority Subsystem Service — Windows process targeted by credential dumping attacks (e.g., Mimikatz) |

---

## M

| Term | Definition |
|---|---|
| **MASVS** | Mobile Application Security Verification Standard — OWASP standard for mobile app security requirements |
| **MFA** | Multi-Factor Authentication — authentication requiring two or more verification factors |
| **MITRE ATT&CK** | Knowledge base of adversary tactics and techniques based on real-world observations |
| **MITRE ENGAGE** | Framework for adversary engagement, deception, and denial operations |
| **MitM / AitM** | Man-in-the-Middle / Adversary-in-the-Middle — intercepting and potentially altering communications between parties |
| **MTTR** | Mean Time to Respond/Remediate — average time between detecting an incident and resolving it |

---

## N

| Term | Definition |
|---|---|
| **NGFW** | Next-Generation Firewall — firewall with deep packet inspection, application awareness, and integrated IPS |
| **NDR** | Network Detection and Response — monitoring network traffic for threats with detection and response capabilities |
| **NIST** | National Institute of Standards and Technology — US agency that publishes cybersecurity standards (800-53, CSF, RMF) |
| **NVD** | National Vulnerability Database — NIST-maintained database of CVEs with CVSS scores |

---

## O

| Term | Definition |
|---|---|
| **OAuth 2.0** | Authorization framework for delegating access without sharing credentials |
| **OIDC** | OpenID Connect — identity layer on top of OAuth 2.0 for authentication |
| **OT** | Operational Technology — hardware and software controlling physical processes (vs. IT) |
| **OSINT** | Open Source Intelligence — gathering intelligence from publicly available sources |
| **OWASP** | Open Web Application Security Project — nonprofit producing freely available web security resources |

---

## P

| Term | Definition |
|---|---|
| **PAM** | Privileged Access Management — controls for securing, managing, and monitoring privileged accounts |
| **PCI DSS** | Payment Card Industry Data Security Standard — security standard for organizations handling payment cards |
| **PII** | Personally Identifiable Information — data that can identify an individual |
| **PKI** | Public Key Infrastructure — framework for managing digital certificates and public/private key pairs |
| **POA&M** | Plan of Action and Milestones — document tracking known weaknesses and remediation plans (US federal) |
| **Post-Quantum Cryptography** | Cryptographic algorithms resistant to attacks by quantum computers (NIST PQC finalists: CRYSTALS-Kyber, CRYSTALS-Dilithium) |

---

## R

| Term | Definition |
|---|---|
| **RBAC** | Role-Based Access Control — access control based on user roles rather than individual identities |
| **RCE** | Remote Code Execution — vulnerability class allowing an attacker to run arbitrary code on a target system |
| **RMF** | Risk Management Framework — NIST process for authorizing federal systems (see NIST SP 800-37) |
| **RPO / RTO** | Recovery Point Objective / Recovery Time Objective — disaster recovery targets for data loss and downtime tolerance |
| **RSA** | Rivest–Shamir–Adleman — public key cryptosystem widely used for secure data transmission |

---

## S

| Term | Definition |
|---|---|
| **SAML** | Security Assertion Markup Language — XML-based standard for exchanging authentication and authorization data |
| **SAST** | Static Application Security Testing — analyzing source code without execution for security vulnerabilities |
| **SBOM** | Software Bill of Materials — inventory of software components, versions, and dependencies |
| **SCA** | Software Composition Analysis — identifying open source components and their known vulnerabilities |
| **SIEM** | Security Information and Event Management — collects, correlates, and alerts on security events from multiple sources |
| **SLSA** | Supply-chain Levels for Software Artifacts — Google-originated framework for software build integrity |
| **SMB** | Server Message Block — Windows file sharing protocol; SMBv1 was exploited by EternalBlue |
| **SOAR** | Security Orchestration, Automation and Response — platforms automating security operations workflows |
| **SOC** | Security Operations Center — team and facility monitoring for and responding to security threats |
| **SOC 2** | System and Organization Controls 2 — AICPA audit framework for service organizations |
| **SPF** | Sender Policy Framework — email authentication method specifying authorized mail servers for a domain |
| **SQL Injection (SQLi)** | Attack inserting malicious SQL into queries, enabling unauthorized database access (OWASP Top 10 #3) |
| **SSRF** | Server-Side Request Forgery — vulnerability tricking a server to make requests to unintended locations (OWASP Top 10 #7) |
| **STIX / TAXII** | Structured Threat Information eXpression / Trusted Automated eXchange of Intelligence Information — standards for threat intelligence sharing |
| **SWG** | Secure Web Gateway — web proxy enforcing policy, URL filtering, and malware inspection |

---

## T

| Term | Definition |
|---|---|
| **TI** | Threat Intelligence — evidence-based knowledge about adversaries enabling informed defensive decisions |
| **TLS** | Transport Layer Security — cryptographic protocol providing secure communications over networks (successor to SSL) |
| **TLP** | Traffic Light Protocol — information sharing classification: TLP:RED (very limited), TLP:AMBER, TLP:GREEN, TLP:WHITE/CLEAR |
| **TTP** | Tactics, Techniques, and Procedures — describes how a threat actor operates (see MITRE ATT&CK) |
| **TPM** | Trusted Platform Module — hardware chip storing cryptographic keys and providing hardware root of trust |
| **Threat Hunting** | Proactive search through networks and data to detect threats evading automated controls |

---

## U

| Term | Definition |
|---|---|
| **UEBA** | User and Entity Behavior Analytics — detecting anomalies in user/entity behavior through ML and statistical analysis |
| **UEFI** | Unified Extensible Firmware Interface — firmware interface between OS and hardware; successor to BIOS |
| **UPN** | User Principal Name — Active Directory format for user accounts (user@domain.com) |

---

## V

| Term | Definition |
|---|---|
| **VPN** | Virtual Private Network — encrypted tunnel for secure remote access; increasingly replaced by ZTNA |
| **VEX** | Vulnerability Exploitability eXchange — standard for communicating exploitability context for vulnerabilities in SBOMs |

---

## W

| Term | Definition |
|---|---|
| **WAF** | Web Application Firewall — filters HTTP/S traffic to protect web apps from attacks (SQLi, XSS, CSRF) |
| **WAAP** | Web Application and API Protection — evolved WAF covering APIs, bots, and DDoS (e.g., Cloudflare, Fastly) |
| **WMI** | Windows Management Instrumentation — Windows feature abused for lateral movement and persistence (T1047) |
| **WPA3** | Wi-Fi Protected Access 3 — latest Wi-Fi security standard with enhanced encryption (SAE replaces PSK) |

---

## X

| Term | Definition |
|---|---|
| **XDR** | Extended Detection and Response — unified threat detection and response across endpoints, network, cloud, and email |
| **XML External Entity (XXE)** | Vulnerability in XML parsers that can expose files, SSRF, or RCE (OWASP Top 10 #5) |
| **XSS** | Cross-Site Scripting — injecting malicious scripts into web pages viewed by other users (OWASP Top 10 #3) |

---

## Z

| Term | Definition |
|---|---|
| **Zero Day (0day)** | Vulnerability unknown to the vendor with no available patch; highly valuable to both attackers and defenders |
| **Zero Trust** | Security model requiring continuous verification of every user, device, and request regardless of network location |
| **ZTNA** | Zero Trust Network Access — replaces VPN with identity-aware, least-privilege access to applications |

---

## Common Acronym Reference

| Acronym | Full Form |
|---|---|
| AES | Advanced Encryption Standard |
| APT | Advanced Persistent Threat |
| ATO | Authority to Operate |
| BAS | Breach and Attack Simulation |
| BEC | Business Email Compromise |
| CASB | Cloud Access Security Broker |
| CIEM | Cloud Infrastructure Entitlement Management |
| CNAPP | Cloud-Native Application Protection Platform |
| CSPM | Cloud Security Posture Management |
| CTI | Cyber Threat Intelligence |
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| CWPP | Cloud Workload Protection Platform |
| DAST | Dynamic Application Security Testing |
| DLP | Data Loss Prevention |
| DSPM | Data Security Posture Management |
| EDR | Endpoint Detection and Response |
| EPSS | Exploit Prediction Scoring System |
| FIDO2 | Fast Identity Online 2 |
| FIM | File Integrity Monitoring |
| GRC | Governance, Risk, and Compliance |
| HSM | Hardware Security Module |
| IAM | Identity and Access Management |
| ICS | Industrial Control System |
| IDS/IPS | Intrusion Detection/Prevention System |
| IOC | Indicator of Compromise |
| IOA | Indicator of Attack |
| ISMS | Information Security Management System |
| JIT | Just-In-Time |
| KEV | Known Exploited Vulnerabilities |
| LOLBAS | Living Off the Land Binaries And Scripts |
| MFA | Multi-Factor Authentication |
| MTTR | Mean Time to Respond |
| NDR | Network Detection and Response |
| NGFW | Next-Generation Firewall |
| OSINT | Open Source Intelligence |
| OT | Operational Technology |
| PAM | Privileged Access Management |
| PKI | Public Key Infrastructure |
| POA&M | Plan of Action and Milestones |
| RBAC | Role-Based Access Control |
| RCE | Remote Code Execution |
| SAML | Security Assertion Markup Language |
| SAST | Static Application Security Testing |
| SBOM | Software Bill of Materials |
| SCA | Software Composition Analysis |
| SIEM | Security Information and Event Management |
| SLSA | Supply-chain Levels for Software Artifacts |
| SOAR | Security Orchestration, Automation and Response |
| SOC | Security Operations Center |
| SPF | Sender Policy Framework |
| STIX/TAXII | Structured Threat Intelligence eXchange / Trusted Automated eXchange |
| TLP | Traffic Light Protocol |
| TTP | Tactics, Techniques, and Procedures |
| TPM | Trusted Platform Module |
| UEBA | User and Entity Behavior Analytics |
| VEX | Vulnerability Exploitability eXchange |
| WAF | Web Application Firewall |
| XDR | Extended Detection and Response |
| ZTNA | Zero Trust Network Access |

---

## Additional Terms

### Offensive / Attack Terms

| Term | Definition |
|---|---|
| **AiTM (Adversary-in-the-Middle)** | Phishing attack that proxies authentication between victim and legitimate site, capturing session tokens even after MFA — used by Evilginx3 and similar tools |
| **AS-REP Roasting** | Attack targeting Kerberos accounts with pre-authentication disabled; attacker requests an AS-REP encrypted with user's password hash, then cracks offline |
| **BFLA (Broken Function Level Authorization)** | API vulnerability where a lower-privileged user can invoke administrative functions; unauthorized vertical privilege escalation via API endpoints |
| **BOLA (Broken Object Level Authorization)** | API vulnerability where a user can access another user's objects by manipulating ID parameters; most common API vulnerability (OWASP API #1) |
| **CRTO** | Certified Red Team Operator — practical red team certification by Zero-Point Security; Cobalt Strike focused; 48-hour lab exam |
| **DCSync** | Post-exploitation technique using legitimate AD replication (drsuapi) to extract password hashes from domain controllers without directly accessing NTDS.dit |
| **DGA (Domain Generation Algorithm)** | Malware technique generating hundreds of pseudo-random domain names daily; only the attacker knows which are registered, making C2 blocking difficult |
| **ESC1-ESC8** | Categories of Active Directory Certificate Services (ADCS) misconfigurations enabling privilege escalation and authentication bypass; discovered by SpecterOps researchers |
| **FGSM (Fast Gradient Sign Method)** | Single-step adversarial example attack; perturbs input by one gradient step in the direction of maximum loss |
| **Golden Ticket** | Kerberos attack using the KRBTGT account hash to forge Ticket Granting Tickets (TGTs) valid for any user, including Domain Admin, for up to 10 years |
| **LLMNR Poisoning** | Attack exploiting Link-Local Multicast Name Resolution to intercept network name resolution requests and capture NTLMv2 hashes; countered by Responder tool |
| **MFA Fatigue** | Social engineering attack flooding a target with MFA push notifications until they approve one out of annoyance; used by Scattered Spider and Lapsus$ |
| **Pass-the-Hash (PtH)** | Using a captured NTLM hash directly for authentication without needing the plaintext password |
| **Pass-the-Ticket (PtT)** | Using a stolen Kerberos ticket (TGT or TGS) directly for authentication without knowing the password |
| **RollJam** | RF attack by Samy Kamkar that captures rolling-code key fob signals by jamming while recording; attacker retains valid unused code for replay |
| **Silver Ticket** | Kerberos attack using a service account's hash to forge service tickets for a specific service; more targeted than Golden Ticket but doesn't require KRBTGT |
| **SPN (Service Principal Name)** | AD attribute registering a service for Kerberos authentication; accounts with SPNs are targets for Kerberoasting |
| **Unconstrained Delegation** | AD configuration allowing a service account to impersonate any user to any service; the most dangerous delegation type; exploited via SpoolSample/PrinterBug |

### Defensive / Blue Team Terms

| Term | Definition |
|---|---|
| **ASR Rules (Attack Surface Reduction)** | Windows Defender feature blocking specific behaviors commonly used by malware (Office spawning child processes, LSASS credential access) independent of signatures |
| **ATT&CK Evaluations** | MITRE annual testing of commercial EDR vendors against real APT techniques; results published at attackevals.mitre-engenuity.org |
| **Canary Token** | Lightweight honeytoken (URL, file, credential) that fires an alert when accessed; used to detect intruders accessing areas they shouldn't |
| **DAM (Database Activity Monitoring)** | Records all SQL queries against databases at network/agent level; detects insider threats, privilege abuse, and data exfiltration |
| **FAIR Model** | Factor Analysis of Information Risk — quantitative framework for modeling cyber risk in financial terms (Annual Loss Expectancy = Loss Event Frequency × Loss Magnitude) |
| **Honeynet** | Network of honeypots and decoy systems designed to attract and study attackers while protecting real assets |
| **JA3/JA3S** | TLS fingerprinting method based on client (JA3) and server (JA3S) hello parameters; used to identify specific TLS clients (Cobalt Strike beacons, malware families) |
| **Malleable C2** | Cobalt Strike and Sliver feature allowing complete customization of beacon network traffic to mimic legitimate applications; makes static IOC detection ineffective |
| **MTD (Maximum Tolerable Downtime)** | Maximum period a business process can be disrupted before unacceptable consequences occur; drives RPO/RTO requirements |
| **OCSF (Open Cybersecurity Schema Framework)** | Open-source schema for normalizing security event data across vendors; enables interoperability between SIEM and security tools |
| **PAW (Privileged Access Workstation)** | Dedicated hardened device used only for administrative tasks; isolated from internet browsing and email to prevent credential theft |
| **RPKI (Resource Public Key Infrastructure)** | System for cryptographically verifying BGP route origin announcements; prevents BGP hijacking attacks |
| **ROSI (Return on Security Investment)** | Financial metric calculating security investment value: (Risk Reduction × Asset Value) - Control Cost; used to justify security budgets |
| **SCIM (System for Cross-domain Identity Management)** | Standard protocol for automating user provisioning between identity providers and SaaS applications |
| **Sigma** | Generic, open-source SIEM rule format that can be converted to Splunk SPL, KQL, Elastic EQL, and other platform-specific query languages |
| **Tiered Administration Model** | Active Directory security architecture separating administrator accounts into tiers (0=DCs, 1=Servers, 2=Workstations) to prevent credential theft across tiers |
| **VAP (Very Attacked People)** | Proofpoint metric identifying employees receiving the most targeted, sophisticated attacks; used to prioritize additional security controls |

---

## Related Resources
- [Security Frameworks Reference](FRAMEWORKS.md) — framework comparisons and mappings
- [Security Tools Reference](TOOLS.md) — tool quick-reference by category
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — pipeline stages and vendor mapping
- [Disciplines](disciplines/threat-intelligence.md) — discipline pages with detailed terminology context
