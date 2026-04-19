# Penetration Testing

> Authorized, simulated cyberattack on a system to identify exploitable vulnerabilities before real adversaries do. Governed by a scope document and Rules of Engagement (RoE), covering external/internal/web app/mobile/wireless/social engineering, and more.

## What Penetration Testers Do

- Conduct authorized attacks against client systems to discover and exploit vulnerabilities
- Define scope, objectives, and testing boundaries in collaboration with clients
- Perform passive and active reconnaissance to map the attack surface
- Exploit identified vulnerabilities to demonstrate real-world impact
- Escalate privileges and move laterally to assess the depth of compromise
- Document all findings with evidence, impact ratings, and actionable remediation guidance
- Deliver clear reports tailored to both executive and technical audiences
- Retest remediated vulnerabilities to verify fixes are effective

---

## Types of Penetration Tests

| Type | Target | Typical Duration | Deliverable |
|---|---|---|---|
| External Network | Internet-facing systems | 1–2 weeks | Technical report + executive summary |
| Internal Network | Systems inside the perimeter | 2–4 weeks | Technical report + executive summary |
| Web Application | Single web application | 1–2 weeks | Technical report + OWASP-mapped findings |
| Mobile Application | iOS / Android application | 1–2 weeks | Technical report + API findings |
| Social Engineering / Phishing | Employees | 1–3 weeks | Click/credential capture metrics + awareness recommendations |
| Wireless | Wi-Fi infrastructure | 2–5 days | Technical report + rogue AP / encryption findings |
| Physical | Building access, locks, cameras | 1–3 days | Narrative report + photographic evidence |
| Red Team | Full simulation of threat actor | 4–12 weeks | Attack narrative, TTPs used, detection gap analysis |
| Cloud | AWS / Azure / GCP environment | 1–2 weeks | Technical report + IAM / misconfiguration findings |

---

## Testing Methodologies

| Framework | Focus | Reference |
|---|---|---|
| [PTES](http://www.pentest-standard.org/) (Penetration Testing Execution Standard) | End-to-end pentest lifecycle — 7 phases | pentest-standard.org |
| [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) (Web Security Testing Guide) | Web application testing | owasp.org |
| [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final) | Technical Guide to Information Security Testing | csrc.nist.gov |
| [OSSTMM](https://www.isecom.org/OSSTMM.3.pdf) (Open Source Security Testing Methodology Manual) | Metrics-driven security testing across all channels | isecom.org |
| [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) | Vulnerability severity scoring | first.org |

---

## Testing Methodology — Phases

### Phase 1: Pre-Engagement

Define the boundaries, authorization, and objectives before any testing begins.

**Key Activities**
- Draft and sign the Statement of Work (SoW) and Rules of Engagement (RoE)
- Identify in-scope and out-of-scope targets (IP ranges, domains, applications)
- Define testing windows, emergency contact procedures, and escalation paths
- Perform threat modeling — understand the client's crown jewels and likely adversaries
- Provision credentials (for authenticated tests) and testing infrastructure

**Tools / Artifacts**
- Scope agreement templates, threat model worksheets, kick-off meeting notes

---

### Phase 2: Reconnaissance

Gather intelligence about the target without necessarily touching their infrastructure.

**Key Activities**
- **Passive (OSINT):** Enumerate domains, subdomains, email addresses, employee names, job postings, leaked credentials, SSL certificates, public code repos
- **Active:** DNS brute-force, zone transfers, web crawling, shodan/censys queries, direct banner grabbing

**Tools**

| Tool | Purpose |
|---|---|
| [Maltego](https://www.maltego.com/) | Visual OSINT link analysis |
| [Shodan](https://www.shodan.io/) | Internet-wide device / service search |
| [theHarvester](https://github.com/laramies/theHarvester) | Email, domain, and IP harvesting |
| [Amass](https://github.com/owasp-amass/amass) | Subdomain enumeration and OSINT |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Fast passive subdomain discovery |
| LinkedIn / OSINT Framework | Employee enumeration and social mapping |

---

### Phase 3: Scanning & Enumeration

Actively probe the target to identify open ports, running services, software versions, and known vulnerabilities.

**Key Activities**
- TCP/UDP port scanning across in-scope IP ranges
- Service fingerprinting and version identification
- Vulnerability scanning to enumerate known CVEs
- Web application crawling and directory brute-force
- Authentication mechanism enumeration (login pages, API endpoints)

**Tools**

| Tool | Purpose |
|---|---|
| [Nmap](https://nmap.org/) | TCP/UDP port scanning, scripting engine (NSE) |
| [Masscan](https://github.com/robertdavidgraham/masscan) | Fast internet-speed port scanning |
| [Nessus](https://www.tenable.com/products/nessus) / [OpenVAS](https://www.openvas.org/) | Credentialed and uncredentialed vulnerability scanning |
| [FFUF](https://github.com/ffuf/ffuf) | Web fuzzing — directories, parameters, vhosts |
| [Gobuster](https://github.com/OJ/gobuster) / [dirb](https://sourceforge.net/projects/dirb/) | Web content and directory enumeration |

---

### Phase 4: Exploitation

Attempt to exploit identified vulnerabilities to demonstrate real-world access.

**Key Activities**
- Weaponize findings: select or adapt proof-of-concept exploits
- Attempt initial access via service exploits, credential attacks, or social engineering
- Bypass authentication, authorization, and input validation controls
- Exploit web vulnerabilities: SQL injection, XSS, SSRF, XXE, deserialization, etc.
- Document every action taken with timestamps, commands, and screenshots

**Tools**

| Tool | Purpose |
|---|---|
| [Metasploit Framework](https://www.metasploit.com/) | Modular exploitation and payload delivery |
| Manual PoC exploits | Custom code for specific CVEs |
| [Exploit-DB](https://www.exploit-db.com/) | Public exploit repository |
| [Burp Suite Pro](https://portswigger.net/burp/pro) | Web application interception and exploitation |
| [SQLmap](https://sqlmap.org/) | Automated SQL injection exploitation |

---

### Phase 5: Post-Exploitation

Determine the full impact of initial access — what an attacker could do once inside.

**Key Activities**
- Privilege escalation (local and domain)
- Persistence mechanisms (for scoped red team engagements only, with explicit permission)
- Lateral movement to other systems and network segments
- Credential harvesting and pass-the-hash / pass-the-ticket attacks
- Data exfiltration simulation (demonstrate access to sensitive data)
- Active Directory enumeration and attack path mapping

**Tools**

| Tool | Purpose |
|---|---|
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential dumping from Windows memory |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | Active Directory attack path visualization |
| [Impacket](https://github.com/fortra/impacket) | Python toolkit for Windows protocol attacks |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | SMB/WinRM/LDAP lateral movement |
| [Chisel](https://github.com/jpillora/chisel) / [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) | Tunneling and network pivoting |

---

### Phase 6: Reporting

Communicate findings clearly to both technical teams and business stakeholders.

**Key Activities**
- Write an executive summary: business risk, top findings, overall risk rating
- Document each finding with ID, title, severity (CVSS), evidence, impact, and remediation
- Map findings to relevant standards (OWASP, NIST, CIS)
- Deliver both PDF and editable formats; conduct debrief call with client
- Archive and encrypt all engagement data per agreed data handling requirements

**Tools**

| Tool | Purpose |
|---|---|
| [Dradis](https://dradisframework.com/) | Collaborative pentest reporting |
| [Ghostwriter](https://github.com/GhostManager/Ghostwriter) | Full engagement management + reporting |
| [Plextrac](https://plextrac.com/) | Cloud-based pentest report platform |
| [SysReptor](https://github.com/Syslifters/sysreptor) | Open-source pentest reporting tool |

---

## Scoping and Rules of Engagement Checklist

Before any testing begins, confirm the following in writing:

- [ ] IP ranges, domains, and applications explicitly in scope
- [ ] IP ranges, domains, and applications explicitly out of scope
- [ ] Testing windows (business hours only vs. after-hours vs. 24/7)
- [ ] Emergency contacts and escalation procedure if a system is disrupted
- [ ] Credential provisioning: authenticated vs. unauthenticated testing
- [ ] Social engineering permission (phishing, vishing, pretexting)
- [ ] Denial-of-service testing permission (or explicit prohibition)
- [ ] Physical testing permission (tailgating, badge cloning, lock picking)
- [ ] Data handling requirements (encrypt all screenshots/evidence; delete after delivery)
- [ ] Notification of third-party providers (cloud, CDN, hosting) if applicable
- [ ] Signed authorization letter (get out of jail free letter)

---

## Common Tools by Phase

| Phase | Tool | Purpose |
|---|---|---|
| Recon | Maltego | OSINT link analysis and entity mapping |
| Recon | Shodan | Search internet-exposed services and devices |
| Recon | theHarvester | Email, subdomain, and IP enumeration |
| Recon | Amass | Subdomain enumeration |
| Recon | Sublist3r | Fast passive subdomain discovery |
| Recon | LinkedIn scraping | Employee and org chart enumeration |
| Scanning | Nmap | TCP/UDP port scanning and NSE scripting |
| Scanning | Masscan | High-speed port scanning |
| Scanning | Nessus / OpenVAS | Vulnerability scanning |
| Web | Burp Suite Pro | Web proxy, scanner, intruder |
| Web | FFUF | Web fuzzing (dirs, params, vhosts) |
| Web | Nikto | Web server misconfiguration scanner |
| Web | SQLmap | SQL injection automation |
| Web | WPScan | WordPress vulnerability scanner |
| Web | dirb / gobuster | Directory and content enumeration |
| Exploitation | Metasploit Framework | Modular exploitation framework |
| Exploitation | Manual PoC exploits | CVE-specific proof-of-concept scripts |
| Exploitation | Exploit-DB | Public exploit database |
| Post-Exploit | Mimikatz | Windows credential dumping |
| Post-Exploit | BloodHound | AD attack path discovery |
| Post-Exploit | Impacket | Windows protocol attack toolkit |
| Post-Exploit | CrackMapExec | Lateral movement across SMB/WinRM/LDAP |
| Post-Exploit | Chisel / Ligolo-ng | Network pivoting and tunneling |
| Reporting | Dradis | Collaborative reporting platform |
| Reporting | Ghostwriter | Engagement management and reporting |
| Reporting | Plextrac | Cloud pentest report management |
| Reporting | SysReptor | Open-source pentest reporting |

---

## Vulnerability Scoring — CVSS v3.1

CVSS (Common Vulnerability Scoring System) v3.1 provides a standardized way to rate vulnerability severity. The base score is calculated from the following metrics:

| Metric | Options | Description |
|---|---|---|
| Attack Vector (AV) | Network / Adjacent / Local / Physical | How the vulnerability is exploited |
| Attack Complexity (AC) | Low / High | Conditions beyond attacker control required for exploitation |
| Privileges Required (PR) | None / Low / High | Level of access required before exploitation |
| User Interaction (UI) | None / Required | Whether a victim must take action |
| Confidentiality Impact (C) | None / Low / High | Impact on data confidentiality |
| Integrity Impact (I) | None / Low / High | Impact on data integrity |
| Availability Impact (A) | None / Low / High | Impact on system availability |

**Score Ranges**

| Score | Severity |
|---|---|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

**EPSS (Exploit Prediction Scoring System)** is a complementary metric from FIRST that estimates the probability a given CVE will be exploited in the wild within 30 days. Use CVSS for severity and EPSS for prioritization.

---

## Report Structure

A professional penetration test report contains the following sections:

### 1. Executive Summary (1–2 pages)
- Written in business language — no technical jargon
- Overall risk rating (Critical / High / Medium / Low)
- Top findings summarized with business impact
- High-level remediation priorities

### 2. Scope and Methodology
- Tested targets, dates, and testing windows
- Testing approach and methodology references (PTES, OWASP, NIST SP 800-115)
- Tester credentials and assumptions

### 3. Findings Table

| ID | Title | Severity | CVSS Score | Status |
|---|---|---|---|---|
| PT-001 | Unauthenticated RCE via Apache Struts | Critical | 10.0 | Open |
| PT-002 | SQL Injection in Login Form | High | 8.8 | Open |
| PT-003 | TLS 1.0 Enabled on Public Web Server | Medium | 5.3 | Open |

### 4. Per-Finding Detail
Each finding contains:
- **Description** — What the vulnerability is and where it was found
- **Evidence** — Screenshots, request/response captures, tool output
- **Impact** — What an attacker could achieve by exploiting this
- **Remediation** — Specific, actionable fix guidance
- **References** — CVE, CWE, OWASP, vendor advisory

### 5. Appendix
- Raw tool output (Nmap scans, Nessus exports)
- Methodology details and full testing timeline
- Scope confirmation artifacts

---

## Certifications

| Cert | Provider | Level | Cost | Renewal |
|---|---|---|---|---|
| [eJPT](https://security.ine.com/certifications/ejpt-certification/) (eLearnSecurity Junior Penetration Tester) | INE | Entry | ~$200 | None |
| [PNPT](https://certifications.tcm-sec.com/pnpt/) (Practical Network Penetration Tester) | TCM Security | Intermediate | ~$400 | None |
| [OSCP](https://www.offsec.com/courses/pen-200/) (Offensive Security Certified Professional) | OffSec | Intermediate | ~$1,499/yr | 3 years |
| [CPTS](https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist) (HTB Certified Penetration Testing Specialist) | HackTheBox | Intermediate | ~$210 | None |
| [GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) (GIAC Penetration Tester) | SANS | Intermediate | ~$949 | 4 yr CPE |
| [BSCP](https://portswigger.net/web-security/certification) (Burp Suite Certified Practitioner) | PortSwigger | Web-focused | ~$99 | Annual |
| [CREST CRT](https://www.crest-approved.org/certification-careers/crest-certifications/crest-registered-penetration-tester/) (Registered Penetration Tester) | CREST | Intermediate | Varies | 3 years |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [HackTheBox](https://www.hackthebox.com/) | Labs | Hands-on machines and guided paths |
| [TryHackMe](https://tryhackme.com/) | Labs | Beginner-friendly learning paths |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Labs / Courses | Best free web application testing training |
| [TCM Security Academy](https://academy.tcm-sec.com/) | Courses | Practical, affordable pentest courses |
| [INE Security](https://security.ine.com/) | Courses | eJPT / eCPPT / eWPT courseware |
| [Hacking: The Art of Exploitation (Erickson)](https://nostarch.com/hacking2.htm) | Book | Deep-dive into exploitation fundamentals |
| [The Web Application Hacker's Handbook](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%2C+2nd+Edition-p-9781118026472) | Book | Classic web app testing reference |
| [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines) | Reference | Detailed technical pentest guidance |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Reference | Cheatsheet for every attack category |
| [GTFOBins](https://gtfobins.github.io/) | Reference | Unix binaries for privilege escalation |
| [LOLBAS](https://lolbas-project.github.io/) | Reference | Windows LOLBins for post-exploitation |

---

## Related Disciplines & Resources

- [Red Teaming](red-teaming.md) — Adversarial simulation beyond the structured pentest methodology
- [Active Directory Security](active-directory.md) — In-depth coverage of AD attack and defense techniques
- [PENTEST_CHECKLISTS.md](../PENTEST_CHECKLISTS.md) — Phase-by-phase testing checklists
- [CERTIFICATIONS.md](../CERTIFICATIONS.md) — Full certification roadmap across all disciplines
- [HTB Tracks](../research/HTB_TRACKS.md) — HackTheBox learning paths aligned to penetration testing
