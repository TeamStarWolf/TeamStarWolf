# Cybersecurity Interview Preparation

A comprehensive guide to common interview questions, technical topics, and preparation strategies for cybersecurity roles. Organized by role type and difficulty level.

---

## General Preparation Strategy

1. **Know the fundamentals cold** — networking (TCP/IP, DNS, TLS), OS internals (Windows/Linux), and the CIA triad
2. **Practice explaining concepts simply** — "explain this to a non-technical person" tests are common
3. **Prepare a portfolio** — HTB/THM writeups, CTF flags, home lab documentation, GitHub projects
4. **Know your resume** — every tool, cert, and project should be something you can discuss in depth
5. **STAR format** — behavioral questions: Situation, Task, Action, Result

---

## Networking Fundamentals

### Core Questions

| Question | Key Points to Cover |
|---|---|
| Explain the OSI model and give examples at each layer | L1: cables/fiber, L2: Ethernet/MAC, L3: IP/routing, L4: TCP/UDP, L7: HTTP/DNS. Focus on L3-L7 for security work |
| What happens when you type google.com into a browser? | DNS resolution, TCP 3-way handshake, TLS negotiation, HTTP request, CDN routing |
| What is the difference between TCP and UDP? | TCP: reliable, ordered, connection-oriented (3-way handshake). UDP: faster, stateless — used for DNS, VoIP, gaming |
| Explain the TCP 3-way handshake | SYN → SYN-ACK → ACK. Half-open during SYN flood attack |
| What is ARP and how can it be abused? | Maps IP to MAC. ARP poisoning/spoofing enables MitM on local network |
| What is the difference between a hub, switch, and router? | Hub: broadcasts all, Switch: MAC table forwarding, Router: IP-based forwarding between networks |
| How does DNS work? | Recursive resolver → root nameserver → TLD → authoritative NS. Cache poisoning, DNSSEC for protection |
| What is NAT and why is it used? | Network Address Translation: maps private IPs to public. PAT (overloaded NAT) is most common |
| Explain HTTPS / TLS handshake | Client hello → server certificate → key exchange → symmetric session key established |
| What ports does HTTP/HTTPS/SSH/FTP/DNS use? | HTTP: 80, HTTPS: 443, SSH: 22, FTP: 21/20, DNS: 53, RDP: 3389, SMB: 445 |
| What is a subnet mask? What is /24? | /24 = 255.255.255.0, 254 usable hosts. CIDR notation. Understand subnetting for network segmentation |
| What is the difference between IDS and IPS? | IDS: detect and alert only. IPS: inline, can block traffic. HIDS vs NIDS |

---

## Operating System Internals

### Windows

| Question | Key Points |
|---|---|
| What is LSASS and why is it targeted? | Local Security Authority Subsystem Service — stores credentials in memory. Mimikatz dumps NTLM hashes, Kerberos tickets |
| Explain Windows authentication (NTLM vs Kerberos) | NTLM: challenge-response, older, pass-the-hash vulnerable. Kerberos: ticket-based, DC-issued TGT, Kerberoasting target |
| What is the Windows Registry? | Hierarchical database storing config. HKLM (system-wide) vs HKCU (user-specific). Common persistence location |
| What are Windows Event Log IDs you should know? | 4624 (logon), 4625 (failed logon), 4648 (explicit creds), 4698 (scheduled task), 4720 (account created), 7045 (new service), 4688 (process creation) |
| What is UAC and can it be bypassed? | User Account Control — elevation prompt. Many bypass techniques (fodhelper, eventvwr, CMSTP). Mark of the Web |
| What is the difference between a local and domain account? | Local: stored in SAM. Domain: stored in AD NTDS.dit. Domain admins are high-value targets |
| How does Pass-the-Hash work? | NTLM auth accepts password hash directly. Steal hash via Mimikatz, reuse without cracking |
| What is Kerberoasting? | Request service ticket (TGS) for any SPN-registered account, crack offline. Targets service accounts with weak passwords |

### Linux

| Question | Key Points |
|---|---|
| How does Linux file permissions work? | rwxrwxrwx — owner/group/other. chmod, chown. SUID bit (chmod +s) — privilege escalation vector |
| What is sudo and how is it abused? | Allows running commands as another user (root). Misconfigured sudo rules (NOPASSWD, wildcard) = privesc |
| What are cron jobs and how are they abused? | Scheduled tasks. World-writable scripts called by root cron = privilege escalation |
| Where are credentials stored on Linux? | /etc/shadow (hashed passwords), ~/.ssh/id_rsa (SSH keys), env variables, .bash_history |
| What is /proc and why does it matter? | Virtual filesystem for process info. /proc/[pid]/mem, /proc/[pid]/cmdline can leak sensitive data |
| Explain Linux capabilities | Fine-grained privileges. cap_setuid, cap_net_raw, etc. Replaces some SUID needs. Misconfigured caps = privesc |
| What is LD_PRELOAD and how is it abused? | Env variable loading shared libraries before others. If preserved through sudo = root code execution |

---

## Security Concepts

| Question | Key Points |
|---|---|
| Explain the CIA triad | Confidentiality (encryption), Integrity (hashing), Availability (redundancy). Add non-repudiation for AAA |
| What is defense in depth? | Multiple layered controls — if one fails, others compensate. Physical → network → host → application → data |
| What is the principle of least privilege? | Grant minimum access necessary to perform a function. Reduces blast radius of compromise |
| What is zero trust? | Never trust, always verify — continuous authentication, device posture, microsegmentation |
| Explain authentication vs authorization | AuthN: who are you (credential verification). AuthZ: what can you do (access control) |
| What is a PKI? | Public Key Infrastructure: CAs, certificates, key pairs. Enables TLS, code signing, email encryption |
| What is the difference between symmetric and asymmetric encryption? | Symmetric: same key (AES, fast). Asymmetric: key pair (RSA, slower). TLS uses both: asymmetric for key exchange, symmetric for data |
| What is a hash function and what makes it good? | One-way function. Good: collision resistant, pre-image resistant, avalanche effect. MD5/SHA1 broken, use SHA-256+ |
| What is salting? | Random value added to password before hashing. Defeats rainbow tables. Per-user salt means same password = different hash |
| What is MFA and what are its types? | Something you know (password), have (token/phone), are (biometric). SMS weakest (SIM swap), FIDO2 strongest |
| What is SQL injection? | Inserting SQL meta-characters to modify query logic. ' OR 1=1 -- classic example. Prevent with parameterized queries |
| What is XSS? | Cross-site scripting: injecting JS into pages. Reflected (URL-based), Stored (persistent), DOM-based. Steal cookies, deface |
| What is CSRF? | Cross-Site Request Forgery: trick authenticated user into making unwanted request. Prevent with CSRF tokens, SameSite cookies |
| What is SSRF? | Server-Side Request Forgery: make server fetch attacker-controlled URLs. Can hit internal services, cloud metadata APIs |

---

## Role-Specific Questions

### SOC Analyst / Blue Team

| Question | Answer Guidance |
|---|---|
| Walk me through how you would triage a phishing alert | Check headers (sender IP, SPF/DKIM/DMARC), inspect URLs/attachments in sandbox, identify recipients, search for similar emails, escalate or close |
| What is a false positive? How do you handle them? | Alert that fires when no real threat exists. Tune detection rules, document as known-good, add to whitelist with approval |
| What SIEM are you familiar with? | Mention Splunk (SPL queries), Sentinel (KQL), Elastic (EQL/KQL). Show you can write queries, not just read dashboards |
| Explain lateral movement and how to detect it | Moving from system to system using stolen creds or exploits. Look for: new logon events from known machine, admin share access (C$), PSExec/WMI/WinRM usage, unusual process lineage |
| What is a SOC playbook? | Step-by-step response procedure for a specific alert type. Reduces response time, ensures consistency |
| What threat intel feeds do you use? | MISP, CISA AIS, abuse.ch, VirusTotal Enterprise, CrowdStrike/Mandiant feeds |
| How would you hunt for beaconing? | Look for periodic, regular outbound connections to same IP/domain. Low byte count, consistent timing, unusual user agent |

### Penetration Tester / Red Team

| Question | Answer Guidance |
|---|---|
| What is your methodology for a black-box pentest? | Recon → scanning → enumeration → exploitation → post-exploitation → pivoting → reporting. Reference PTES, OWASP, NIST |
| How do you escalate privileges on a Windows machine? | Check: unquoted service paths, weak service permissions, AlwaysInstallElevated, DLL hijacking, stored credentials, token impersonation |
| How do you escalate privileges on a Linux machine? | SUID binaries (GTFOBins), sudo misconfigs (NOPASSWD), world-writable cron scripts, capabilities, PATH hijacking |
| Explain a common AD attack path | Enumerate with BloodHound → find user with GenericAll on a group → add to group → inherit admin rights → DCSync → dump all hashes |
| What is BloodHound and how do you use it? | Graph-based AD attack path tool. Ingestor (SharpHound) collects data, Neo4j + BloodHound visualizes shortest paths to DA |
| What is the difference between a pentest and a red team engagement? | Pentest: find and verify vulnerabilities in scope. Red team: simulate realistic threat actor, test detection and response, more stealth |
| How do you avoid detection during an engagement? | OPSEC: use LOLBins, encrypt C2 traffic, blend into normal traffic patterns, avoid noisy scanners, stage payloads |
| What is C2 and what frameworks do you know? | Command and Control infrastructure. Cobalt Strike (gold standard), Sliver (OSS), Havoc (OSS), Brute Ratel, Metasploit |

### Incident Responder / DFIR

| Question | Answer Guidance |
|---|---|
| Walk me through responding to a ransomware incident | Isolate → preserve forensics → identify blast radius → check backups → contain → eradicate (rebuild, reset creds) → restore → post-incident |
| What is the NIST IR lifecycle? | Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity |
| What volatile evidence should you collect first? | Memory dump, running processes, network connections, logged-on users, open files — collected before shutdown. Then disk image |
| What tools do you use for memory forensics? | Volatility (pslist, netscan, dumpfiles, malfind), WinPmem for acquisition, Rekall |
| How do you determine if a binary is malicious? | Static: hash lookup (VirusTotal), strings analysis, PE header inspection. Dynamic: sandbox (Any.run, Triage), behavioral analysis |
| What are common persistence mechanisms? | Registry run keys, scheduled tasks, services, startup folder, DLL hijacking, WMI subscriptions, browser extensions |
| Explain a timeline analysis | Correlate file system (MFT, $UsnJrnl), event logs, prefetch, registry hives, browser history to reconstruct attacker activity |
| What is chain of custody? | Documentation proving evidence has not been tampered with from collection through court. Hash evidence at collection |

### Application Security

| Question | Answer Guidance |
|---|---|
| What is OWASP Top 10? | 10 most critical web app security risks. 2021: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, SSRF, etc. |
| How do you prevent SQL injection? | Parameterized queries / prepared statements. Input validation. Least-privilege DB accounts. WAF as defense-in-depth |
| What is IDOR? | Insecure Direct Object Reference: accessing resources by changing ID in request (e.g., /user/1234 → /user/1235). Missing authorization check |
| What is JWT and what vulnerabilities exist? | JSON Web Token: header.payload.signature. Attacks: alg=none (no sig verification), weak secret (crack with hashcat), key confusion RS256→HS256 |
| What is the Same-Origin Policy? | Browser security: restricts scripts from one origin accessing resources from another. CORS relaxes this — misconfigured CORS = data theft |
| How would you perform a code review for security? | SAST tool first (Semgrep, Bandit). Then manual: input validation, auth checks, cryptography use, logging of sensitive data, error handling |
| Explain DevSecOps | Integrating security into CI/CD: SAST in PR checks, DAST in staging, SCA for dependencies, secrets scanning, IaC scanning |

### Cloud Security

| Question | Answer Guidance |
|---|---|
| What is the shared responsibility model? | Cloud provider responsible for security OF the cloud (infra). Customer responsible for security IN the cloud (data, IAM, config) |
| How would you approach an AWS compromise? | Preserve CloudTrail logs, identify compromised IAM keys, revoke them, check for new IAM users/roles/policies, look for resource abuse (EC2, Lambda, S3 exfil) |
| What is an IAM role vs user? | User: long-term creds (access key/secret). Role: assumed temporarily, no long-term creds. Prefer roles over users |
| What is an S3 bucket misconfiguration? | Public ACLs, bucket policies granting `*` principal, missing encryption. Check with AWS Macie or CSPM tools |
| How do you detect cryptomining in AWS? | GuardDuty alert on EC2 cryptomining, unusual CPU/GPU spike, outbound traffic to mining pools, large unexpected billing |
| What is a CSPM tool? | Cloud Security Posture Management: continuously scans cloud configs for misconfigurations. Wiz, Prisma Cloud, Defender for Cloud |
| Explain IAM privilege escalation in AWS | iam:PassRole + EC2 launch rights = assume role with more privileges. iam:CreatePolicyVersion to add admin policy. Use tools like Pacu, Cloudsplaining |

---

## Behavioral / Soft Skill Questions

| Question | Approach |
|---|---|
| Tell me about yourself | 90 seconds: background, why security, current skills, what you are looking for next |
| Describe a time you found a critical vulnerability | Use STAR. Include impact, how you communicated it, how it was remediated |
| How do you stay current in cybersecurity? | Twitter/X follows, RSS feeds (Krebs, Bleeping Computer), HTB/THM weekly, CISA advisories, conference talks (DEF CON, Black Hat YouTube) |
| How do you explain a technical issue to a non-technical stakeholder? | Avoid jargon, use analogies, focus on business impact and risk, recommend specific actions |
| Tell me about a time you worked under pressure | Security incident scenarios work well. Show structured thinking (triage, escalation, resolution) |
| What do you do when you disagree with a security decision? | Raise concern with data, document it, accept decision if overruled — but escalate if it poses unacceptable risk |
| Where do you want to be in 5 years? | Show ambition tied to the role: certifications planned, skills to develop, leadership aspirations |

---

## Technical Practical Tests

Many companies include a practical component. Common formats:

### CTF / Challenge Box
- Practice on HackTheBox, TryHackMe, PicoCTF
- Be comfortable with basic privesc on both Windows and Linux
- Know how to enumerate quickly: nmap, gobuster/ffuf, enum4linux

### Packet Analysis
- Know Wireshark filters: `tcp.port == 443`, `http.request.method == GET`, `ip.addr == 10.0.0.1`
- Identify: port scans (SYN flood pattern), C2 beaconing (periodic small packets), data exfil (large outbound)
- Understand TCP stream reconstruction and HTTP object export

### Log Analysis
- Splunk: `index=windows EventCode=4624 | stats count by src_ip`
- Elastic (KQL): `event.code: 4624 and winlog.event_data.LogonType: 3`
- Know how to pivot: IP → hostname → user → process → parent process

### Scenario Walk-Throughs
- "You get an alert at 3am — what do you do?" — show triage process
- "You find malware on a laptop — what are your first 5 actions?" — isolate, image memory, capture logs, escalate, forensic triage

---

## Quick Reference: Must-Know Tools by Role

| Role | Tools to Know |
|---|---|
| SOC Analyst | Splunk, Sentinel, Elastic, CrowdStrike, Defender for Endpoint, VirusTotal, Proofpoint |
| Incident Responder | Volatility, FTK/Autopsy, Velociraptor, KAPE, Wireshark, Zeek, CyberChef |
| Penetration Tester | Nmap, Burp Suite, Metasploit, BloodHound, Impacket, CrackMapExec, Mimikatz |
| Red Teamer | Cobalt Strike, Sliver, Havoc, BOF kits, C2Concealer, ScareCrow, SharpCollection |
| AppSec Engineer | Semgrep, Burp Suite Pro, OWASP ZAP, Trivy, Snyk, SonarQube, Gitleaks |
| Cloud Security | Pacu, Prowler, ScoutSuite, Cloudsplaining, Wiz, Prisma Cloud, AWS CLI |
| Malware Analyst | Ghidra, IDA Pro, x64dbg, Cuckoo/CAPE, Any.run, YARA, Volatility, PEStudio |

---

## Certification Cheat Sheet

| Role | Recommended Certs |
|---|---|
| SOC / Blue Team Entry | CompTIA Security+, BTL1, HTB CDSA |
| SOC / Blue Team Mid | CySA+, GCIA, GCIH, GCFE |
| Pentesting Entry | eJPT, PNPT, HTB CPTS |
| Pentesting Mid/Senior | OSCP, GPEN, GXPN |
| DFIR | GCFE, GCFA, GCFR, GREM |
| Cloud Security | AWS SAA + Security Specialty, CCSP, AZ-500 |
| AppSec | GWEB, GWAPT, BSCP, ISC2 CSSLP |
| Leadership / GRC | CISSP, CISM, CRISC, CISA |

See [Certifications Reference](CERTIFICATIONS.md) for full details on each cert.

---


### Governance, Risk & Compliance (GRC)

| Question | Answer Guidance |
|---|---|
| What is a risk register? | A living document tracking identified risks, their likelihood, impact, owner, and treatment status. Updated regularly and reviewed by leadership |
| Explain the difference between a policy, standard, and procedure | Policy: high-level intent and direction. Standard: specific measurable requirement. Procedure: step-by-step instructions. Guidelines: recommended but not mandatory |
| What is NIST CSF 2.0 and what are its six functions? | Govern, Identify, Protect, Detect, Respond, Recover. CSF 2.0 added Govern as a new function covering strategy, roles, and organizational risk appetite |
| What is a SOC 2 Type II report? | AICPA audit of controls across 5 Trust Services Criteria over a 6-12 month period. Type I: design only (point-in-time). Type II: operating effectiveness over time |
| How do you perform a gap analysis? | Compare current-state controls against a target framework. Document gaps, assign risk ratings, prioritize by risk severity and remediation effort |
| What is a BIA (Business Impact Analysis)? | Identifies critical business functions and quantifies the impact of disruption. Outputs RTO, RPO, and MTD per critical function |
| Qualitative vs. quantitative risk assessment? | Qualitative: High/Medium/Low ratings — fast but subjective. Quantitative: dollar-value calculations (ALE = ARO x SLE) — more defensible for budget decisions |
| How would you build a third-party risk program? | Tier vendors by risk level (data access, operational criticality), define questionnaires per tier, review SOC 2 and ISO 27001 reports, perform on-site assessments for highest-risk vendors, include contractual security requirements |
| What is CMMC 2.0? | DoD framework for defense contractors: Level 1 (17 practices), Level 2 (110 NIST 800-171 practices), Level 3 (plus 24 NIST 800-172 practices). C3PAO third-party assessments required at Levels 2 and 3 |
| How do you measure security program effectiveness? | KPIs: patch SLA compliance rate, phishing simulation click rate trend, MTTD/MTTR, critical vulnerability remediation rate, control test pass rates, audit findings closed on time |

### Threat Intelligence Analyst

| Question | Answer Guidance |
|---|---|
| Explain the intelligence lifecycle | Planning and Direction -> Collection -> Processing -> Analysis -> Dissemination -> Feedback. Feedback loop refines future collection requirements |
| What is the difference between strategic, operational, and tactical intelligence? | Strategic: long-term executive-level trend reports. Operational: active campaign TTPs and threat actor profiles. Tactical: IOCs (IPs, hashes, domains) for immediate defensive use |
| What is the Diamond Model of Intrusion Analysis? | Framework with four vertices: Adversary, Capability, Infrastructure, Victim. Used to link intrusion events into campaigns and cluster activity for attribution |
| Cyber Kill Chain vs. ATT&CK? | Kill Chain (Lockheed Martin): 7 linear phases from Reconnaissance to Actions on Objectives. ATT&CK: granular non-linear taxonomy with 14 tactics and hundreds of techniques -- better for detection engineering and coverage gap analysis |
| What is MISP and how is it used? | Open-source Threat Intelligence Platform for sharing structured threat data. Supports STIX/TAXII, automated correlation, and galaxy clusters for tagging actors and malware families |
| How do you assess confidence in a report? | Evaluate source reliability (track record and access level), information credibility (corroboration, timeliness, internal consistency), and analysis quality. Apply the Admiralty Scale or ACH methodology |
| IOC types and their limitations? | Types: IPs, domains, URLs, file hashes, email addresses. Primary limitation: high perishability -- adversaries rotate infrastructure rapidly. TTPs are more durable indicators for long-term detection |
| What is STIX/TAXII? | STIX: structured JSON format for threat intelligence objects (indicators, campaigns, malware, TTPs, threat actors). TAXII: transport protocol for automated STIX data sharing between platforms |
| Describe a threat actor you know well | Example: APT29/Cozy Bear (Russian SVR) -- targets government and political organizations, responsible for SUNBURST supply chain attack, uses custom Cobalt Strike malleable C2, spearphishing, and living-off-the-land techniques across the entire kill chain |

---

## Salary Negotiation & Offer Evaluation

### Know Your Market Value

Research compensation thoroughly before any negotiation. Key sources:

| Source | URL | Best For |
|---|---|---|
| Levels.fyi | [levels.fyi](https://www.levels.fyi/) | Base + bonus + equity at tech companies |
| LinkedIn Salary | [linkedin.com/salary](https://www.linkedin.com/salary/) | Role and location-based ranges |
| Glassdoor | [glassdoor.com](https://www.glassdoor.com/) | Company-specific data with culture reviews |
| SANS Salary Survey | [sans.org/salary-survey](https://www.sans.org/salary-survey/) | Annual cybersecurity-specific compensation benchmarks |
| Dice | [dice.com](https://www.dice.com/) | Tech and security contractor/permanent role rates |

### Approximate Security Salary Ranges (US, 2024-2025)

| Role | Entry (0-2 yr) | Mid (3-5 yr) | Senior (6+ yr) |
|---|---|---|---|
| SOC Analyst | $55,000-$75,000 | $75,000-$100,000 | $100,000-$130,000 |
| Penetration Tester | $70,000-$95,000 | $95,000-$130,000 | $130,000-$180,000+ |
| Incident Responder | $65,000-$90,000 | $90,000-$125,000 | $125,000-$170,000+ |
| Security Engineer | $80,000-$110,000 | $110,000-$150,000 | $150,000-$200,000+ |
| Cloud Security Engineer | $90,000-$120,000 | $120,000-$160,000 | $160,000-$220,000+ |
| AppSec Engineer | $85,000-$115,000 | $115,000-$155,000 | $155,000-$210,000+ |
| Security Architect | $110,000-$140,000 | $140,000-$180,000 | $180,000-$250,000+ |
| CISO | --- | $150,000-$220,000 | $220,000-$400,000+ |
| GRC Analyst | $60,000-$85,000 | $85,000-$115,000 | $115,000-$150,000 |
| Threat Intel Analyst | $65,000-$90,000 | $90,000-$130,000 | $130,000-$170,000+ |
| DFIR Analyst | $70,000-$95,000 | $95,000-$130,000 | $130,000-$175,000+ |

*Ranges vary significantly by location, company size, industry, and clearance level. TS/SCI clearance typically commands a $20,000-$50,000+ premium.*

### Negotiation Principles

1. **Get the offer in writing first.** Never negotiate from a verbal offer.
2. **Never anchor first.** When asked for salary expectations: *"I would prefer to discuss compensation once I understand the full scope of the role and total package."*
3. **Counter anchored high.** If offered $95,000 and your market data supports $110,000-$120,000: *"Based on my experience with [specific skills/certs] and current market data, I was targeting $110,000-$120,000. Is there flexibility?"*
4. **Evaluate total compensation.** Bonus target, RSU vesting schedule, 401k match, health premiums, training budget ($5,000-$15,000/yr at top security employers), remote flexibility, and signing bonus all have real dollar value.
5. **Use competing offers ethically.** *"I have a competing offer at $X. I prefer your organization because of [genuine reason], but would need compensation closer to that level to accept."*

### Handling Negotiation Pushback

| Pushback | Effective Response |
|---|---|
| "That is above our budget" | "Could we structure a 90-day review milestone with a defined path to $X?" |
| "We have a fixed salary band" | "What is the top of the band? Can we close the gap with signing bonus or additional PTO?" |
| "You lack the experience" | "Understood. Given my [cert/project/achievement], what would a 6-12 month milestone look like to reach that target?" |
| "We need an answer today" | "I need 48 hours to review the complete offer and benefits. I will confirm by [specific date and time]." |

*Never accept same-day pressure tactics. Legitimate offers allow at least 48-72 hours for consideration.*

## Related Resources
- [Career Paths](CAREER_PATHS.md) — role descriptions, salary ranges, and progression maps
- [Certifications Reference](CERTIFICATIONS.md) — 40+ certs with costs, difficulty, and DoD 8570 status
- [Hands-On Labs](LABS.md) — HTB, THM, BTLO, and other practice platforms
- [HTB Learning Tracks](research/HTB_TRACKS.md) — structured learning paths on HackTheBox
- [Security Tools Reference](TOOLS.md) — tool matrix by category
