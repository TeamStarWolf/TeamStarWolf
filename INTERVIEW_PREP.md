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

## Related Resources
- [Career Paths](CAREER_PATHS.md) — role descriptions, salary ranges, and progression maps
- [Certifications Reference](CERTIFICATIONS.md) — 40+ certs with costs, difficulty, and DoD 8570 status
- [Hands-On Labs](LABS.md) — HTB, THM, BTLO, and other practice platforms
- [HTB Learning Tracks](research/HTB_TRACKS.md) — structured learning paths on HackTheBox
- [Security Tools Reference](TOOLS.md) — tool matrix by category
