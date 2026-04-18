# Offensive Security

Simulating adversary tactics through penetration testing, red teaming, and adversary emulation to identify weaknesses before attackers do.

---

## Where to Start

Offensive security is learned by doing. The conceptual foundation is understanding how systems work — operating systems, networking, authentication protocols, and application behavior — before you understand how they break. Start with Hack The Box or TryHackMe to build lab skills in a safe environment. Watch IppSec's HackTheBox walkthroughs to understand not just the answer but the thought process. Build up to Active Directory attacks, which are the core skill set for real-world engagements. From there, adversary emulation with a C2 framework and ATT&CK-mapped techniques takes you from penetration testing into red teaming.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Linux fundamentals, networking, scripting, basic exploitation | TryHackMe (beginner paths), TCM Security free YouTube, IppSec easy boxes |
| Practitioner | Active Directory attacks, web exploitation, C2 frameworks, privilege escalation | HTB Academy, TCM Security PNPT course, BHIS Introduction to Pentesting |
| Advanced | Red team operations, EDR evasion, adversary emulation, custom tooling | CRTO, OSCP, OSEP, CRTE |

---

## Free Training

- [IppSec YouTube](https://www.youtube.com/@ippsec) — HackTheBox walkthroughs averaging nearly an hour each; 500+ videos covering every technique from beginner to expert; the most effective free offensive security education available
- [IppSec Search](https://ippsec.rocks) — Search across all IppSec video transcripts by tool or technique to find exactly the walkthrough you need
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Free full courses and technique demonstrations; Practical Ethical Hacking previews, Active Directory content, and SOC 101
- [TCM Academy Free Tier](https://academy.tcm-sec.com/courses) — 25+ hours of free on-demand content; no credit card required
- [Antisyphon: Introduction to Pentesting](https://www.antisyphontraining.com/product/introduction-to-pentesting-with-john-strand/) — Pay-what-you-can ($0+) with John Strand; fundamentals through lab exercises
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — Pentest technique deep dives, Active Directory attack walkthroughs, and adversary simulation content
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on offensive techniques, red team operations, and adversary behavior
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; Active Directory, web exploitation, and penetration testing paths
- [TryHackMe](https://tryhackme.com) — Beginner-friendly browser-based labs; no local setup required; structured learning paths
- [CISA Free Training](https://niccs.cisa.gov/training/catalog) — Includes ethical hacking and penetration testing fundamentals

---

## Tools & Repositories

### C2 Frameworks
- [metasploit-framework](https://github.com/rapid7/metasploit-framework) — The standard exploitation and post-exploitation framework
- [metasploit-payloads](https://github.com/rapid7/metasploit-payloads) — Official Metasploit payloads
- [Havoc](https://github.com/HavocFramework/Havoc) — Modern C2 framework with extensible agent capabilities
- [Sliver](https://github.com/BishopFox/sliver) — Open source adversary simulation C2 framework
- [Mythic](https://github.com/its-a-feature/Mythic) — Collaborative red team C2 platform with a plugin architecture
- [Empire](https://github.com/BC-SECURITY/Empire) — Actively maintained PowerShell and Python post-exploitation framework
- [Villain](https://github.com/t3l3machus/Villain) — Multi-session handler with reverse shell generation
- [NimPlant](https://github.com/chvancooten/NimPlant) — Nim-based implant for evasive operations
- [pupy](https://github.com/n1nj4sec/pupy) — Cross-platform Python-based C2

### Active Directory Attacks
- [BloodHound](https://github.com/SpecterOps/BloodHound) — Active Directory and Entra ID attack path mapping
- [SharpHound](https://github.com/SpecterOps/SharpHound) — BloodHound data collection agent
- [AzureHound](https://github.com/SpecterOps/AzureHound) — Azure/Entra ID data collector for BloodHound
- [impacket](https://github.com/fortra/impacket) — Python library for Windows network protocols (GetTGT, secretsdump, ntlmrelayx)
- [NetExec](https://github.com/Pennyw0rth/NetExec) — Network pentesting Swiss army knife; maintained CrackMapExec successor
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) — Classic SMB/WinRM/LDAP pentesting framework
- [mimikatz](https://github.com/gentilkiwi/mimikatz) — Credential extraction and Kerberos attack toolkit
- [Responder](https://github.com/lgandx/Responder) — LLMNR/NBT-NS/MDNS poisoner for NTLM relay attacks
- [mitm6](https://github.com/dirkjanm/mitm6) — IPv6 DNS takeover for NTLM relay attacks
- [Certipy](https://github.com/ly4k/Certipy) — AD CS (Active Directory Certificate Services) attack tool
- [Coercer](https://github.com/p0dalirius/Coercer) — Coerce Windows hosts to authenticate to arbitrary SMB endpoints
- [kerbrute](https://github.com/ropnop/kerbrute) — Kerberos username enumeration and password spraying
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) — WinRM shell for Windows remote management abuse
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh) — PowerShell LLMNR/NBNS/mDNS spoofer

### GhostPack
- [Rubeus](https://github.com/GhostPack/Rubeus) — Kerberos abuse toolkit (AS-REP roasting, pass-the-ticket, overpass-the-hash)
- [Seatbelt](https://github.com/GhostPack/Seatbelt) — Host security checks and situational awareness
- [Certify](https://github.com/GhostPack/Certify) — Enumerate and abuse AD CS misconfigurations
- [SharpUp](https://github.com/GhostPack/SharpUp) — Windows privilege escalation checks
- [ForgeCert](https://github.com/GhostPack/ForgeCert) — Forge AD CS certificates for arbitrary principal authentication
- [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) — Audit AD CS PKI configurations

### Reconnaissance
- [amass](https://github.com/owasp-amass/amass) — In-depth external attack surface mapping
- [subfinder](https://github.com/projectdiscovery/subfinder) — Passive subdomain discovery
- [httpx](https://github.com/projectdiscovery/httpx) — Fast HTTP probing and fingerprinting
- [nuclei](https://github.com/projectdiscovery/nuclei) — Template-based vulnerability and reconnaissance scanning
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — Community-maintained nuclei scan templates
- [naabu](https://github.com/projectdiscovery/naabu) — Fast port scanner
- [katana](https://github.com/projectdiscovery/katana) — Web crawling and spidering
- [AutoRecon](https://github.com/AutoRecon/AutoRecon) — Multi-threaded network reconnaissance tool
- [EyeWitness](https://github.com/RedSiege/EyeWitness) — Screenshot web services and identify default credentials
- [theHarvester](https://github.com/laramies/theHarvester) — Email, subdomain, and employee enumeration from public sources

### OSINT
- [spiderfoot](https://github.com/smicallef/spiderfoot) — Automated OSINT platform with 200+ modules
- [sherlock](https://github.com/sherlock-project/sherlock) — Username search across social networks
- [holehe](https://github.com/megadose/holehe) — Check email account registration across services
- [GHunt](https://github.com/mxrch/GHunt) — Investigate Google accounts
- [recon-ng](https://github.com/lanmaster53/recon-ng) — Web reconnaissance framework

### Privilege Escalation
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng) — LinPEAS and WinPEAS privilege escalation enumeration
- [LinEnum](https://github.com/rebootuser/LinEnum) — Linux privilege escalation enumeration script
- [wesng](https://github.com/bitsadmin/wesng) — Windows Exploit Suggester next generation
- [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) — Smart Linux privesc enumeration

### Web Exploitation
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — Automated SQL injection and database takeover tool
- [zaproxy](https://github.com/zaproxy/zaproxy) — OWASP ZAP web application security scanner
- [wapiti](https://github.com/wapiti-scanner/wapiti) — Web application vulnerability scanner
- [ffuf](https://github.com/ffuf/ffuf) — Fast web fuzzer for content discovery and parameter fuzzing
- [gobuster](https://github.com/OJ/gobuster) — Directory, file, and DNS brute-forcing tool
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload collection for every web vulnerability class
- [evilginx2](https://github.com/kgretzky/evilginx2) — Man-in-the-middle reverse proxy for credential and session capture

### Phishing & Social Engineering
- [gophish](https://github.com/gophish/gophish) — Open source phishing simulation framework
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) — TrustedSec social engineering framework

### Reference & Wordlists
- [SecLists](https://github.com/danielmiessler/SecLists) — The most-used collection of security wordlists for fuzzing and brute-force
- [HackTricks](https://github.com/carlospolop/hacktricks) — The community reference for pentesting techniques, attack commands, and methodology
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload cheat sheets for every attack class

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Hacker Playbook 3 | Peter Kim | Red team methodology, AD attacks, and bypass techniques in a structured scenario format |
| Penetration Testing | Georgia Weidman | Foundational pentesting methodology with lab-first approach |
| The Web Application Hacker's Handbook | Stuttard & Pinto | Comprehensive web exploitation reference covering every vulnerability class |
| Red Team Development and Operations | Joe Vest | Red team program design, tradecraft, and operational planning |
| Hacking: The Art of Exploitation | Jon Erickson | Low-level exploitation fundamentals; shellcode, buffer overflows, and memory manipulation |
| The Art of Intrusion | Kevin Mitnick | Real intrusion case studies with attacker methodology and thought process |

---

## Certifications

- **PNPT** (Practical Network Penetration Tester) — TCM Security's hands-on pentesting certification; report-based assessment; best value for practitioners
- **OSCP** (Offensive Security Certified Professional) — The industry benchmark; 24-hour hands-on exam; proves you can find and exploit vulnerabilities under pressure
- **CRTO** (Certified Red Team Operator) — Zero-Point Security; Cobalt Strike red team operations with real-world tradecraft
- **CRTE** (Certified Red Team Expert) — Active Directory and enterprise red team operations at advanced level
- **OSEP** (Offensive Security Experienced Penetration Tester) — Advanced bypasses, evasion, and mature target environments
- **CEH** (Certified Ethical Hacker) — Widely recognized vendor-neutral certification; more theory-focused

---

## Channels

- [IppSec](https://www.youtube.com/@ippsec) — The gold standard for learning offensive techniques through HackTheBox walkthroughs; every video teaches methodology, not just commands
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Practical pentesting instruction covering Active Directory, web apps, and real-world engagement methodology
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Active Directory attacks, C2 techniques, and adversary simulation walkthroughs
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, malware analysis, and offensive technique demonstrations
- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — Binary exploitation, CTF, and deep technical offensive research
- [The Cyber Mentor](https://www.youtube.com/@TCMSecurityAcademy) — Practical ethical hacking and penetration testing instruction

---

## Who to Follow

- [@HackingLZ](https://x.com/HackingLZ) — Chris Truncer; red team tooling and tradecraft
- [@424f424f](https://x.com/424f424f) — Rob Fuller; Active Directory attacks and pentesting
- [@gentilkiwi](https://x.com/gentilkiwi) — Benjamin Delpy; mimikatz author and Kerberos research
- [@harmj0y](https://x.com/harmj0y) — Will Schroeder; GhostPack and AD attack research
- [@_dirkjan](https://x.com/_dirkjan) — Dirk-jan Mollema; Azure/AD attacks, mitm6, ROADtools
- [@ly4k_](https://x.com/ly4k_) — Certipy author; AD CS attack research
- [@SpecterOps](https://x.com/SpecterOps) — BloodHound team; AD attack path research
- [@vysecurity](https://x.com/vysecurity) — Red team tradecraft and OPSEC
- [@TheHackersNews](https://x.com/TheHackersNews) — Vulnerability and exploit news

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map red team techniques to ATT&CK, correlate with CVE and EPSS data, and identify detection gaps across the matrix
- [HackTricks](https://book.hacktricks.xyz) — The community cheat sheet for every attack technique; search by protocol, service, or technique
- [GTFOBins](https://gtfobins.github.io) — Unix binary abuse reference for privilege escalation and defense bypass
- [LOLBAS](https://lolbas-project.github.io) — Living Off the Land Binaries and Scripts for Windows abuse techniques
- [Hack The Box](https://www.hackthebox.com) — The premier platform for offensive security skill development
- [Exploit-DB](https://www.exploit-db.com) — Archive of public exploits and proof-of-concept code
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Attack payload cheat sheets maintained by the community
