# Offensive Security

Simulating adversary tactics through penetration testing, red teaming, and adversary emulation to identify weaknesses before attackers do.

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
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — Comprehensive hacking techniques wiki
- [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — Internal network pentest cheat sheet
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payloads for all vulnerability types
- [SecLists](https://github.com/danielmiessler/SecLists) — Wordlists for fuzzing, credential attacks, and more
- [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) — Living Off The Land Binaries and Scripts for Windows
- [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) — Unix binary abuse for privilege escalation and shell escapes

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Penetration Testing: A Hands-On Introduction | Georgia Weidman | Lab-first approach to learning pentesting fundamentals |
| Red Team Field Manual (RTFM) | Ben Clark | On-engagement command reference — print this and keep it on your desk |
| The Hacker Playbook 3 | Peter Kim | Best practical AD attack coverage available in book form |
| Black Hat Python | Justin Seitz | Build your own offensive tools — pairs directly with OSCP preparation |
| Hacking: The Art of Exploitation | Jon Erickson | Teaches C, assembly, shellcode, and exploitation together |
| Advanced Penetration Testing | Wil Allsopp | Nation-state tradecraft, APT simulation, and custom C2 concepts |
| Attacking and Defending Active Directory | Nikhil Mittal | Focused entirely on AD attack paths, Kerberos, and defense |
| Windows Internals (Part 1 & 2) | Russinovich et al. | The definitive Windows OS internals reference |

## Certifications

- **OSCP** (Offensive Security Certified Professional) — The industry-standard hands-on pentesting certification
- **PNPT** (Practical Network Penetration Tester) — TCM Security's practical, report-based certification
- **CRTO** (Certified Red Team Operator) — Cobalt Strike tradecraft and red team operations
- **CRTE** (Certified Red Team Expert) — Advanced AD attacks with defense evasion
- **OSEP** (Offensive Security Experienced Penetration Tester) — Evasion techniques and mature environments

## Channels

- [IppSec](https://www.youtube.com/@ippsec) — HackTheBox machine walkthroughs with deep methodology explanations
- [The Cyber Mentor](https://www.youtube.com/@TCMSecurityAcademy) — Practical pentesting training and OSCP preparation
- [SpecterOps](https://www.youtube.com/@SpecterOps) — BloodHound, AD research, and red team operations
- [Red Team Village](https://www.youtube.com/@RedTeamVillage) — DEF CON red team village talks and workshops
- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — CTF challenges, exploit development, and RE with deep explanations
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTFs, malware analysis, and tool demonstrations
- [Antisyphon Training](https://www.youtube.com/@AntisyphonTraining) — Pay-what-you-can pentesting and detection courses

## Who to Follow

- [@harmj0y](https://x.com/harmj0y) — Will Schroeder; BloodHound co-creator and GhostPack author
- [@_wald0](https://x.com/_wald0) — Andy Robbins; BloodHound co-creator and AD research
- [@gentilkiwi](https://x.com/gentilkiwi) — Benjamin Delpy; Mimikatz author
- [@danielhbohannon](https://x.com/danielhbohannon) — PowerShell obfuscation and offensive scripting research
- [@enigma0x3](https://x.com/enigma0x3) — Matt Nelson; UAC bypass and AppLocker research
- [@tifkin_](https://x.com/tifkin_) — Lee Christensen; GhostPack co-author
- [@hdmoore](https://x.com/hdmoore) — HD Moore; Metasploit creator
- [@_RastaMouse](https://x.com/_RastaMouse) — Daniel Duggan; red team training and evasion research
- [@cobbr_io](https://x.com/cobbr_io) — Ryan Cobb; Covenant C2 and offensive .NET
- [@BishopFox](https://x.com/BishopFox) — Bishop Fox offensive security research
- [@OffSecTraining](https://x.com/OffSecTraining) — Offensive Security official

## Key Resources

- [HackTricks](https://book.hacktricks.xyz) — The most comprehensive hacking techniques reference
- [SpecterOps Blog](https://posts.specterops.io) — Regular deep-dive AD and offensive research posts
- [HackingThe.Cloud](https://hackingthe.cloud) — Cloud attack techniques and misconfigurations
- [LOLBAS Project](https://lolbas-project.github.io) — Searchable LOLBAS reference
- [GTFOBins](https://gtfobins.github.io) — Unix binary abuse reference
- [TryHackMe](https://tryhackme.com) — Guided labs for learning offensive techniques
- [HackTheBox](https://www.hackthebox.com) — Practice machines for developing real-world attack skills

---

*Part of the [TeamStarWolf](https://github.com/TeamStarWolf) community resource library.*
