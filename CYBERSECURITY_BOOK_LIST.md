# 📚 Cybersecurity Master Book & Resource List
> **The definitive reading list** — every book paired with hands-on GitHub repos, YouTube channels, certifications, and practice platforms. Built for practitioners, not checkbox collectors.

---

## 🗺️ Table of Contents

| # | Section | Level |
|---|---------|-------|
| 1 | [How To Use This List](#-how-to-use-this-list) | — |
| 2 | [Learning Paths](#-learning-paths) | — |
| 3 | [📰 News & Daily Intel](#-news--daily-intel) | — |
| 4 | [Core / Must-Read](#-core--must-read-high-signal) | All |
| 5 | [Offensive Security & Pentesting](#-offensive-security--pentesting) | 🟡🔴 |
| 6 | [Web Security & Bug Bounty](#-web-security--bug-bounty) | 🟡🔴 |
| 7 | [Active Directory & Windows Security](#-active-directory--windows-security) | 🟡🔴 |
| 8 | [Reverse Engineering & Malware Analysis](#-reverse-engineering--malware-analysis) | 🔴 |
| 9 | [Cryptography](#-cryptography) | 🟡🔴 |
| 10 | [Blue Team / Defense / SOC](#️-blue-team--defense--soc) | 🟢🟡 |
| 11 | [Threat Intelligence & Hunting](#-threat-intelligence--hunting) | 🟡🔴 |
| 12 | [OSINT / Privacy / Social Engineering](#️-osint--privacy--social-engineering) | 🟢🟡 |
| 13 | [Cloud Security](#️-cloud-security) | 🟡🔴 |
| 14 | [Mobile Security](#-mobile-security) | 🟡🔴 |
| 15 | [Hardware / IoT / ICS Security](#-hardware--iot--ics-security) | 🔴 |
| 16 | [Systems / Low-Level / Exploit Dev](#️-systems--low-level--exploit-dev) | 🔴 |
| 17 | [Research / Fuzzing](#-research--exploit-culture--fuzzing) | 🔴 |
| 18 | [Networking](#-networking-critical-foundation) | 🟢🟡 |
| 19 | [Programming for Hackers](#-programming-for-hackers) | 🟢🟡 |
| 20 | [Hacker Culture / History](#-hacker-culture--history--real-world-ops) | 🟢 |
| 21 | [AI / ML Security](#-ai--ml-security) | 🟡🔴 |
| 22 | [Certifications & Foundations](#-certifications--foundations) | 🟢🟡 |
| 23 | [Career / Getting Hired](#-career--getting-hired) | 🟢 |
| 24 | [Practice Environments](#-practice-environments) | All |
| 25 | [Coverage Summary](#-coverage-summary) | — |

**Difficulty Key:** 🟢 Beginner · 🟡 Intermediate · 🔴 Advanced

---

## 🧭 How To Use This List

This is not a list you read front-to-back. Use it as a **map**.

- **Pick your role first** → use the Learning Paths below
- **Read the book** → immediately open the paired repos and run something
- **Don't collect, apply** → the goal is one lab per chapter, not a bookshelf
- **Stack certifications with books** → each section shows which certs align
- **Use the YouTube channels** → some instructors are better than books

> 💡 **Pro tip:** For each book, spend 60% of your time in the repos. Reading without doing is just trivia accumulation.

---

## 🛤️ Learning Paths

### 🟢 Path 1: Complete Beginner → Security+
```
Networking Foundation → CompTIA guides → Security Engineering (ch 1-10)
→ HackTricks (browse) → TryHackMe free rooms → Security+ exam
```

### 🟡 Path 2: Security+ → OSCP
```
Penetration Testing (Weidman) → Hacker Playbook 3 → Black Hat Python
→ Hacking: Art of Exploitation → TCM Security courses → PNPT → OSCP
```

### 🟡 Path 3: Blue Team / SOC Analyst
```
Blue Team Field Manual → Practice of Network Security Monitoring
→ Incident Response & Computer Forensics → Sigma rules → Hayabusa labs
→ BTL1 cert → GCIH or CySA+
```

### 🔴 Path 4: Red Team Operator
```
Hacker Playbook 3 → Advanced Penetration Testing → RTFM
→ Windows Internals → BloodHound/AD labs → C2 framework mastery
→ CRTO → CRTE → OSEP
```

### 🔴 Path 5: Malware Analyst / DFIR
```
Practical Malware Analysis → Art of Memory Forensics
→ PMAT course + labs → RE with Ghidra/IDA → CAPEv2 sandbox
→ GCFE → GREM
```

### 🔴 Path 6: Vulnerability Researcher
```
Hacking: Art of Exploitation → Shellcoder's Handbook
→ Art of Software Security Assessment → Fuzzing book
→ AFL++ + CodeQL labs → bug bounty → CVE credits
```

---

## 📰 News & Daily Intel

> Stay current. Attackers don't take days off. These are the highest-signal free sources in the industry — bookmark them all, read daily.

### Breaking News
- [The Hacker News](https://thehackernews.com) — High-volume daily cybersecurity news — breaches, CVEs, threat actors
- [Bleeping Computer](https://www.bleepingcomputer.com) — Best breaking coverage on ransomware, malware, and vulnerability disclosures
- [The Record by Recorded Future](https://therecord.media) — Serious journalism on nation-state and criminal cyber operations
- [Dark Reading](https://www.darkreading.com) — Enterprise security news and in-depth analysis
- [SC Magazine](https://www.scmagazine.com) — Security industry news and product coverage
- [Krebs on Security](https://krebsonsecurity.com) — Brian Krebs — investigative cybercrime journalism, unmatched depth
- [TechCrunch Security](https://techcrunch.com/category/security/) — Tech-focused breach and vulnerability coverage
- [Network Computing](https://www.networkcomputing.com) — Infrastructure and network security news
- [Information Week Security](https://www.informationweek.com) — Enterprise security strategy and news

### Threat Intelligence & Research
- [SANS Internet Storm Center](https://isc.sans.edu/diaryarchive.html) — Daily threat diary from SANS handlers — excellent signal-to-noise ratio
- [Mandiant Blog](https://www.mandiant.com/resources/blog) — APT tracking, malware analysis, and incident reports
- [Google Project Zero](https://googleprojectzero.blogspot.com) — Elite vuln research — browser, kernel, and hardware bugs
- [SpecterOps Posts](https://posts.specterops.io) — AD and Windows attack research from the BloodHound team
- [DFIR Report](https://thedfirreport.com) — Real intrusion case studies — attacker TTPs from actual incidents
- [Offensive Security Research](https://www.offensive-security.com) — OffSec exploits, papers, and CVE research
- [Risky Business Podcast](https://risky.biz) — Weekly security news podcast — the best in the industry

### CVE & Vulnerability Tracking
- [NVD (NIST)](https://nvd.nist.gov) — Official CVE database with CVSS scores and patch info
- [CVE.mitre.org](https://cve.mitre.org) — Canonical CVE list and reference
- [Exploit-DB](https://www.exploit-db.com) — Public exploit archive — search by CVE, platform, or type
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities actively used by attackers — highest priority patching list
- [AttackerKB](https://attackerkb.com) — Community-rated CVE exploitability assessments
- [Vulners](https://vulners.com) — Aggregated vulnerability database with API access

> 💡 **Pro tip:** Subscribe to the CISA KEV RSS feed and set up a Google Alert for your organization's tech stack. The KEV catalog is the most actionable threat list available — if a CVE is on it, patch immediately.

---

## ⭐ Core / Must-Read (High Signal)

> Start here regardless of specialty. These books have the highest signal-to-page ratio in the field.

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Web Application Hacker's Handbook** | Stuttard & Pinto | 🟡 | Still the most complete web vuln reference ever written |
| **Penetration Testing** | Georgia Weidman | 🟢 | Best hands-on intro to pentesting — covers lab setup to exploitation |
| **The Hacker Playbook 3** | Peter Kim | 🟡 | Real engagement TTPs, AD attacks, red team tradecraft |
| **Practical Malware Analysis** | Sikorski & Honig | 🟡 | The definitive malware RE textbook — still unmatched |
| **Serious Cryptography** | Jean-Philippe Aumasson | 🟡 | Applied crypto for practitioners — no PhD required |
| **Security Engineering** | Ross Anderson | 🟡 | Broadest view of security as a systems problem — free online |

> 💡 **Pro tip:** Ross Anderson's *Security Engineering* (3rd ed.) is [free on his website](https://www.cl.cam.ac.uk/~rja14/book.html). Read it.

**🔧 Hands-on repos:**
- [HackTricks](https://github.com/HackTricks-wiki/hacktricks) — The living reference for every technique across all core books
- [awesome-security](https://github.com/sbilly/awesome-security) — Curated megalist of tools, papers, and resources
- [Awesome-Hacking-Resources](https://github.com/vitalysim/Awesome-Hacking-Resources) — Broad hacking resource collection

**📺 YouTube channels to pair:**
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, malware analysis, everything
- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — Deep technical security content
- [NetworkChuck](https://www.youtube.com/@NetworkChuck) — Entry-level networking + hacking fun

---

## 💻 Offensive Security & Pentesting

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Metasploit: The Penetration Tester's Guide** | Kennedy et al. | 🟢 | Framework bible — understand the tool you'll use on every engagement |
| **Black Hat Python** | Justin Seitz | 🟡 | Build your own offensive tools — pairs perfectly with OSCP |
| **Hacking: The Art of Exploitation** | Jon Erickson | 🔴 | The only book that teaches C, assembly, shellcode AND exploitation together |
| **Attacking Network Protocols** | James Forshaw | 🔴 | Deep protocol analysis and custom exploit dev for network services |
| **Real-World Bug Hunting** | Peter Yaworski | 🟢 | 35 real disclosed vulnerabilities with full methodology — great starter |
| **Advanced Penetration Testing** | Wil Allsopp | 🔴 | Nation-state tradecraft, APT simulation, custom C2 concepts |
| **Red Team Field Manual (RTFM)** | Ben Clark | 🟡 | On-engagement command reference — print this, keep it on your desk |
| **Bug Bounty Bootcamp** | Vickie Li | 🟢 | Modern web bug bounty methodology A-Z |
| **Web Hacking 101** | Peter Yaworski | 🟢 | Free on Leanpub — 30 real bug reports, great first bug bounty book |
| **Penetration Testing: A Hands-On Introduction** | Georgia Weidman | 🟢 | The lab-first approach to learning pentesting |

> 💡 **Pro tip:** Pair **RTFM + HackTricks + InternalAllTheThings** as your three-tab reference during any engagement. They cover Windows, Linux, and web respectively.

**🔧 Hands-on repos:**
- [metasploit-payloads](https://github.com/rapid7/metasploit-payloads) — Official Metasploit payloads (pairs directly with Metasploit book)
- [NetExec](https://github.com/Pennyw0rth/NetExec) — Modern network pentesting Swiss army knife (nxc)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) — Classic SMB/WinRM/LDAP pentesting framework
- [evil-winrm](https://github.com/Hackplayers/evil-winrm) — WinRM shell for post-exploitation
- [Responder](https://github.com/lgandx/Responder) — LLMNR/NBT-NS poisoner (essential for internal pentests)
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng) — LinPEAS / WinPEAS privilege escalation scripts
- [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) — Living Off The Land Binaries and Scripts (Windows)
- [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) — Unix binary abuse for privilege escalation and evasion
- [Seatbelt](https://github.com/GhostPack/Seatbelt) — Host situational awareness checks (C#)
- [SharpUp](https://github.com/GhostPack/SharpUp) — Windows privilege escalation checks (C#)
- [Snaffler](https://github.com/SnaffCon/Snaffler) — Find credentials/sensitive files in network shares
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) — SET phishing and exploitation framework
- [pentest_compilation](https://github.com/adon90/pentest_compilation) — Commands from OSCP and real engagements
- [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) — Internal pentest / Active Directory cheatsheets
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payloads and bypass techniques for every vuln class
- [Nemesis](https://github.com/SpecterOps/Nemesis) — Offensive data enrichment and triage pipeline
- [impacket](https://github.com/fortra/impacket) — Python classes for Windows network protocols (AD attacks)
- [nishang](https://github.com/samratashok/nishang) — PowerShell offensive security framework

**📋 Essential cheat sheet URLs (bookmark these):**
- [revshells.com](https://www.revshells.com) — Reverse shell generator for every language — instant copy/paste
- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/) — Free comprehensive Metasploit guide from OffSec
- [ropnop - Upgrading Shells to TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) — The definitive TTY upgrade guide
- [ropnop - Transferring Files Kali→Windows](https://blog.ropnop.com/transferring-files-from-kali-to-windows/) — All file transfer methods in one place
- [explainshell.com](https://explainshell.com) — Paste any shell command and get an explanation of every flag
- [Nmap NSE Script Docs](https://nmap.org/nsedoc/) — Full reference for all 600+ Nmap scripts
- [Nmap Cheat Sheet (highon.coffee)](https://highon.coffee/blog/nmap-cheat-sheet/) — Quick flag and scan type reference
- [LOLBAS Project](https://lolbas-project.github.io) — Windows Living Off The Land binary abuse

**🎓 Certifications:** OSCP · PNPT · eCPPT · GPEN · GCIH  
**📺 YouTube:** [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) · [IppSec](https://www.youtube.com/@ippsec) · [HackerSploit](https://www.youtube.com/@HackerSploit)  
**🏆 Practice:** [Hack The Box](https://hackthebox.com) · [TryHackMe](https://tryhackme.com) · [PentesterLab](https://pentesterlab.com)

---

## 🌐 Web Security & Bug Bounty

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Web Application Hacker's Handbook** | Stuttard & Pinto | 🟡 | Encyclopedic — every web vuln class explained with attack and defense |
| **Bug Bounty Bootcamp** | Vickie Li | 🟢 | Modern methodology, recon to report, focused on HackerOne/Bugcrowd |
| **Web Hacking 101** | Peter Yaworski | 🟢 | Real bug disclosures — learn what actually gets paid |
| **Browser Hackers Handbook** | Wade Alcorn | 🔴 | Browser internals, XSS to client-side exploitation depth |
| **The Tangled Web** | Michal Zalewski | 🔴 | How browsers work — essential for understanding client-side attacks |

> 💡 **Pro tip:** Subscribe to [portswigger.net/research](https://portswigger.net/research) and [HackerOne Hacktivity](https://hackerone.com/hacktivity). Real disclosed reports teach more than any book chapter.

**🔧 Hands-on repos:**
- [zaproxy](https://github.com/zaproxy/zaproxy) — OWASP ZAP web app scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) — Fast vulnerability scanner with 9000+ community templates
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — Community CVE/vuln detection templates
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap) — SSRF fuzzer and exploitation tool
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) — GraphQL injection and pentesting engine
- [Arjun](https://github.com/s0md3v/Arjun) — HTTP parameter discovery (hidden params = hidden vulns)
- [OWASP WSTG](https://github.com/OWASP/wstg) — Web Security Testing Guide — the methodology bible
- [OWASP ASVS](https://github.com/OWASP/ASVS) — Application Security Verification Standard
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — Subdomain takeover fingerprints and status
- [bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) — Payloads and tips per vuln class
- [Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups) — Real-world disclosed writeups by vulnerability type
- [client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) — Prototype pollution gadget database
- [HowToHunt](https://github.com/KathanP19/HowToHunt) — Web vuln hunting methodology with test cases
- [akto](https://github.com/akto-api-security/akto) — API security testing platform
- [dirsearch](https://github.com/maurosoria/dirsearch) — Web path and directory scanner
- [ffuf](https://github.com/ffuf/ffuf) — Blazing fast web fuzzer
- [gobuster](https://github.com/OJ/gobuster) — Directory/DNS/VHost/S3 enumeration
- [katana](https://github.com/projectdiscovery/katana) — Fast web crawler for attack surface mapping
- [httpx](https://github.com/projectdiscovery/httpx) — HTTP toolkit for probing web servers at scale
- [subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain enumeration tool
- [feroxbuster](https://github.com/epi052/feroxbuster) — Fast, recursive content discovery tool
- [caido](https://github.com/caido/caido) — Modern Burp alternative for web pentesting
- [dalfox](https://github.com/hahwul/dalfox) — XSS scanning and parameter analysis

**🎓 Certifications:** BSCP (PortSwigger) · eWPT · GWEB · OSWE  
**📺 YouTube:** [Rana Khalil](https://www.youtube.com/@RanaKhalil101) · [NahamSec](https://www.youtube.com/@NahamSec) · [STÖK](https://www.youtube.com/@STOKfredrik)  
**🏆 Practice:** [PortSwigger Web Academy](https://portswigger.net/web-security) (free) · [HackerOne](https://hackerone.com) · [Bugcrowd](https://bugcrowd.com) · [DVWA](https://github.com/digininja/DVWA)

---

## 🏰 Active Directory & Windows Security

> One of the most critical domains for red and blue teams. AD is present in ~90% of enterprise environments.

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Hacker Playbook 3** | Peter Kim | 🟡 | Best practical AD attack coverage in book form |
| **Windows Internals (Part 1 & 2)** | Russinovich et al. | 🔴 | The definitive Windows OS internals reference — understand what you're attacking |
| **Attacking and Defending Active Directory** | Nikhil Mittal | 🟡 | Focused entirely on AD attack paths, Kerberos, and defense |
| **The Art of Invisibility** | Kevin Mitnick | 🟢 | Operational security and evasion mindset |

> 💡 **Pro tip:** You don't need a book for AD attacks — [SpecterOps' blog](https://posts.specterops.io) and the BloodHound docs are more current than any book. Combine with labs.

**🔧 Hands-on repos:**
- [BloodHound](https://github.com/SpecterOps/BloodHound) — The definitive AD attack path mapping tool
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) — BloodHound data collector
- [impacket](https://github.com/fortra/impacket) — Python library for AD/Windows network protocols (GetTGT, secretsdump, etc.)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) — Swiss army knife for AD environments
- [NetExec](https://github.com/Pennyw0rth/NetExec) — The maintained CME successor
- [Rubeus](https://github.com/GhostPack/Rubeus) — Kerberos abuse toolkit (AS-REP roasting, pass-the-ticket, etc.)
- [Certify](https://github.com/GhostPack/Certify) — Find AD CS misconfigurations (ESC1-ESC8)
- [Certipy](https://github.com/ly4k/Certipy) — Python AD CS attack tool
- [Whisker](https://github.com/eladshamir/Whisker) — Shadow credentials attack tool
- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) — RBCD/Shadow Credentials relay escalation
- [responder](https://github.com/lgandx/Responder) — LLMNR/NBNS/MDNS poisoning
- [mitm6](https://github.com/dirkjanm/mitm6) — IPv6 DNS takeover for NTLM relay attacks
- [ntlmrelayx](https://github.com/fortra/impacket) — Part of Impacket — NTLM relay attacks
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh) — PowerShell LLMNR/NBNS spoofer
- [PowerView](https://github.com/PowerShellMafia/PowerSploit) — AD enumeration via PowerShell
- [ADRecon](https://github.com/adrecon/ADRecon) — Active Directory reconnaissance report generator
- [PingCastle](https://github.com/vletoux/pingcastle) — AD risk assessment and health check
- [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) — Find and abuse LAPS configurations
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) — Directory Services internals — dump hashes, manage AD
- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) — AD information via LDAP to HTML/JSON/CSV
- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) — SMB/LDAP enumeration tool rewrite
- [BloodyAD](https://github.com/CravateRouge/bloodyAD) — AD privilege escalation framework
- [pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) — GPO abuse for privilege escalation
- [ADFSDump](https://github.com/mandiant/ADFSDump) — Extract ADFS configuration (token signing certs)

**🎓 Certifications:** CRTO · CRTE · PNPT · OSEP · GXPN  
**📺 YouTube:** [IppSec](https://www.youtube.com/@ippsec) · [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) · [Orange Cyberdefense](https://www.youtube.com/@OrangeCyberdefense)  
**🏆 Practice:** [Hack The Box Pro Labs (RastaLabs, Offshore)](https://hackthebox.com) · [TCM AD Labs](https://tcm-sec.com) · [VulnLab](https://vulnlab.com)

---

## 🧠 Reverse Engineering & Malware Analysis

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Practical Malware Analysis** | Sikorski & Honig | 🟡 | Gold standard — every DFIR/malware analyst has read this |
| **Practical Binary Analysis** | Dennis Andriesse | 🔴 | Goes deeper on ELF, disassembly, and dynamic analysis |
| **The Ghidra Book** | Eagle & Nance | 🟡 | The only comprehensive Ghidra RE guide |
| **Malware Analyst's Cookbook** | Ligh et al. | 🟡 | 70+ recipes for analyzing malware samples |
| **Rootkits and Bootkits** | Matrosov et al. | 🔴 | Deep dive into UEFI/MBR-level malware — advanced |
| **Reversing: Secrets of RE** | Eldad Eilam | 🔴 | Classic — covers x86 RE techniques in depth |
| **Learning Malware Analysis** | Monnappa K A | 🟡 | Modern malware analysis walkthrough, Windows internals included |

> 💡 **Pro tip:** Build your own [FlareVM](https://github.com/mandiant/flare-vm) box. Run every sample you study in it. Reading about malware without running it is half the education.

**🔧 Hands-on repos:**
- [pe-bear](https://github.com/hasherezade/pe-bear) — PE file reversing GUI tool by @hasherezade
- [pe-sieve](https://github.com/hasherezade/pe-sieve) — Scan running processes for injected/hollow implants
- [hollows_hunter](https://github.com/hasherezade/hollows_hunter) — Detect and dump process hollowing
- [malware_training_vol1](https://github.com/hasherezade/malware_training_vol1) — Windows malware analysis training materials
- [capa](https://github.com/mandiant/capa) — FLARE tool — identify executable capabilities automatically
- [flare-vm](https://github.com/mandiant/flare-vm) — Windows malware analysis VM setup scripts (automated)
- [flare-floss](https://github.com/mandiant/flare-floss) — Extract obfuscated strings from malware automatically
- [flare-fakenet-ng](https://github.com/mandiant/flare-fakenet-ng) — Simulate network responses for dynamic analysis
- [flare-ida](https://github.com/mandiant/flare-ida) — IDA Pro plugins and scripts from the FLARE team
- [dnSpy](https://github.com/dnSpy/dnSpy) — .NET debugger and assembly editor (decompile C#/VB.NET)
- [cutter](https://github.com/rizinorg/cutter) — Free and open RE platform (Rizin/Radare2 GUI)
- [radare2](https://github.com/radareorg/radare2) — UNIX-like reverse engineering framework
- [yara](https://github.com/VirusTotal/yara) — Pattern matching for malware identification
- [yarGen](https://github.com/Neo23x0/yarGen) — Generate YARA rules from malware strings
- [signature-base](https://github.com/Neo23x0/signature-base) — YARA rules and IOC database by @cyb3rops
- [volatility](https://github.com/volatilityfoundation/volatility) — Memory forensics framework (v2)
- [volatility3](https://github.com/volatilityfoundation/volatility3) — Volatility 3 — modern memory forensics
- [CAPEv2](https://github.com/kevoreilly/CAPEv2) — Malware config + payload extraction sandbox
- [PMAT-labs](https://github.com/HuskyHacks/PMAT-labs) — Practical Malware Analysis & Triage course labs
- [learning-malware-analysis](https://github.com/jstrosch/learning-malware-analysis) — Safe malware-mimicking sample programs
- [Malware-analysis-and-Reverse-engineering](https://github.com/Dump-GUY/Malware-analysis-and-Reverse-engineering) — Public writeups with samples
- [Gepetto](https://github.com/JusticeRage/Gepetto) — IDA Pro + LLM plugin for RE assistance
- [Manalyze](https://github.com/JusticeRage/Manalyze) — Static analyzer for PE executables
- [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) — File type, packer, and compiler detector
- [pafish](https://github.com/a0rtega/pafish) — Test VM/sandbox evasion detection techniques
- [malwoverview](https://github.com/alexandreborges/malwoverview) — First response malware triage tool
- [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) — Curated malware analysis resource list
- [awesome-reversing](https://github.com/tylerha97/awesome-reversing) — Curated reversing resource list
- [theZoo](https://github.com/ytisf/theZoo) — Live malware samples for analysis practice (handle safely!)

**🎓 Certifications:** GREM · eCMAP · GCFE · GCFA · CREA  
**📺 YouTube:** [OALabs](https://www.youtube.com/@OALABS) · [MalwareAnalysisForHedgehogs](https://www.youtube.com/@MalwareAnalysisForHedgehogs) · [hasherezade](https://www.youtube.com/@hasherezade)  
**🏆 Practice:** [MalwareBazaar](https://bazaar.abuse.ch) · [ANY.RUN](https://any.run) · [Hybrid Analysis](https://hybrid-analysis.com) · [VirusTotal](https://virustotal.com)

---

## 🔐 Cryptography

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Serious Cryptography** | Jean-Philippe Aumasson | 🟡 | Best applied crypto book — real implementations, not just theory |
| **Cryptography Engineering** | Ferguson, Schneier, Kohno | 🟡 | Practical crypto engineering — how to build it correctly |
| **Understanding Cryptography** | Paar & Pelzl | 🟡 | Textbook quality — excellent for understanding primitives |
| **Real-World Cryptography** | David Wong | 🟡 | Modern crypto protocols — TLS 1.3, Signal, Noise framework |
| **An Introduction to Mathematical Cryptography** | Hoffstein et al. | 🔴 | The math behind it — for researchers who want depth |

> 💡 **Pro tip:** [CryptoHack](https://cryptohack.org) is the best free hands-on crypto learning platform. Pair every chapter of Serious Cryptography with the relevant CryptoHack challenges.

**🔧 Hands-on repos:**
- [sigstore](https://github.com/sigstore/sigstore) — Code signing and supply chain security (applied crypto)
- [cosign](https://github.com/sigstore/cosign) — Container and binary signing
- [getsops/sops](https://github.com/getsops/sops) — Secrets management with envelope encryption (AGE/KMS)
- [hashicorp/vault](https://github.com/hashicorp/vault) — Secrets management with HSM and PKI support
- [age](https://github.com/FiloSottile/age) — Simple, modern file encryption tool by @FiloSottile
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — Find leaked secrets in git history
- [gitleaks](https://github.com/gitleaks/gitleaks) — Detect secrets in code/git history
- [awesome-ethereum-security](https://github.com/crytic/awesome-ethereum-security) — Blockchain/smart contract crypto security
- [CryptoHack challenges](https://github.com/cryptohack/cryptohack-blog) — Platform for learning practical crypto through challenges

**🎓 Certifications:** GCFE (crypto section) · CISSP (domain 3) · CEH (cryptography module)  
**📺 YouTube:** [Christof Paar Lectures](https://www.youtube.com/@introductiontocryptography4223) · [David Wong](https://www.youtube.com/@cryptologie)  
**🏆 Practice:** [CryptoHack](https://cryptohack.org) · [Cryptopals Challenges](https://cryptopals.com)

---

## 🛡️ Blue Team / Defense / SOC

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Blue Team Field Manual (BTFM)** | Clark & Robertson | 🟢 | The defender's desk reference — commands for every IR task |
| **Incident Response & Computer Forensics** | Luttgens et al. | 🟡 | Structured IR methodology — what to do when the alarm fires |
| **The Practice of Network Security Monitoring** | Richard Bejtlich | 🟡 | NSM fundamentals — how to build a detection program |
| **Security Operations Center** | Joseph Muniz | 🟢 | SOC design, staffing, tools, and metrics — good for SOC leads |
| **Applied Network Security Monitoring** | Sanders & Smith | 🟡 | Practical NSM with Bro/Zeek and Snort — lab-first |
| **Crafting the InfoSec Playbook** | Bollinger et al. | 🟡 | Building detection strategies and security analytics |
| **The DFIR Report** | Various | 🟡 | Not a book — [thedfirreport.com](https://thedfirreport.com) — real intrusion analysis reports |

> 💡 **Pro tip:** The [DFIR Report](https://thedfirreport.com) publishes real intrusion case studies. Read every report — they're more valuable than most books on defense.

**🔧 Hands-on repos:**
- [sigma](https://github.com/SigmaHQ/sigma) — Generic SIEM detection rule format — the Rosetta Stone of detections
- [pySigma](https://github.com/SigmaHQ/pySigma) — Convert Sigma rules to any SIEM query language
- [hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma-based Windows event log threat hunting (fast)
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) — PowerShell event log threat hunting (SANS)
- [detection-rules](https://github.com/elastic/detection-rules) — Elastic SIEM detection rules
- [security_content](https://github.com/splunk/security_content) — Splunk Security detection content
- [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) — Artifacts and keywords for threat hunting
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — Community threat hunting playbooks mapped to ATT&CK
- [Loki](https://github.com/Neo23x0/Loki) — Simple IOC and YARA scanner for incident response
- [rita](https://github.com/activecm/rita) — Detect C2 beaconing through statistical network analysis
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) — Visualize malicious Windows logon activity
- [HELK](https://github.com/Cyb3rWard0g/HELK) — Hunting ELK stack for threat hunting
- [TheHive](https://github.com/TheHive-Project/TheHive) — Collaborative IR case management platform
- [Cortex](https://github.com/TheHive-Project/Cortex) — Observable analysis and response automation
- [adversary_emulation_library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) — ATT&CK-based adversary emulation plans
- [attack-navigator](https://github.com/mitre-attack/attack-navigator) — ATT&CK matrix visualization and tracking
- [caldera](https://github.com/mitre/caldera) — Automated adversary emulation platform
- [atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Atomic tests for each ATT&CK technique
- [uac](https://github.com/tclahr/uac) — Live response artifact collection for IR
- [velociraptor](https://github.com/Velocidex/velociraptor) — Endpoint visibility and digital forensics platform
- [timesketch](https://github.com/google/timesketch) — Timeline analysis for DFIR
- [plaso](https://github.com/log2timeline/plaso) — Super timeline creation from forensic artifacts
- [awesome-incident-response](https://github.com/meirwah/awesome-incident-response) — Curated IR tools and resources
- [awesome-detection-engineering](https://github.com/infosecB/awesome-detection-engineering) — Detection engineering resources
- [awesome-threat-detection](https://github.com/0x4D31/awesome-threat-detection) — Threat detection and hunting resources
- [chainsaw](https://github.com/WithSecureLabs/chainsaw) — Hunt through Windows event logs fast

**🎓 Certifications:** BTL1 · GCIH · GCFE · GCFA · CySA+ · BlueTeamLabs  
**📺 YouTube:** [Eric Capuano](https://www.youtube.com/@reginald254) · [SANS DFIR](https://www.youtube.com/@SANSForensics) · [13Cubed](https://www.youtube.com/@13Cubed)  
**🏆 Practice:** [Blue Team Labs Online](https://blueteamlabs.online) · [CyberDefenders](https://cyberdefenders.org) · [LetsDefend](https://letsdefend.io)

---

## 🔍 Threat Intelligence & Hunting

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Threat Intelligence Handbook** | CyberEdge Group | 🟢 | Free PDF — SOC-focused TI fundamentals |
| **Intelligence-Driven Incident Response** | Rebekah Brown & Scott Roberts | 🟡 | F3EAD and Diamond Model applied to IR |
| **Hacking the Hacker** | Roger Grimes | 🟢 | Profiles of 26 top security researchers and their methods |
| **Applied Incident Response** | Steve Anson | 🟡 | Practical IR with Windows forensics and TI context |

> 💡 **Pro tip:** Follow [MITRE ATT&CK](https://attack.mitre.org) updates religiously. Every new technique published is a gap you can fill with a detection. Subscribe to CISA advisories and Mandiant threat reports.

**🔧 Hands-on repos:**
- [MITRE ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) — Map detections and coverage against ATT&CK
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) — Open source threat intelligence platform
- [MISP](https://github.com/MISP/MISP) — Malware Information Sharing Platform (the standard for TI sharing)
- [IntelMQ](https://github.com/certtools/intelmq) — TI feed collection and processing framework
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — Hunt procedures mapped to ATT&CK
- [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) — Hunting keywords by technique
- [APTnotes](https://github.com/kbandla/APTnotes) — Public APT campaign documents going back years
- [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence) — Curated TI feeds, tools, and resources
- [yeti](https://github.com/yeti-platform/yeti) — Your Everyday Threat Intelligence platform
- [Harpoon](https://github.com/Te-k/harpoon) — CLI tool for TI — VirusTotal, Shodan, Passive DNS
- [ioc-finder](https://github.com/fhightower/ioc-finder) — Extract IOCs from text automatically
- [CyberChef](https://github.com/gchq/CyberChef) — The Swiss army knife for data transformation and IOC decoding
- [urlscan.io](https://github.com/ninoseki/mihari) — Continuous IOC monitoring framework (mihari)
- [vt-cli](https://github.com/VirusTotal/vt-cli) — VirusTotal CLI for automated lookups
- [Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) — 100+ analyzers for TI enrichment

**🎓 Certifications:** GCTI · CREST CPSA · FOR578 (SANS TI) · eCTHP  
**📺 YouTube:** [Recorded Future](https://www.youtube.com/@RecordedFuture) · [SANS Threat Hunting](https://www.youtube.com/@SANSForensics)  
**🏆 Practice:** [MITRE ATT&CK Evaluations](https://attackevals.mitre-engenuity.org) · [RangeForce](https://rangeforce.com)

---

## 🕵️ OSINT / Privacy / Social Engineering

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **OSINT Techniques** | Michael Bazzell | 🟢 | The definitive OSINT methodology book — updated annually |
| **Extreme Privacy** | Michael Bazzell | 🟢 | How to disappear from data brokers and the internet |
| **Open Source Intelligence Techniques** (older ed.) | Michael Bazzell | 🟢 | Earlier edition — still valuable for foundational methods |
| **Social Engineering: The Science of Human Hacking** | Christopher Hadnagy | 🟢 | Psychological manipulation for security purposes |
| **People Hacker** | Jenny Radcliffe | 🟢 | Real-world physical and social engineering stories |
| **The Art of Deception** | Kevin Mitnick | 🟢 | Classic — social engineering case studies from the master |

> 💡 **Pro tip:** Michael Bazzell's [Privacy, Security & OSINT Show](https://inteltechniques.com/podcast.html) podcast covers updates that keep the book current. Subscribe and listen while commuting.

**🔧 Hands-on repos:**
- [awesome-osint](https://github.com/jivoi/awesome-osint) — Comprehensive curated OSINT resource list
- [osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) — 300+ online OSINT tools and services
- [spiderfoot](https://github.com/smicallef/spiderfoot) — Automated OSINT and attack surface mapping
- [theHarvester](https://github.com/laramies/theHarvester) — Email, subdomain, name, and DNS harvesting
- [GHunt](https://github.com/mxrch/GHunt) — Google account OSINT framework
- [maigret](https://github.com/soxoj/maigret) — Username search across 3000+ sites
- [holehe](https://github.com/megadose/holehe) — Check if email is registered across services
- [phoneinfoga](https://github.com/sundowndev/phoneinfoga) — Phone number intelligence gathering
- [social-analyzer](https://github.com/qeeqbox/social-analyzer) — Profile finder across 1000+ social sites
- [h8mail](https://github.com/khast3x/h8mail) — Email OSINT and breach data hunting
- [gitrob](https://github.com/michenriksen/gitrob) — GitHub organization sensitive data recon
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — Find secrets in git repos — leaked API keys, tokens
- [social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit) — Phishing, credential harvesting, pretexting
- [gophish](https://github.com/gophish/gophish) — Open-source phishing campaign framework
- [sherlock](https://github.com/sherlock-project/sherlock) — Username hunting across social networks
- [recon-ng](https://github.com/lanmaster53/recon-ng) — Modular OSINT framework (like Metasploit for OSINT)
- [Maltego community](https://github.com/MaltegoTech/maltego-trx) — Graph-based OSINT visualization framework
- [OSINT-Framework](https://github.com/lockfale/OSINT-Framework) — Web-based OSINT tool directory organized by category

**🎓 Certifications:** OSINT Curious · GOSI · CREST · Trace Labs OSINT CTF  
**📺 YouTube:** [Michael Bazzell](https://www.youtube.com/@IntelTechniques) · [OSINT Dojo](https://www.youtube.com/@OSINTDojo) · [Bendobrown](https://www.youtube.com/@Bendobrown)  
**🏆 Practice:** [TraceLabs Missing Persons CTF](https://tracelabs.org) · [Bellingcat Online Investigations](https://www.bellingcat.com)

---

## ☁️ Cloud Security

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **CCSP Official Study Guide** | Chapple & Seidl | 🟡 | Broad cloud security foundations — covers AWS/Azure/GCP concepts |
| **Hacking the Cloud** | Various (online) | 🟡 | [hackingthe.cloud](https://hackingthe.cloud) — free, updated constantly |
| **AWS Security Handbook** | Marzia Kjell | 🟡 | Practical AWS security from misconfig to exploitation |
| **Cloud Security and Privacy** | Tim Mather | 🟢 | Executive/architect level cloud security overview |
| **Kubernetes Security and Observability** | Liz Rice | 🟡 | Container and K8s security depth |
| **Hacking Kubernetes** | Rice & Hausenblas | 🔴 | Attack and defense for Kubernetes environments |

> 💡 **Pro tip:** Cloud attack paths change fast — [HackingThe.Cloud](https://hackingthe.cloud) and [CloudSecDocs](https://cloudsecdocs.com) are more current than any book. Pair with hands-on labs in a personal AWS/Azure free tier account.

**🔧 Hands-on repos:**
- [pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework
- [prowler](https://github.com/prowler-cloud/prowler) — Cloud security posture assessment (AWS/Azure/GCP)
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — Multi-cloud security auditing tool
- [cloudmapper](https://github.com/duo-labs/cloudmapper) — AWS environment analysis and network visualization
- [MicroBurst](https://github.com/NetSPI/MicroBurst) — Azure security assessment PowerShell scripts
- [AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) — Entra ID attack scenarios and detections
- [AzureADAssessment](https://github.com/AzureAD/AzureADAssessment) — Azure AD tenant security assessment
- [AADInternals](https://github.com/Gerenios/AADInternals) — Azure AD / M365 offensive/defensive PowerShell toolkit
- [ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD recon, token abuse, attack framework
- [checkov](https://github.com/bridgecrewio/checkov) — IaC security scanning (Terraform, CloudFormation, etc.)
- [trivy](https://github.com/aquasecurity/trivy) — Container, cloud, and IaC vulnerability scanner
- [open-cvdb](https://github.com/wiz-sec/open-cvdb) — Public cloud vulnerability database by Wiz
- [untitledgoosetool](https://github.com/cisagov/untitledgoosetool) — CISA Azure/M365 incident response tool
- [terrascan](https://github.com/tenable/terrascan) — IaC compliance and security scanning
- [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) — Microsoft Sentinel detection rules and workbooks
- [kube-bench](https://github.com/aquasecurity/kube-bench) — CIS Kubernetes benchmark security checks
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) — Kubernetes security weakness discovery
- [falco](https://github.com/falcosecurity/falco) — Cloud-native runtime security — detect suspicious behavior
- [cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) — Intentionally vulnerable AWS environment for practice
- [TerraformGoat](https://github.com/HXSecurity/TerraformGoat) — Vulnerable Terraform deployments for cloud security labs
- [stratus-red-team](https://github.com/DataDog/stratus-red-team) — Cloud threat emulation for AWS/Azure/GCP
- [cloud-custodian](https://github.com/cloud-custodian/cloud-custodian) — Rules engine for cloud governance and security

**🎓 Certifications:** CCSP · AWS Security Specialty · CCSK · KCSA · GCP Security Engineer  
**📺 YouTube:** [CloudSecurityPodcast](https://www.youtube.com/@CloudSecurityPodcast) · [fwd:cloudsec](https://www.youtube.com/@fwdcloudsec) · [Nick Jones (NCC)](https://www.youtube.com/@nickjones)  
**🏆 Practice:** [CloudGoat (Rhino)](https://github.com/RhinoSecurityLabs/cloudgoat) · [flaws.cloud](http://flaws.cloud) · [flaws2.cloud](http://flaws2.cloud) · [AWSGoat](https://github.com/ine-labs/AWSGoat)

---

## 📱 Mobile Security

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Mobile Application Hacker's Handbook** | Lodge et al. | 🟡 | Comprehensive iOS and Android attack surface coverage |
| **Android Security Internals** | Nikolay Elenkov | 🔴 | Deep Android security architecture — for serious analysts |
| **iOS Application Security** | David Thiel | 🟡 | Practical iOS app testing and reverse engineering |
| **Hacking and Securing iOS Applications** | Jonathan Zdziarski | 🟡 | Classic — covers iOS forensics and security research |

> 💡 **Pro tip:** [OWASP Mobile Security Testing Guide (MSTG)](https://mas.owasp.org/MASTG/) is free and more current than any book. Use it as your primary reference alongside these books.

**🔧 Hands-on repos:**
- [Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg) — OWASP MSTG — the mobile security bible
- [Mobile Application Security Checklist](https://github.com/OWASP/owasp-masvs) — OWASP MASVS verification standard
- [objection](https://github.com/sensepost/objection) — Mobile runtime exploration powered by Frida
- [frida](https://github.com/frida/frida) — Dynamic instrumentation toolkit for iOS/Android/desktop
- [apktool](https://github.com/iBotPeaches/Apktool) — Android APK reverse engineering tool
- [jadx](https://github.com/skylot/jadx) — DEX/APK to Java decompiler with GUI
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Mobile Security Framework — static/dynamic analysis
- [androguard](https://github.com/androguard/androguard) — Android app analysis in Python
- [drozer](https://github.com/WithSecureLabs/drozer) — Android security assessment framework
- [dexcalibur](https://github.com/FrenchYeti/dexcalibur) — Android reverse engineering with Frida hooks
- [gplaycli](https://github.com/matlink/gplaycli) — Download APKs from Google Play for analysis
- [needle](https://github.com/WithSecureLabs/needle) — iOS security assessment framework
- [idb](https://github.com/dmayer/idb) — iOS app security assessment tool
- [iphonebackupanalyzer](https://github.com/PicciMario/iPhone-Backup-Analyzer) — Parse iOS backups for DFIR

**🎓 Certifications:** eMAPT · GMOB (GIAC) · eWMD  
**📺 YouTube:** [B3nac](https://www.youtube.com/@B3nacSec) · [HackerOne mobile track](https://www.youtube.com/@HackerOneTV)  
**🏆 Practice:** [DIVA Android](https://github.com/payatu/diva-android) · [iGoat](https://github.com/OWASP/iGoat-Swift) · [HpAndro Android Security](https://github.com/RavikumarRamesh/hpAndro1337)

---

## 🔌 Hardware / IoT / ICS Security

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **The Hardware Hacker** | Andrew "bunnie" Huang | 🟡 | Hardware reverse engineering and supply chain attacks — fascinating |
| **Practical IoT Hacking** | Fotios Chantzis et al. | 🟡 | Protocol attacks, firmware extraction, radio hacking |
| **Hacking Embedded Linux** | Craig Smith | 🟡 | Embedded system security from firmware to exploitation |
| **The Car Hacker's Handbook** | Craig Smith | 🟡 | CAN bus, OBD-II, and automotive security |
| **Industrial Network Security** | Knapp & Langill | 🟡 | ICS/SCADA security fundamentals and defense |
| **Hacking the Xbox** | Andrew "bunnie" Huang | 🟢 | Classic hardware hacking — still relevant for methodology |

> 💡 **Pro tip:** A $20 RTL-SDR dongle and [GQRX](https://gqrx.dk) gets you into RF analysis. A $50 Flipper Zero gets you into sub-GHz, NFC, and infrared. Hardware hacking is cheaper to start than most people think.

**🔧 Hands-on repos:**
- [firmwalker](https://github.com/craigz28/firmwalker) — Search extracted firmware for interesting files
- [binwalk](https://github.com/ReFirmLabs/binwalk) — Firmware analysis, extraction, and reverse engineering
- [firmae](https://github.com/pr0v3rbs/FirmAE) — Emulate firmware for dynamic analysis
- [FACT_core](https://github.com/fkie-cad/FACT_core) — Firmware Analysis and Comparison Tool
- [OpenWRT exploit collection](https://github.com/threat9/routersploit) — RouterSploit — router exploitation framework
- [flashrom](https://github.com/flashrom/flashrom) — Read/write flash chips
- [IoTGoat](https://github.com/OWASP/IoTGoat) — OWASP IoT security testing practice firmware
- [awesome-embedded-and-iot-security](https://github.com/fkie-cad/awesome-embedded-and-iot-security) — Curated IoT/embedded security resources
- [ICS/SCADA resources](https://github.com/hslatman/awesome-industrial-control-system-security) — Curated ICS/SCADA security resource list
- [GNURadio](https://github.com/gnuradio/gnuradio) — Software-defined radio toolkit for RF analysis
- [URH](https://github.com/jopohl/urh) — Universal Radio Hacker — analyze wireless protocols

**🎓 Certifications:** GICSP (ICS Security) · ICS-CERT training · CSSA  
**📺 YouTube:** [Joe Grand (Kingpin)](https://www.youtube.com/@JoeGrand) · [Phil's Lab](https://www.youtube.com/@PhilsLab) · [LiveOverflow Hardware](https://www.youtube.com/@LiveOverflow)  
**🏆 Practice:** [Hack The Box IoT challenges](https://hackthebox.com) · [DVID](https://github.com/Vulcainreo/DVID) · [Damn Vulnerable Router Firmware](https://github.com/threat9/dvrf)

---

## ⚙️ Systems / Low-Level / Exploit Dev

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Hacking: The Art of Exploitation** | Jon Erickson | 🔴 | Teaches C, assembly, buffer overflows, shellcode all in one |
| **The Shellcoder's Handbook** | Koziol et al. | 🔴 | Deep shellcode and exploit technique reference |
| **Linux Hardening in Hostile Networks** | Kyle Rankin | 🟡 | Practical Linux defense — kernel hardening to network security |
| **Windows Internals (Part 1 & 2)** | Russinovich et al. | 🔴 | If you exploit Windows, you must understand it first |
| **The Art of Memory Forensics** | Ligh et al. | 🔴 | Memory forensics in depth — Windows/Linux/Mac internals |
| **Rootkits and Bootkits** | Matrosov et al. | 🔴 | Persistence at the deepest level — UEFI, MBR, bootkit analysis |

> 💡 **Pro tip:** [pwn.college](https://pwn.college) from Arizona State University is the best free platform for learning binary exploitation from zero to hero. Do it before the books — they'll make more sense after.

**🔧 Hands-on repos:**
- [pwndbg](https://github.com/pwndbg/pwndbg) — GDB plugin for exploit dev and RE (most popular)
- [pwntools](https://github.com/Gallopsled/pwntools) — CTF framework and exploit development library in Python
- [gef](https://github.com/hugsy/gef) — GDB Enhanced Features — alternative to pwndbg
- [peda](https://github.com/longld/peda) — Python Exploit Development Assistance for GDB
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) — Find ROP gadgets for ROP chain construction
- [angr](https://github.com/angr/angr) — Binary analysis platform — symbolic execution
- [unicorn](https://github.com/unicorn-engine/unicorn) — Lightweight CPU emulator framework
- [volatility3](https://github.com/volatilityfoundation/volatility3) — Memory forensics (pairs with Art of Memory Forensics)
- [MalConfScan](https://github.com/JPCERTCC/MalConfScan) — Volatility plugin for malware config extraction
- [Detours](https://github.com/microsoft/Detours) — Microsoft API monitoring and instrumentation
- [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) — Directory Services Internals PowerShell module
- [kernel-exploits](https://github.com/lucyoa/kernel-exploits) — Kernel exploit collection for learning and practice
- [one_gadget](https://github.com/david942j/one_gadget) — Find one-gadget RCE in libc
- [pwninit](https://github.com/io12/pwninit) — Automate PWN challenge setup
- [seccomp-tools](https://github.com/david942j/seccomp-tools) — Analyze seccomp rules in binary exploitation
- [checksec](https://github.com/slimm609/checksec.sh) — Check binary security mitigations (NX, PIE, RELRO, stack canary)
- [ropper](https://github.com/sashs/Ropper) — ROP gadget finder and chain builder
- [heap-exploitation](https://github.com/DhavalKapil/heap-exploitation) — Heap exploitation techniques guide

**🎓 Certifications:** OSED · OSCE³ · GXPN · eCXD  
**📺 YouTube:** [pwn.college](https://www.youtube.com/@pwncollege) · [LiveOverflow](https://www.youtube.com/@LiveOverflow) · [ir0nstone](https://www.youtube.com/@ir0nstone)  
**🏆 Practice:** [pwn.college](https://pwn.college) · [exploit.education](https://exploit.education) · [ROP Emporium](https://ropemporium.com) · [pwnable.kr](https://pwnable.kr)

---

## 🧪 Research / Exploit Culture / Fuzzing

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **POC \|\| GTFO** | Manul Laphroaig (ed.) | 🔴 | The hacker magazine — culture, craftsmanship, and chaos |
| **POC \|\| GTFO II** | Manul Laphroaig (ed.) | 🔴 | Second volume — mandatory for the researcher mindset |
| **The Art of Software Security Assessment** | Dowd, McDonald, Schuh | 🔴 | The bible of source code auditing — still unmatched |
| **Fuzzing for Software Security Testing** | Sutton, Greene, Amini | 🟡 | Classic fuzzing fundamentals — structure-aware to black-box |
| **The Fuzzing Book** | Zeller et al. | 🟡 | [Free online](https://www.fuzzingbook.org) — modern fuzzing from greybox to symbolic |

> 💡 **Pro tip:** Google Project Zero's [blog](https://googleprojectzero.blogspot.com) and [research repo](https://github.com/google/security-research) are the highest-signal free content in vulnerability research. Read every post.

**🔧 Hands-on repos:**
- [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) — AFL++ coverage-guided fuzzer — the standard
- [honggfuzz](https://github.com/google/honggfuzz) — Security-oriented, multi-process fuzzer from Google
- [oss-fuzz](https://github.com/google/oss-fuzz) — Continuous fuzzing for open source projects
- [clusterfuzz](https://github.com/google/clusterfuzz) — Google's scalable fuzzing infrastructure
- [winafl](https://github.com/googleprojectzero/winafl) — AFL for Windows binaries (Project Zero)
- [Jackalope](https://github.com/googleprojectzero/Jackalope) — Binary coverage-guided fuzzer (Project Zero)
- [boofuzz](https://github.com/jtpereyda/boofuzz) — Network protocol fuzzer — successor to Sulley
- [codeql](https://github.com/github/codeql) — Semantic code analysis for vulnerability research
- [google/security-research](https://github.com/google/security-research) — Google security advisories with working PoCs
- [Fuzzing-Against-the-Machine](https://github.com/PacktPublishing/Fuzzing-Against-the-Machine) — Book companion with labs
- [libFuzzer](https://github.com/llvm/llvm-project) — Part of LLVM — coverage-guided fuzzing library
- [pwnautomate](https://github.com/n0mi1k/apkleaks) — Scanning for secrets in decompiled APKs
- [semgrep](https://github.com/semgrep/semgrep) — Static analysis for finding bugs at scale

**🎓 Certifications:** OSED · OSCE · CVE credits are better than any cert here  
**📺 YouTube:** [Google Project Zero](https://www.youtube.com/@GoogleProjectZero) · [Trail of Bits](https://www.youtube.com/@trailofbits) · [USENIX Security](https://www.youtube.com/@USENIXSecurity)  
**🏆 Practice:** [Fuzzbench](https://github.com/google/fuzzbench) · Google VRP · HackerOne bounties

---

## 📈 Networking (Critical Foundation)

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Computer Networking: A Top-Down Approach** | Kurose & Ross | 🟢 | The university standard — if you don't know TCP/IP deeply, start here |
| **TCP/IP Illustrated (Vol 1)** | W. Richard Stevens | 🟡 | The deep reference — every protocol dissected with packet traces |
| **Network+ Certification All-in-One** | Mike Meyers | 🟢 | Hands-on cert prep with good conceptual coverage |
| **The Practice of Network Security Monitoring** | Richard Bejtlich | 🟡 | NSM methodology — tools, visibility, and program building |
| **Attacking Network Protocols** | James Forshaw | 🔴 | Protocol RE and custom exploit dev for network services |

> 💡 **Pro tip:** Spin up a home lab with a pfSense router and a managed switch. Capture your own traffic, build your own Zeek/Suricata instance. You'll learn more in a week than in a month of reading.

**🔧 Hands-on repos:**
- [wireshark](https://github.com/wireshark/wireshark) — The standard packet capture and analysis tool
- [zeek](https://github.com/zeek/zeek) — Network analysis framework — turn pcaps into structured logs
- [suricata](https://github.com/OISF/suricata) — Network IDS/IPS/NSM engine
- [snort3](https://github.com/snort3/snort3) — Snort 3 IDS — the classic reinvented
- [bettercap](https://github.com/bettercap/bettercap) — Network MITM, recon, and 802.11/BLE attacks
- [masscan](https://github.com/robertdavidgraham/masscan) — Internet-scale port scanner (10M packets/sec)
- [nmap](https://github.com/nmap/nmap) — The network scanner — NSE scripting + OS detection
- [ntopng](https://github.com/ntop/ntopng) — Web-based network traffic monitoring
- [maltrail](https://github.com/stamparm/maltrail) — Malicious traffic detection via signature + ML
- [rita](https://github.com/activecm/rita) — C2 beaconing detection through statistical analysis
- [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) — WiFi security auditing suite
- [scapy](https://github.com/secdev/scapy) — Python packet manipulation library — build any packet you want
- [netdisco](https://github.com/netdisco/netdisco) — Network device discovery and inventory
- [p0f](https://github.com/p0f/p0f) — Passive OS fingerprinting from network traffic
- [stenographer](https://github.com/google/stenographer) — Full-packet capture indexing at Google scale

**🎓 Certifications:** CompTIA Network+ · CCNA · GCIA · GNFA  
**📺 YouTube:** [David Bombal](https://www.youtube.com/@davidbombal) · [Professor Messer](https://www.youtube.com/@professormesser) · [Chris Greer (Wireshark)](https://www.youtube.com/@ChrisGreer)  
**🏆 Practice:** [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) · [PacketLife pcap library](https://packetlife.net/captures/)

---

## 🧠 Programming for Hackers

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Black Hat Python** | Justin Seitz | 🟡 | Build network scanners, keyloggers, C2 channels in Python |
| **Violent Python** | TJ O'Connor | 🟢 | Shorter, faster intro to offensive Python — forensics to exploitation |
| **Gray Hat Python** | Justin Seitz | 🔴 | Python for reverse engineering and binary analysis |
| **Black Hat Go** | Steele, Patten, Branden | 🟡 | Go for offensive security — faster, cross-compiled, stealthy |
| **Rust for Rustaceans** | Jon Gjengset | 🔴 | Advanced Rust for building low-level security tools |

> 💡 **Pro tip:** Learn Go. The modern offensive tooling ecosystem (Sliver, Havoc, Nuclei, Subfinder) is all written in Go. Being able to read and modify offensive tools is a massive skill multiplier.

**🔧 Hands-on repos:**
- [red-python-scripts](https://github.com/davidbombal/red-python-scripts) — Python red team scripts collection
- [pwntools](https://github.com/Gallopsled/pwntools) — Python exploit development framework
- [PyExfil](https://github.com/ytisf/PyExfil) — Python data exfiltration channel implementations
- [Arjun](https://github.com/s0md3v/Arjun) — Python HTTP parameter discovery
- [impacket](https://github.com/fortra/impacket) — Python library for Windows/AD network protocols
- [scapy](https://github.com/secdev/scapy) — Python packet crafting and manipulation
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — Go vulnerability scanner — learn offensive Go
- [RedTeamPowershellScripts](https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts) — PowerShell red team scripts
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) — PowerShell offensive security framework
- [OffensiveNim](https://github.com/byt3bl33d3r/OffensiveNim) — Offensive tooling in Nim language
- [Sliver](https://github.com/BishopFox/sliver) — Go-based C2 framework — study the source
- [Havoc](https://github.com/HavocFramework/Havoc) — Modern C2 framework — C/C++ core to study
- [metasploit-framework](https://github.com/rapid7/metasploit-framework) — Ruby C2/exploitation framework — read the modules

**🎓 Certifications:** PCEP (Python) · PNPT (applied scripting) · OSCP (custom tools)  
**📺 YouTube:** [TCM Security Python](https://www.youtube.com/@TCMSecurityAcademy) · [Seitz Black Hat Python series](https://www.youtube.com/)  
**🏆 Practice:** [HackTheBox machines that require custom scripts](https://hackthebox.com) · [SANS Holiday Hack](https://holidayhackchallenge.com)

---

## 🎭 Hacker Culture / History / Real-World Ops

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Ghost in the Wires** | Kevin Mitnick | 🟢 | The most entertaining hacking memoir ever written |
| **The Art of Invisibility** | Kevin Mitnick | 🟢 | Privacy and OpSec — practical and readable |
| **The Art of Intrusion** | Kevin Mitnick | 🟢 | Real intrusion case studies with technical detail |
| **The Cuckoo's Egg** | Clifford Stoll | 🟢 | The original cyber investigation story — still gripping |
| **Sandworm** | Andy Greenberg | 🟢 | The definitive account of Russian offensive cyber operations |
| **This Is How They Tell Me the World Ends** | Nicole Perlroth | 🟢 | The global zero-day market, NSA, and cyber warfare |
| **Permanent Record** | Edward Snowden | 🟢 | NSA surveillance programs from the inside |
| **Kingpin** | Kevin Poulsen | 🟢 | The Max Butler story — carding, dark markets, and opsec failures |
| **Countdown to Zero Day** | Kim Zetter | 🟢 | Stuxnet — the most detailed account of the first cyber weapon |
| **The Fifth Domain** | Clarke & Knake | 🟢 | Cyber warfare policy and the US defense posture |

> 💡 **Pro tip:** These books are not just entertainment — they reveal *why* people do this, how adversaries think, and what real operational security failure looks like. They build threat modeling intuition that no technical book can.

**🔧 Hands-on repos:**
- [APTnotes](https://github.com/kbandla/APTnotes) — Public APT campaign documents (real-world ops context)
- [red_team_tool_countermeasures](https://github.com/mandiant/red_team_tool_countermeasures) — Detection rules for real red team tools
- [malware-indicators](https://github.com/citizenlab/malware-indicators) — Citizen Lab spyware IOCs (context for Perlroth/Sandworm)
- [the-catch](https://github.com/PaulSec/awesome-sec-talks) — Curated security conference talks
- [KrebsOnSecurity](https://github.com/jivoi/awesome-osint) — Context for Kingpin/cybercrime journalism

**📺 YouTube:** [Darknet Diaries Podcast](https://darknetdiaries.com) — 180+ real-world hacking stories in audio form  
**🏆 Read next:** [Risky.biz podcast](https://risky.biz) · [Smashing Security](https://smashingsecurity.com) · The DFIR Report

---

## 🤖 AI / ML Security

> One of the fastest-growing attack surfaces. Relevant whether you're red teaming LLM applications or defending AI pipelines.

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **Hacking AI** | Various | 🟡 | Emerging — adversarial ML, model theft, data poisoning |
| **Adversarial Machine Learning** | Biggio & Roli | 🔴 | Academic foundation for adversarial attacks on ML |
| **AI and the Future of Cybersecurity** | Various | 🟢 | Framework-level thinking on AI in security operations |

> 💡 **Pro tip:** [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [MITRE ATLAS](https://atlas.mitre.org) are the current reference standards. Both are free.

**🔧 Hands-on repos:**
- [garak](https://github.com/leondz/garak) — LLM vulnerability scanner (prompt injection, jailbreaks)
- [promptmap](https://github.com/utkusen/promptmap) — Automated prompt injection testing
- [PyRIT](https://github.com/Azure/PyRIT) — Microsoft's Python Risk Identification Toolkit for LLMs
- [llm-attacks](https://github.com/llm-attacks/llm-attacks) — Universal adversarial attacks on aligned LLMs
- [PrivacyLens](https://github.com/microsoft/presidio) — PII detection and anonymization (protect training data)
- [adversarial-robustness-toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox) — IBM ART — adversarial ML attack/defense toolkit
- [cleverhans](https://github.com/cleverhans-lab/cleverhans) — Adversarial example library for ML security research
- [alibi-detect](https://github.com/SeldonIO/alibi-detect) — ML data drift and outlier detection

**🎓 Certifications:** AWS ML Security · MITRE ATLAS practitioner (emerging)  
**📺 YouTube:** [Simon Willison](https://www.youtube.com/@simonw) · [Yannic Kilcher](https://www.youtube.com/@YannicKilcher) (adversarial ML papers)  
**🏆 Practice:** [Gandalf prompt injection game](https://gandalf.lakera.ai) · HuggingFace CTFs

---

## 🎓 Certifications & Foundations

| Book | Author | Difficulty | Why Read It |
|------|--------|-----------|-------------|
| **CISSP Official Study Guide** | Chapple & Stewart | 🟡 | The management-level cert — required for senior roles |
| **CISSP Official Practice Tests** | Chapple & Stewart | 🟡 | 2000+ practice questions — required for passing |
| **CompTIA Security+ Study Guide** | Chapple & Seidl | 🟢 | Entry-level cert — the industry minimum baseline |
| **CompTIA Network+ Guide** | Mike Meyers | 🟢 | Networking foundation — do this before Security+ |
| **CompTIA PenTest+ Guide** | Various | 🟡 | Mid-level pentest cert — lighter than OSCP |
| **CEH Certified Ethical Hacker** | Various | 🟢 | Broad survey — better for resume than for skills |

> 💡 **Pro tip:** Cert priority order for offense: **Net+ → Sec+ → PNPT → OSCP → CRTO**. For defense: **Net+ → Sec+ → BTL1 → CySA+ → GCIH**. Don't get CISSP until you have 5 years experience — it won't help you before then.

**🔧 Hands-on repos:**
- [Free-Certifications](https://github.com/cloudcommunity/Free-Certifications) — Free courses with certs to supplement paid study
- [Security-101](https://github.com/microsoft/Security-101) — Microsoft's 8-lesson cybersecurity curriculum (free)
- [awesome-hacking](https://github.com/carpedm20/awesome-hacking) — Hacking tutorials and resources for foundations
- [90DaysOfCyber](https://github.com/0xHop/90DaysOfCyber) — Structured 90-day cybersecurity learning path
- [Cybersecurity-Roadmap](https://github.com/nicowillis/cybersecurity-roadmap) — Community-built career roadmap

**📺 YouTube:** [Professor Messer (Sec+, Net+)](https://www.youtube.com/@professormesser) · [Pete Zerger (CISSP)](https://www.youtube.com/@insidecloudandsecurity)  
**🏆 Free study:** [Professor Messer free course notes](https://professormesser.com) · [CyberSeek](https://cyberseek.org/pathway.html)

---

## 💼 Career / Getting Hired

> The skills above get you the job. These resources help you land it.

| Resource | Why It Matters |
|----------|---------------|
| **"Cybersecurity Career Master Plan"** — Lim, Grayson, Donahue | Roadmap from beginner to employed — practical, not fluffy |
| **"The Art of the Job Hunt"** (Cyber-focused) | Resume, portfolio, and interview prep for security roles |
| **Resume tips from r/netsec and r/cybersecurity** | Real hiring feedback from practitioners |

> 💡 **Pro tip:** Your GitHub profile IS your resume in this field. Public CTF writeups, tools you built, and blog posts about vulnerabilities you found beat any certification on paper.

**🔧 Career-boosting repos:**
- [HackTheBox writeups](https://github.com/Hackplayers/hackthebox-writeups) — Model your writeup format here
- [awesome-ctf](https://github.com/apsdehal/awesome-ctf) — CTF tools, writeups, and learning resources
- [ctf-katana](https://github.com/JohnHammond/ctf-katana) — CTF challenge hints and solver techniques
- [CTFd](https://github.com/CTFd/CTFd) — Host your own CTF — great portfolio project
- [TryHackMe learning paths](https://tryhackme.com) — Structured skill progression with certs
- [PortSwigger Web Academy](https://portswigger.net/web-security) — Free, world-class web security training
- [pwn.college](https://pwn.college) — Free binary exploitation from zero to advanced

**📺 YouTube:** [Gerald Auger (SimplyCyber)](https://www.youtube.com/@SimplyCyber) · [TCM Security career advice](https://www.youtube.com/@TCMSecurityAcademy)  
**🏆 Portfolio builders:** Start a blog · Do HTB/THM writeups · Submit a CVE · Contribute to an open source security tool · Win a CTF

---

## 🎯 Practice Environments

> Not optional. You cannot learn security without breaking things. These are the best sandboxes.

### Web & App Security
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application — classic beginner web target
- [WebGoat](https://github.com/WebGoat/WebGoat) — OWASP deliberately insecure web app with lessons
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Most modern intentionally vulnerable web app
- [vulhub](https://github.com/vulhub/vulhub) — Pre-built vulnerable Docker environments for 100s of real CVEs
- [Metasploitable3](https://github.com/rapid7/metasploitable3) — Deliberately vulnerable VM from Rapid7 — pairs directly with Metasploit book
- [OWASP Broken Web Applications (BWA)](https://github.com/chuckfw/owaspbwa) — Collection of vulnerable web apps in a single VM
- [PentesterLab Exercises](https://www.pentesterlab.com/exercises/) — Structured web security labs with badges — great for web fundamentals

### OSCP-Prep VulnHub Progression
> Complete these in order — they mirror OSCP lab difficulty. Attempt yourself first, then watch the walkthrough.

| # | Machine | Key Skills |
|---|---------|-----------|
| 1 | [Kioptrix Level 1](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/) | SMB exploitation, basic enumeration |
| 2 | [Kioptrix Level 1.1 (#2)](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/) | SQL injection, command injection |
| 3 | [Kioptrix Level 1.2 (#3)](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/) | Web app exploitation, privesc |
| 4 | [Kioptrix Level 1.3 (#4)](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/) | SMB, MySQL, restricted shell escape |
| 5 | [Kioptrix 2014](https://www.vulnhub.com/entry/kioptrix-2014-5,62/) | Web + BSD privesc |
| 6 | [FristiLeaks 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/) | Web exploitation, Python privesc |
| 7 | [Stapler 1](https://www.vulnhub.com/entry/stapler-1,150/) | Multiple attack vectors, great methodology practice |
| 8 | [PwnLab: init](https://www.vulnhub.com/entry/pwnlab-init,158/) | LFI, file upload, pivoting between users |
| 9 | [Tr0ll 1](https://www.vulnhub.com/entry/tr0ll-1,100/) | Enumeration patience, trolling-style hints |
| 10 | [Tr0ll 2](https://www.vulnhub.com/entry/tr0ll-2,107/) | More complex, multiple privesc vectors |
| 11 | [Mr-Robot 1](https://www.vulnhub.com/entry/mr-robot-1,151/) | WordPress exploitation + privesc — iconic machine |
| 12 | [SickOs 1.2](https://www.vulnhub.com/entry/sickos-12,144/) | SSRF + privesc chain, realistic flow |
| 13 | [HackLAB: Vulnix](https://www.vulnhub.com/entry/hacklab-vulnix,48/) | NFS, user enumeration, privesc |
| 14 | [pWnOS 2.0](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/) | Web app exploitation focus |
| 15 | [Lord Of The Root 1.0.1](https://www.vulnhub.com/entry/lord-of-the-root-101,129/) | Port knocking, SQLi, kernel exploit |

> 💡 After VulnHub basics, move to [Hack The Box retired machines](https://hackthebox.com). Watch [IppSec's walkthroughs](https://www.youtube.com/@ippsec) after each attempt — the best free OSCP prep available.

### Traffic Analysis Labs
- [Malware Traffic Analysis Training](https://www.malware-traffic-analysis.net/training-exercises.html) — Real PCAP exercises — identify C2, malware, and intrusions from packet captures
- [Malware Traffic Analysis Tutorials](https://www.malware-traffic-analysis.net/tutorials/index.html) — Step-by-step Wireshark analysis tutorials
- [Blue Team Village DEFCON Workshop](https://www.malware-traffic-analysis.net/2018/workshop/BlueTeamVillage/) — Workshop-style PCAP analysis exercises
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Official Wireshark sample PCAPs for all protocol types
- [PacketLife PCAP Library](https://packetlife.net/captures/) — Protocol-specific capture files for study

### Active Directory Labs
- [GOAD](https://github.com/Orange-Cyberdefense/GOAD) — Game of Active Directory — 5-VM vulnerable AD lab (the best one)
- [BadBlood](https://github.com/davidprowe/BadBlood) — Populate AD with realistic, vulnerable configurations
- [Vulnerable-AD](https://github.com/WazeHell/vulnerable-AD) — Quick vulnerable AD setup script

### CTF Platforms
- [CTFd](https://github.com/CTFd/CTFd) — Host your own CTF challenges
- [ctf-katana](https://github.com/JohnHammond/ctf-katana) — CTF problem-solving hints and tools
- [awesome-ctf](https://github.com/apsdehal/awesome-ctf) — Curated CTF resources

### Malware Analysis Labs
- [PMAT-labs](https://github.com/HuskyHacks/PMAT-labs) — Practical Malware Analysis & Triage course labs
- [learning-malware-analysis](https://github.com/jstrosch/learning-malware-analysis) — Safe malware-mimicking sample programs
- [theZoo](https://github.com/ytisf/theZoo) — Live malware for research (handle in isolated VM only!)
- [flare-vm](https://github.com/mandiant/flare-vm) — One-click malware analysis workstation setup

### Hardware & Network
- [WiFiChallengeLab](https://github.com/r4ulcl/WiFiChallengeLab-docker) — Virtualized WiFi pentesting practice
- [GNS3](https://github.com/GNS3/gns3-server) — Network simulation for Cisco/networking lab work

### Online Platforms (No Setup Required)
| Platform | Best For | Cost |
|----------|---------|------|
| [Hack The Box](https://hackthebox.com) | Pentesting, AD, reversing | Free + VIP |
| [TryHackMe](https://tryhackme.com) | Beginners → intermediate | Free + premium |
| [PortSwigger Web Academy](https://portswigger.net/web-security) | Web security mastery | **Free** |
| [pwn.college](https://pwn.college) | Binary exploitation | **Free** |
| [CryptoHack](https://cryptohack.org) | Cryptography | **Free** |
| [PentesterLab](https://pentesterlab.com) | Web + code review | Free + pro |
| [Blue Team Labs Online](https://blueteamlabs.online) | SOC/DFIR | Free + premium |
| [CyberDefenders](https://cyberdefenders.org) | DFIR, forensics | Free |
| [VulnHub](https://vulnhub.com) | Offline VM labs | **Free** |
| [CTFtime](https://ctftime.org) | Upcoming CTF events | **Free** |

---

## 📊 Coverage Summary

| Domain | Books | Key Tools | Best Free Practice |
|--------|-------|-----------|-------------------|
| News & Daily Intel | — | SANS ISC, CISA KEV, Exploit-DB | CISA KEV catalog (free) |
| Core Foundation | 6 | HackTricks, awesome-security | Security Engineering (free PDF) |
| Offensive / Pentest | 10 | Metasploit, NetExec, BloodHound | Hack The Box |
| Web Security | 5 | ZAP, Nuclei, ffuf, OWASP WSTG | PortSwigger Academy (free) |
| Active Directory | 4 | BloodHound, Impacket, Rubeus | GOAD lab |
| Malware / RE | 7 | FLARE-VM, Capa, pe-bear, Volatility | MalwareBazaar + PMAT labs |
| Cryptography | 5 | Vault, Sigstore, age | CryptoHack (free) |
| Blue Team / SOC | 7 | Sigma, Hayabusa, RITA, TheHive | CyberDefenders (free) |
| Threat Intelligence | 4 | MISP, OpenCTI, ATT&CK Navigator | MITRE ATT&CK (free) |
| OSINT | 6 | SpiderFoot, Maigret, GHunt | TraceLabs CTF |
| Cloud Security | 6 | Pacu, Prowler, ScoutSuite, Trivy | flaws.cloud (free) |
| Mobile Security | 4 | MobSF, Frida, Objection | DIVA Android |
| Hardware / IoT | 6 | Binwalk, Firmwalker, RouterSploit | DVID |
| Exploit Dev | 6 | pwntools, pwndbg, ROPgadget, angr | pwn.college (free) |
| Fuzzing / Research | 4 | AFL++, OSS-Fuzz, CodeQL | FuzzBench |
| Networking | 5 | Wireshark, Zeek, Suricata | Wireshark sample captures |
| Programming | 5 | pwntools, Impacket, Scapy | HTB scripting challenges |
| Hacker Culture | 10 | APTnotes, DFIR Report | Darknet Diaries podcast |
| AI / ML Security | 3 | garak, ART, PyRIT | Gandalf challenge |
| Certifications | 6 | Free-Certifications, Security-101 | Professor Messer (free) |
| Career | — | GitHub portfolio, CTF writeups | TryHackMe learning paths |

---

*Last updated: 2026 · Maintained by [@TeamStarWolf](https://github.com/TeamStarWolf)*
