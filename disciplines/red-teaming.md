# Red Teaming

> Red teaming simulates a realistic, goal-oriented threat actor — measuring an organization's ability to detect, respond to, and recover from a determined adversary. Where penetration testing finds vulnerabilities, red teaming tests whether defenders can catch someone exploiting them.

Red teaming differs fundamentally from penetration testing. A pentest is scoped, time-boxed, and delivers a list of vulnerabilities. A red team engagement simulates a persistent Advanced Persistent Threat (APT): it is stealth-first, objective-driven, and measures the blue team's detection and response capability, not just the attack surface. Engagements typically run weeks to months, avoid detection as a primary constraint, and conclude with a findings debrief that includes defender performance metrics alongside technical findings. Understanding this distinction is essential before approaching the tooling or tradecraft.

---

## Red Team vs Penetration Test vs Bug Bounty

| Attribute | Red Team | Penetration Test | Bug Bounty |
|---|---|---|---|
| **Objective** | Simulate APT; test detection & response | Find and prove exploitable vulnerabilities | Discover specific vulnerability classes |
| **Scope** | Full organization, typically unrestricted | Defined systems or application surface | Defined targets per program rules |
| **Duration** | Weeks to months | Days to weeks | Continuous / ongoing |
| **Stealth** | Primary constraint — avoid detection | Not required; noise acceptable | Not required |
| **Deliverable** | Red team report + defender performance metrics | Technical vulnerability report | Per-finding disclosure reports |
| **Audience** | CISO, SOC leadership, board | Security engineering, IT operations | Security team, program owner |

---

## Red Team Engagement Types

**Full Red Team (FRT)** — No prior knowledge of the target environment. Operators begin from zero (open-source recon only) with unrestricted objectives such as domain admin, data exfiltration, or executive email access. Closest simulation of a real APT intrusion.

**Assumed Breach** — Operators are seeded with a foothold: a compromised endpoint, VPN credentials, or low-privilege domain account. Skips initial access to focus assessment time on post-exploitation, lateral movement, and detection capability. Most efficient model for organizations that have already tested initial access controls.

**Purple Team** — Collaborative exercise where defenders observe attacks in real time. Red team announces each technique before executing it; blue team attempts detection. Produces a direct mapping of detection coverage and drives immediate tuning of SIEM rules and EDR policies. See also: [Purple Teaming](disciplines/purple-teaming.md).

**Tabletop Exercise** — Scenario-based discussion with no actual attack execution. A facilitator walks an IR team through a realistic intrusion scenario and evaluates response decisions, escalation paths, and playbook quality. Low cost; high value for process validation and training.

---

## Red Team Kill Chain / Methodology

Red team operations map across both the Lockheed Martin Cyber Kill Chain and the MITRE ATT&CK framework. The two models are complementary: Kill Chain provides phase sequencing; ATT&CK provides granular technique taxonomy.

| Phase | Kill Chain Stage | Key ATT&CK Tactics |
|---|---|---|
| **1. Reconnaissance** | Reconnaissance | Reconnaissance (TA0043) |
| **2. Weaponization** | Weaponization | Resource Development (TA0042) |
| **3. Initial Access** | Delivery / Exploitation | Initial Access (TA0001) |
| **4. Execution** | Installation | Execution (TA0002) |
| **5. Persistence** | Installation | Persistence (TA0003) |
| **6. Privilege Escalation** | Installation | Privilege Escalation (TA0004) |
| **7. Defense Evasion** | C2 | Defense Evasion (TA0005) |
| **8. Credential Access** | C2 | Credential Access (TA0006) |
| **9. Discovery** | C2 | Discovery (TA0007) |
| **10. Lateral Movement** | C2 | Lateral Movement (TA0008) |
| **11. Collection & Exfiltration** | Actions on Objectives | Collection (TA0009), Exfiltration (TA0010) |
| **12. Objectives** | Actions on Objectives | Impact (TA0040) |

### Phase Details

**1. Reconnaissance** — OSINT (LinkedIn, GitHub, Shodan, WHOIS), passive DNS enumeration, certificate transparency logs, job postings for technology stack intelligence, employee enumeration via email pattern analysis. Tools: Maltego, SpiderFoot, theHarvester, Amass, Shodan.

**2. Weaponization** — Payload development tailored to target environment (AV/EDR identified from recon), C2 infrastructure staging, domain registration and aging, redirector configuration, Malleable C2 profile development to blend with target's expected traffic.

**3. Initial Access** — Spearphishing (GoPhish, custom), adversary-in-the-middle phishing for MFA bypass (evilginx2), VPN/Citrix exploit, supply chain compromise, external-facing application exploitation. Initial access method selection is driven by OPSEC constraints.

**4. Execution** — User execution (macro, LNK, ISO), scripted execution (PowerShell, WScript, MSHTA), scheduled task creation, service installation. AMSI and script block logging bypass required in most modern environments.

**5. Persistence** — Registry run keys, scheduled tasks, WMI subscriptions, implant staging in legitimate-looking paths, COM hijacking, service installation. Persistence is established before escalation to survive endpoint reboots and credential rotation.

**6. Privilege Escalation** — Local privesc (token impersonation, service misconfiguration, AlwaysInstallElevated), Active Directory escalation (Kerberoasting, AS-REP Roasting, ADCS ESC attacks via Certipy, ACL abuse, DCSync). See: [Active Directory](disciplines/active-directory.md).

**7. Defense Evasion** — AMSI patching, hardware breakpoint-based bypasses, EDR unhooking via direct/indirect syscalls, sleep obfuscation, process injection into trusted processes, LOLBins for execution proxy, stomping PE headers.

**8. Credential Access** — LSASS dump (Mimikatz, Nanodump), Kerberoasting, AS-REP Roasting, DPAPI credential extraction, credential hunting in file shares and scripts, DCSync from domain controller.

**9. Discovery** — Network scanning (internal Nmap via pivot), Active Directory enumeration (BloodHound, PowerView, ADExplorer), share enumeration, GPO review, cloud metadata service queries.

**10. Lateral Movement** — Pass-the-Hash (CrackMapExec, Impacket), Pass-the-Ticket, Overpass-the-Hash, RDP with stolen credentials, WMI remote execution, PSExec, DCOM, SSH agent forwarding. Tunneling via Ligolo-ng or Chisel for network pivot.

**11. Collection & Exfiltration** — Stage sensitive data (credentials, IP, PII) to a collection directory, compress and encrypt, exfiltrate via C2 channel (HTTP/S, DNS) or out-of-band (SFTP to redirector). Exfil rate and timing chosen to blend with baseline.

**12. Objectives** — Demonstrate impact commensurate with engagement goal: domain admin access proof, simulated ransomware deployment, exfiltration of crown jewel data, executive mailbox access, or supply chain compromise simulation.

---

## C2 Frameworks

| Framework | License | Language | Key Features | Typical Use |
|---|---|---|---|---|
| **Cobalt Strike** | Commercial | Java (server) / C (Beacon) | Malleable C2 profiles, BOF ecosystem, team server, sleep obfuscation, mature operator interface | Industry gold standard; primary choice for enterprise red teams |
| **Sliver** (BishopFox) | Open source | Go | HTTPS/DNS/mTLS/WireGuard transport, Go implants, multiplayer, BOF support | Leading free CS alternative; growing community |
| **Havoc** | Open source | C/C++ (Demon) | Modern evasion, sleep encryption, indirect syscalls, Koffee BOF loader | Popular in research and open-source red teams |
| **Brute Ratel C4 (BRC4)** | Commercial | C | OPSEC-first design, no CS Beacon signatures, used by real APT groups | Adversary simulation requiring APT-grade OPSEC |
| **Metasploit Framework** | Open source | Ruby | Exploit module ecosystem, Meterpreter, stageless payloads, broad platform support | Initial access and technique validation |
| **Mythic** | Open source | Python (server) | Modular multi-language agents, REST API, browser UI, extensible payload service | Research, custom agent development |
| **Nighthawk** (MDSec) | Commercial | C | Advanced evasion, hardware breakpoints, BOF support, modern EDR bypass | High-assurance red teams requiring maximum evasion |
| **PowerShell Empire** | Open source | PowerShell / Python | Stagers, listeners, post-exploitation modules | Now maintained as BC-Security fork; educational use |

---

## Payload Development and Evasion

### AMSI Bypass Techniques
- Memory patching — patch `AmsiScanBuffer` return value to always return `AMSI_RESULT_CLEAN`
- Hardware breakpoints — set a hardware breakpoint on `AmsiScanBuffer` via VEH to redirect execution
- Obfuscation — string splitting, encoding, reflection to prevent static AMSI pattern matching
- COM server abuse — load AMSI through a context where it is not initialized

### AV/EDR Evasion
- **Direct syscalls** — invoke NT system calls directly without going through ntdll.dll (SysWhispers2/3)
- **Indirect syscalls** — resolve syscall numbers but use an unhooked syscall stub from ntdll; evades hook-detection heuristics
- **Unhooking ntdll.dll** — load a clean copy from disk or KnownDlls and overwrite the hooked in-memory copy
- **Sleep encryption** — encrypt implant memory during beacon sleep intervals; evades in-memory scanner snapshots
- **Process injection** — inject into remote processes (explorer, svchost) to inherit trust and network context

### Payload Formats
Shellcode (`.bin`), position-independent shellcode, DLL (reflective loading or proxying), EXE, macro-enabled Office documents, HTA, LNK (shortcut), ISO/VHD (bypasses Mark-of-the-Web), self-extracting archives.

### Obfuscation Tools
- **Donut** — converts EXE/DLL/.NET assemblies to position-independent shellcode
- **ScareCrow** — shellcode loader generator with EDR bypass and code-signing support
- **Chameleon** — PowerShell script obfuscator targeting AMSI and AV signatures
- **garble** — Go source obfuscator producing stripped, symbol-free binaries
- **LLVM IR obfuscation** — compile-time obfuscation passes on LLVM IR (Obfuscator-LLVM, Hikari)

### LOLBins for Execution
The [LOLBAS project](https://lolbas-project.github.io) catalogs Windows native binaries usable as execution proxies:
`mshta.exe`, `wscript.exe`, `cscript.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`, `rundll32.exe`, `msiexec.exe`, `installutil.exe`, `odbcconf.exe`

### Code Signing
Self-signed certificates or stolen/leaked code-signing certificates are applied to payloads to bypass SmartScreen and mark executables as trusted. Certificate theft from breached organizations is documented in multiple APT intrusions.

---

## Infrastructure OPSEC

**Domain categorization and aging** — Register domains weeks or months before use. Submit to categorization services (Bluecoat, McAfee TrustedSource, Fortiguard) targeting categories like Business Services or Technology to bypass web proxy filtering. Aged domains carry existing reputation.

**Redirectors** — Front-end servers (Apache/Nginx) using `mod_rewrite` rules to proxy only valid C2 callbacks to the team server, while serving benign content or returning 404 to scanners. Redirectors are burned; team servers are protected.

**Malleable C2 profiles** — Cobalt Strike profiles (and equivalent in Sliver/Havoc) define HTTP request/response format, headers, URIs, and staging behavior. Profiles mimicking OneDrive sync, Microsoft Teams traffic, or CDN requests blend into corporate traffic baselines.

**CDN fronting** — Historically: route C2 traffic through Azure CDN, Cloudflare Workers, or AWS CloudFront so the C2 destination appears as a legitimate CDN. Increasingly blocked by providers; domain fronting within the same CDN is largely eliminated.

**Short/long haul infrastructure separation** — Maintain separate infrastructure for interactive operations (short haul, high-touch) and persistent implants (long haul, low-and-slow check-ins). Burning short-haul infrastructure does not expose long-haul access.

**VPS provider selection** — Vultr, DigitalOcean, Hetzner (EU-based, slower abuse response), Contabo. Avoid providers with aggressive abuse teams or IP ranges that are pre-blocked. Rotate provider per engagement.

---

## Tools by Phase

| Phase | Key Tools |
|---|---|
| **Recon** | Maltego, SpiderFoot, theHarvester, Shodan, Amass, subfinder, OSINT Framework |
| **Initial Access** | GoPhish, evilginx2 (AiTM MFA bypass), Metasploit, custom phishing infrastructure |
| **Post-Exploitation** | Cobalt Strike / Sliver / Havoc, Mimikatz, Rubeus, Impacket, Seatbelt |
| **Lateral Movement** | CrackMapExec, Ligolo-ng, Chisel, Impacket psexec/wmiexec, SocksProxy |
| **Active Directory** | BloodHound, PowerView, ADExplorer, Certipy (ADCS), Rubeus, LDAPDomainDump |
| **Evasion** | ScareCrow, Donut, SysWhispers3, BOF kits, Inceptor, Chameleon |

---

## Certifications

| Certification | Provider | Focus | Level |
|---|---|---|---|
| **CRTO** (Certified Red Team Operator) | Zero-Point Security | Cobalt Strike, C2 infrastructure, AD attacks, OPSEC, evasion — fully practical lab exam | Intermediate |
| **CRTP** (Certified Red Team Professional) | Altered Security | Active Directory attack fundamentals — Kerberoasting, delegation, ACL abuse | Beginner–Intermediate |
| **CRTE** (Certified Red Team Expert) | Altered Security | Advanced AD: cross-forest, ADCS, complex trust abuse | Advanced |
| **OSED** (Offensive Security Exploit Developer) | OffSec | Windows exploit development: SEH, ROP chains, custom shellcode | Advanced |
| **OSEP** (Offensive Security Experienced Pentester) | OffSec | AV/EDR evasion, advanced post-exploitation, red team operations | Advanced |
| **HTB CPTS** (Certified Penetration Testing Specialist) | HackTheBox | Comprehensive pentesting and red team skills — practical 10-day exam | Intermediate |

---

## Related Pages

- [Offensive Security](disciplines/offensive-security.md) — broader offensive discipline including exploitation fundamentals
- [Active Directory](disciplines/active-directory.md) — AD attack techniques in depth
- [Penetration Testing](disciplines/penetration-testing.md) — scoped vulnerability testing methodology
- [HTB Tracks](research/HTB_TRACKS.md) — HackTheBox learning paths including red team content
- [Pentest Checklists](PENTEST_CHECKLISTS.md) — phase-by-phase engagement checklists
