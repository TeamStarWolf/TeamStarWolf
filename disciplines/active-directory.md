# Active Directory Security

> Active Directory is the backbone of enterprise identity — controlling authentication, authorization, and access for millions of organizations worldwide. Attackers target AD for persistence and privilege escalation; a compromised domain controller is effectively a full organizational compromise. Defenders must understand both the attack and defense sides of AD (DSRE: Domain Services, Replication, Authentication) to protect their environments.

---

## AD Architecture Fundamentals

### Logical Structure

| Component | Description |
|---|---|
| **Forest** | Top-level security boundary; one or more domains sharing a schema and global catalog |
| **Domain** | Administrative boundary within a forest; contains users, computers, groups, and policies |
| **Tree** | Contiguous namespace of domains within a forest (e.g., corp.example.com → sub.corp.example.com) |
| **Organizational Unit (OU)** | Container for grouping objects; primary target for GPO application and delegation |
| **Trust** | Relationship allowing cross-domain/forest authentication; can be one-way or two-way, transitive or non-transitive |
| **Group Policy Object (GPO)** | Policy container linked to sites, domains, or OUs; enforces security settings, software deployment, scripts |

### Key Infrastructure Components

| Component | Role |
|---|---|
| **Domain Controller (DC)** | Hosts AD DS; handles authentication (Kerberos/NTLM), LDAP queries, replication, and policy enforcement |
| **Global Catalog (GC)** | Partial replica of all objects in the forest; required for logon and universal group resolution |
| **FSMO Roles** | Five single-master operation roles: Schema Master, Domain Naming Master, PDC Emulator, RID Master, Infrastructure Master |
| **SYSVOL** | Shared folder on every DC; stores GPO files and logon scripts — replicated via DFSR/FRS |
| **NETLOGON** | Share hosting legacy logon scripts; used for netlogon service operations |
| **AD DS Database** | `ntds.dit` — stores all AD objects including hashed credentials; target of DCSync and NTDS extraction attacks |

### Authentication Protocols

#### NTLM Challenge-Response
1. Client sends username to server
2. Server responds with a 16-byte random **challenge**
3. Client computes **NTLM response** using the NT hash of the user password
4. Server forwards credentials to DC for verification (or verifies locally for local accounts)
5. Vulnerable to Pass-the-Hash, NTLM relay, and offline cracking

#### Kerberos TGT/TGS Flow
1. **AS-REQ**: Client requests a Ticket Granting Ticket (TGT) from the KDC; includes pre-authentication (timestamp encrypted with user's NT hash)
2. **AS-REP**: KDC issues TGT encrypted with `krbtgt` account hash
3. **TGS-REQ**: Client presents TGT and requests a Service Ticket (TGS) for a target SPN
4. **TGS-REP**: KDC issues service ticket encrypted with target service account's NT hash
5. **AP-REQ**: Client presents service ticket to target service

### Key Protocols & Ports

| Protocol | Port | Use |
|---|---|---|
| LDAP | 389 (TCP/UDP) | Directory queries and modifications (cleartext) |
| LDAPS | 636 (TCP) | LDAP over TLS |
| Kerberos | 88 (TCP/UDP) | Authentication ticket exchange |
| DNS | 53 (TCP/UDP) | Name resolution; SRV records for DC/GC discovery |
| SMB | 445 (TCP) | File shares, SYSVOL/NETLOGON access, RPC transport |
| RPC/EPM | 135 (TCP) | RPC endpoint mapper; used for replication, management |
| Global Catalog | 3268/3269 (TCP) | GC LDAP / GC LDAPS |
| WinRM | 5985/5986 (TCP) | Remote PowerShell management |

---

## Attack Techniques

> All techniques mapped to [MITRE ATT&CK](https://attack.mitre.org/). Study these for red team operations and defensive detection engineering.

| Technique | ATT&CK ID | Description | Tools |
|---|---|---|---|
| **Kerberoasting** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Request TGS tickets for accounts with SPNs; crack RC4-encrypted tickets offline | [BloodHound](https://github.com/SpecterOps/BloodHound), [Rubeus](https://github.com/GhostPack/Rubeus), [GetUserSPNs](https://github.com/fortra/impacket) |
| **AS-REP Roasting** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | Request AS-REP for accounts with pre-auth disabled; crack the encrypted blob offline | [Rubeus](https://github.com/GhostPack/Rubeus), [GetNPUsers](https://github.com/fortra/impacket) |
| **Pass-the-Hash (PtH)** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | Authenticate using an NT hash without knowing the plaintext password | [Mimikatz](https://github.com/gentilkiwi/mimikatz), [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), [Impacket](https://github.com/fortra/impacket) |
| **Pass-the-Ticket (PtT)** | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Inject a stolen Kerberos ticket into memory and use it for authentication | [Mimikatz](https://github.com/gentilkiwi/mimikatz), [Rubeus](https://github.com/GhostPack/Rubeus) |
| **Golden Ticket** | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | Forge a TGT using the `krbtgt` account hash; grants persistent domain-wide access | [Mimikatz](https://github.com/gentilkiwi/mimikatz) (requires krbtgt hash, domain SID) |
| **Silver Ticket** | [T1558.002](https://attack.mitre.org/techniques/T1558/002/) | Forge a service ticket using a service account hash; no KDC contact needed | [Mimikatz](https://github.com/gentilkiwi/mimikatz) (requires service account hash) |
| **DCSync** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | Impersonate a DC to replicate credential data via MS-DRSR protocol | [Mimikatz](https://github.com/gentilkiwi/mimikatz) `lsadump::dcsync`, [secretsdump](https://github.com/fortra/impacket) (requires DA or replication rights) |
| **Unconstrained Delegation** | [T1558](https://attack.mitre.org/techniques/T1558/) | Compromise a system with unconstrained delegation; coerce DC authentication to capture TGT | [SharpHound](https://github.com/BloodHoundAD/SharpHound), [Rubeus](https://github.com/GhostPack/Rubeus) `monitor` |
| **Constrained Delegation** | [T1558](https://attack.mitre.org/techniques/T1558/) | Abuse S4U2Self/S4U2Proxy extensions to impersonate any user to delegated services | [Rubeus](https://github.com/GhostPack/Rubeus) `s4u`, [getST](https://github.com/fortra/impacket) |
| **RBCD (Resource-Based Constrained Delegation)** | [T1558](https://attack.mitre.org/techniques/T1558/) | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on target; gain impersonation rights | [PowerMad](https://github.com/Kevin-Robertson/Powermad), [Rubeus](https://github.com/GhostPack/Rubeus) |
| **ACL Abuse (GenericAll / WriteDacl / ForceChangePassword)** | [T1222](https://attack.mitre.org/techniques/T1222/) | Exploit over-permissive ACEs on AD objects to escalate privileges | [BloodHound](https://github.com/SpecterOps/BloodHound), [PowerView](https://github.com/PowerShellMafia/PowerSploit) |
| **AdminSDHolder Abuse** | [T1222](https://attack.mitre.org/techniques/T1222/) | Backdoor AdminSDHolder ACL; SDProp propagates rogue ACE to protected accounts every 60 min | [PowerView](https://github.com/PowerShellMafia/PowerSploit) |
| **LDAP / NTLM Relay** | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | Capture NTLM auth and relay to LDAP/SMB; create accounts or write RBCD without cracking | [Responder](https://github.com/lgandx/Responder), [ntlmrelayx](https://github.com/fortra/impacket) |
| **Print Spooler (PrinterBug)** | [T1187](https://attack.mitre.org/techniques/T1187/) | Abuse MS-RPRN to coerce DC authentication back to attacker for relay or TGT capture | [printerbug.py](https://github.com/dirkjanm/krbrelayx), [SpoolSample](https://github.com/leechristensen/SpoolSample) |
| **noPac / SamAccountName Spoofing** | [CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) | Change machine account `sAMAccountName` to a DC name and request TGT as DC | [noPac](https://github.com/Ridter/noPac) |
| **ZeroLogon** | [CVE-2020-1472](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472) | Exploit Netlogon crypto flaw to reset DC machine account password without authentication | [zerologon exploit](https://github.com/SecuraBV/CVE-2020-1472) (critical — immediate patch) |
| **PetitPotam** | [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) | Coerce DC authentication via MS-EFSRPC; chain with ntlmrelayx to ADCS for DA cert | [PetitPotam](https://github.com/topotam/PetitPotam), [ntlmrelayx](https://github.com/fortra/impacket) |

---

## Enumeration Tools

| Tool | Type | Primary Use |
|---|---|---|
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) + [SharpHound](https://github.com/BloodHoundAD/SharpHound) | Graph analysis | Visualize attack paths, find shortest path to Domain Admin |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | PowerShell module | Enumerate users, groups, ACLs, GPOs, trusts, shares |
| [ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer) (Sysinternals) | GUI browser | Browse and snapshot AD objects interactively |
| [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) | LDAP dump | Dump users, groups, computers to readable HTML/JSON |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux) / [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | NetBIOS/SMB | Enumerate shares, users, groups, password policies |
| [kerbrute](https://github.com/ropnop/kerbrute) | Kerberos | User enumeration and password spraying via Kerberos |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Multi-protocol | SMB/LDAP/WinRM Swiss army knife; spray, exec, dump |
| [Impacket](https://github.com/fortra/impacket) | Python suite | Low-level Kerberos, LDAP, SMB, RPC interaction |
| [PingCastle](https://www.pingcastle.com/) | Risk assessment | AD health and security risk scoring |
| [ADRecon](https://github.com/sense-of-security/ADRecon) | Recon | Comprehensive AD enumeration report |

---

## Defensive Controls

| Control | Implementation | ATT&CK Techniques Mitigated |
|---|---|---|
| **Tiered Administration (Tier 0/1/2)** | Tier 0: DCs and AD management only; Tier 1: servers; Tier 2: workstations — no cross-tier logon | T1550, T1003, T1558 — limits lateral movement scope |
| **Protected Users Security Group** | Add privileged accounts; disables NTLM, RC4/DES encryption, unconstrained delegation, credential caching | T1550.002 (PtH), T1558 (Kerberoasting via RC4) |
| **Credential Guard** | Enable via Virtualization-Based Security (VBS); protects LSASS secrets in isolated container | T1003 (LSASS dump), T1550.002 (PtH) |
| **LAPS** | [Local Administrator Password Solution](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) — randomizes local admin passwords per machine | T1550.002 — prevents lateral movement via shared local admin hash |
| **Fine-Grained Password Policies (FGPP)** | Apply stricter policies to privileged accounts via PSOs | T1110 (brute force), T1558 (weak hash cracking) |
| **Privileged Access Workstations (PAWs)** | Dedicated hardened workstations for Tier 0/1 admin tasks; no internet access | T1566 (phishing), T1550, T1003 |
| **Just-In-Time (JIT) Privileged Access** | [Azure AD PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/) or on-prem AD time-limited group membership | T1078 — limits window of privilege exposure |
| **SMB Signing Enforcement** | GPO: `Microsoft network server: Digitally sign communications (always)` = Enabled | T1557.001 — blocks NTLM relay over SMB |
| **Disable LLMNR / NBT-NS** | GPO: Turn off multicast name resolution; disable NetBIOS over TCP/IP via DHCP options | T1557.001 — removes poisoning targets |
| **Extended Protection for Authentication (EPA)** | Enable channel binding on IIS/LDAP to prevent relay to HTTPS/LDAPS | T1557 — mitigates NTLM relay to LDAP/ADCS |
| **Microsoft Defender for Identity (MDI)** | Deploy MDI sensors on all DCs; connects to Azure portal for behavioral analytics | T1558, T1003, T1550 — real-time AD attack detection |
| **Sysmon AD Event Logging** | Deploy Sysmon with [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config); enables process, network, LDAP event capture | Supports detection of enumeration, lateral movement |
| **Audit Policy Hardening** | Enable advanced audit subcategories via `auditpol`; do not rely on basic audit policy | All — required for detection coverage below |
| **ADCS Hardening** | Patch ESC1-ESC8 vulnerabilities; disable SAN-based enrollment where not required; enable CA manager approval | T1649 — prevents certificate-based privilege escalation |
| **Disable Print Spooler on DCs** | `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled` on all DCs | T1187 — eliminates PrinterBug coercion vector |

---

## Detection Strategies

### Critical Windows Event IDs

| Event ID | Source | Meaning |
|---|---|---|
| **4768** | Security | Kerberos TGT requested (AS-REQ) — check encryption type for pre-auth disabled |
| **4769** | Security | Kerberos service ticket requested (TGS-REQ) — check for RC4 (0x17) encryption type |
| **4771** | Security | Kerberos pre-auth failed — brute force or enumeration |
| **4624** | Security | Logon success — check Type 3 (network) from unusual sources for PtH |
| **4625** | Security | Logon failure — brute force, spray |
| **4662** | Security | AD object access — required for DCSync and AdminSDHolder detection |
| **4728 / 4732** | Security | Member added to global/local security group — privilege escalation monitoring |
| **4738** | Security | User account changed — monitor for `userAccountControl` changes disabling pre-auth |
| **4776** | Security | NTLM credential validation attempt — detect spray and PtH patterns |
| **4798 / 4799** | Security | Local group membership enumerated — BloodHound/SharpHound activity |
| **5136** | Security | AD object modified — ACL changes, delegation changes, SPN additions |
| **7045** | System | New service installed — lateral movement persistence |

### Detection Logic by Attack

#### Kerberoasting
- **Event**: 4769 with `Ticket Encryption Type = 0x17` (RC4-HMAC) from a non-DC source
- **SIEM Query (KQL)**: `SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17" | where ServiceName !endswith "$" | summarize count() by Account, IpAddress, bin(TimeGenerated, 1h)`
- **Baseline**: Most modern environments use AES (0x12/0x18); any RC4 TGS request for a user-account SPN is suspicious

#### AS-REP Roasting
- **Event**: 4768 with `Pre-Authentication Type = 0` or absent
- **SIEM Query (KQL)**: `SecurityEvent | where EventID == 4768 and PreAuthType == "0" | project TimeGenerated, TargetUserName, IpAddress`
- **Baseline**: Accounts with `DONT_REQ_PREAUTH` set are high-value targets; audit regularly with `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`

#### DCSync
- **Event**: 4662 on the domain NC object with `Properties = {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All GUID)
- **SIEM Query (KQL)**: `SecurityEvent | where EventID == 4662 and Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" | where SubjectUserName !in ("MSOL_*", "AAD_*") | where not(SubjectUserName endswith "$")`
- **Note**: Only DCs and specific sync accounts should have replication rights; any other principal triggering 4662 with this GUID is a high-fidelity DCSync alert

#### Golden / Silver Ticket
- **Indicators**: TGT lifetime exceeding domain policy (default 10 hours); missing or forged PAC; logon from account without corresponding AS-REQ event
- **MDI Detection**: Microsoft Defender for Identity has built-in Golden Ticket detection via PAC validation anomalies
- **Event**: Correlate 4624 (Type 3 logon) without a preceding 4768 from the same IP/account

#### Pass-the-Hash
- **Event**: 4624 Logon Type 3 with `Authentication Package = NTLM` from unusual source IP or targeting Tier 0 systems
- **SIEM Query (KQL)**: `SecurityEvent | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM" | where TargetUserName !endswith "$" | summarize count() by TargetUserName, IpAddress, bin(TimeGenerated, 1h)`

#### BloodHound / SharpHound Enumeration
- **Indicators**: High-volume LDAP queries originating from workstation; LDAP filter strings characteristic of BloodHound collection (`samAccountType=805306368`, `(objectclass=*)` with large page sizes)
- **Event**: 1644 (LDAP query diagnostic) if enabled; network sensor anomaly on LDAP port volume
- **MDI**: Automatically detects reconnaissance using LDAP and SMB enumeration

---

## Certifications & Training

| Certification / Resource | Focus | Provider |
|---|---|---|
| [CRTE](https://www.alteredsecurity.com/redteamlab) — Certified Red Team Expert | Advanced AD attack chains, multi-forest, Azure AD | [Altered Security](https://www.alteredsecurity.com/) |
| [CRTO](https://training.zeropointsecurity.co.uk/courses/red-team-ops) — Certified Red Team Operator | AD red team ops using Cobalt Strike | [Zero-Point Security](https://training.zeropointsecurity.co.uk/) |
| [CARTP](https://www.alteredsecurity.com/azureredteam) — Certified Azure Red Team Professional | Azure AD / Entra ID attack paths | [Altered Security](https://www.alteredsecurity.com/) |
| [HTB CAPE / CDSA](https://academy.hackthebox.com/) | AD exploitation and defensive modules | [HTB Academy](https://academy.hackthebox.com/) |
| [HTB Active Directory Exploitation Track](https://www.hackthebox.com/tracks) | Hands-on AD machines (domain privesc, lateral movement) | [HackTheBox](https://www.hackthebox.com/) |
| [SpecterOps Training](https://specterops.io/training/) | BloodHound Enterprise, AD security deep dives | [SpecterOps](https://specterops.io/) |
| [TCM Security — PEH](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course) | Practical AD enumeration and exploitation | [TCM Security](https://academy.tcm-sec.com/) |

---

## Key References

| Resource | Type | Notes |
|---|---|---|
| [The Hacker Recipes — Active Directory](https://www.thehacker.recipes/ad/) | Reference | Comprehensive AD attack technique walkthroughs |
| [SpecterOps Blog](https://specterops.io/blog/) | Blog | Foundational AD research (BloodHound, Kerberos, delegation) |
| [harmj0y Blog](https://blog.harmj0y.net/) | Blog | Kerberos, delegation, and PowerView research |
| [dirkjanm Blog](https://dirkjanm.io/) | Blog | NTLM relay, Kerberos, ADCS (ESC attacks) |
| [Will Schroeder / @tifkin\_](https://twitter.com/tifkin_) | Research | AdminSDHolder, ACL abuse, C2 research |
| [Microsoft Defender for Identity Docs](https://learn.microsoft.com/en-us/defender-for-identity/) | Reference | MDI sensor deployment and alert tuning |
| [MITRE ATT&CK — Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/) | Framework | Kerberoasting, credential dumping, ticket forging |
| [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/) | Framework | PtH, PtT, remote services abuse |
| [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples) | Tools | secretsdump, GetUserSPNs, getST, ticketer |
| [Active Directory Security (adsecurity.org)](https://adsecurity.org/) | Blog | Sean Metcalf's comprehensive AD security resource |

---

## Related Disciplines & Research

- [Identity & Access Management](identity-access-management.md) — IAM architecture, PAM, MFA, Credential Guard
- [Red Teaming](red-teaming.md) — Adversary simulation, C2 frameworks, AD exploitation chains
- [Penetration Testing](penetration-testing.md) — Scoped AD assessments, methodology, reporting
- [HTB Machine Index](../research/HTB_MACHINE_INDEX.md) — AD-focused HTB machines for practice
- [HTB Tracks](../research/HTB_TRACKS.md) — Curated AD exploitation and defense learning tracks
