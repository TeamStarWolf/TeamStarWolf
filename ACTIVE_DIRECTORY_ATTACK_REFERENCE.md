# Active Directory Attack Reference — Defender Edition

> **Audience:** Blue teamers, detection engineers, SOC analysts, and AD administrators.  
> **Purpose:** This reference documents the attack techniques adversaries use against Active Directory environments, explained from the defender's perspective — what each attack looks like on the wire, what telemetry it generates, and how to detect and prevent it.  
> **Ethics note:** All tool names and command examples are provided for detection-writing and threat-hunting purposes only.

---

## Table of Contents

1. [AD Reconnaissance & Enumeration (Defender View)](#1-ad-reconnaissance--enumeration-defender-view)
2. [Kerberoasting](#2-kerberoasting)
3. [AS-REP Roasting](#3-as-rep-roasting)
4. [Kerberos Ticket Attacks](#4-kerberos-ticket-attacks)
5. [Pass-the-Hash & NTLM Relay](#5-pass-the-hash--ntlm-relay)
6. [DCSync Attack](#6-dcsync-attack)
7. [Active Directory Certificate Services Attacks](#7-active-directory-certificate-services-attacks)
8. [Lateral Movement Techniques](#8-lateral-movement-techniques)
9. [Domain Persistence Techniques](#9-domain-persistence-techniques)
10. [Detection & Hardening Summary](#10-detection--hardening-summary)

---

## 1. AD Reconnaissance & Enumeration (Defender View)

### Overview

Before attackers escalate privileges or move laterally, they must understand the environment. Active Directory reconnaissance involves querying LDAP to enumerate users, computers, groups, ACLs, GPOs, trust relationships, and service principal names. Because standard user accounts have read access to most AD objects by design, this phase often goes unnoticed unless specific telemetry is enabled.

### What Attackers Query

**Raw LDAP queries (ldapsearch / ADSI):**

Attackers frequently run LDAP queries directly against port 389 (LDAP) or 636 (LDAPS) using tools like `ldapsearch` (Linux) or ADSI interfaces (Windows). Common query targets:

- All enabled user accounts: `(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)`
- All computer accounts: `(objectCategory=computer)`
- All domain groups: `(objectCategory=group)`
- AdminSDHolder-protected accounts: `(adminCount=1)`
- Accounts with no Kerberos preauthentication: `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`
- Accounts with SPN set (for Kerberoasting): `(&(servicePrincipalName=*)(objectCategory=user)(!objectClass=computer))`
- Domain trusts: `(objectClass=trustedDomain)`

**PowerView (PowerShell Empire / PowerSploit module):**

PowerView wraps LDAP queries in convenient PowerShell functions. Key commands defenders should recognize in process telemetry:

- `Get-DomainUser -Properties *` — enumerates all user objects with all attributes
- `Get-DomainComputer -Properties *` — full computer object enumeration
- `Get-DomainGroup -Identity "Domain Admins" -Recurse` — nested group membership
- `Get-DomainGroupMember` — member enumeration for sensitive groups
- `Get-DomainGPO` — Group Policy enumeration
- `Get-DomainTrust` — all trust relationships
- `Find-LocalAdminAccess` — sweeps all domain computers testing if current user has local admin
- `Get-DomainObjectAcl` / `Find-InterestingDomainAcl` — ACL enumeration for privilege escalation paths
- `Get-NetSession` / `Get-NetLoggedon` — live session enumeration via NetSessionEnum/NetWkstaUserEnum (generates 4624/NetBIOS traffic)

**BloodHound Data Collection:**

BloodHound (and its collection component SharpHound) collects multiple data categories and models attack paths as a graph:

- **Collection methods:**
  - `All` — full collection: LDAP (users, computers, groups, GPOs, trusts, ACLs), SMB (local admins, sessions, RDP users), DCOM
  - `DCOnly` — LDAP only against domain controllers; stealthier, avoids SMB to member servers
  - `ComputerOnly` — SMB sessions/admin collection without LDAP enumeration
  - `LoggedOn` — privileged session collection requiring admin rights on target hosts
- **Data collected:** Group memberships, user/computer object properties, ACEs on domain objects, GPO links, domain trusts, active sessions, local admin group members, RDP users, DCOM users
- **Output:** JSON files (computers.json, users.json, groups.json, ous.json, gpos.json, containers.json, domains.json)

**Tool variants:**

| Tool | Language | Transport | Notes |
|---|---|---|---|
| SharpHound.exe | C# | LDAP + SMB | Standard Windows binary; AV-detectable |
| BloodHound.py | Python | LDAP + SMB | Linux-based, runs without touching target disk |
| RustHound | Rust | LDAP | Stealthier binary; generates same JSON schema |
| SilentHound | Python | LDAP only | Minimal footprint, targets DCs only |

### Detection

**Windows Event IDs:**

- **Event ID 4661** (Object handle requested with specific access rights) — generated when LDAP searches access sensitive objects like `domainDNS`, `msDS-GroupManagedServiceAccount`, AdminSDHolder container. Requires "Audit Directory Service Access" policy. High volume during SharpHound runs.
- **Event ID 1644** (Expensive/inefficient LDAP query) — logged on Domain Controllers in the Directory Service log when an LDAP query exceeds threshold (default 15,000 entries returned, 30,000 objects visited, or 30ms of CPU). Field names included in event: caller IP, filter string, attributes requested, elapsed time. This is the highest-fidelity LDAP enumeration indicator.
  - Enable via registry: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics` → `15 Field Engineering` = `5`
  - Search filter appearing in 1644 events from SharpHound: `(objectclass=*)` with all attribute list, or the specific SPN filter above
- **Sysmon Event ID 10** (ProcessAccess) — if PowerView runs in-process with LSASS queries
- **Sysmon Event ID 7 / 4688** — `powershell.exe` loading `PowerView.ps1` (AMSI bypass attempts), `SharpHound.exe` process creation

**Microsoft Defender for Identity (MDI) alerts:**

- *Active Directory attributes reconnaissance (LDAP)* — triggered when high volumes of LDAP queries are observed from a single non-DC source
- *Account enumeration reconnaissance* — NTLM-based enumeration of user account validity
- *Security principal reconnaissance (LDAP)* — large-scale object enumeration
- *Network mapping reconnaissance (DNS)* — DNS zone transfer or reverse lookup sweeps

**Network-level detection (Zeek / NDR):**

Zeek's `ldap.log` captures all LDAP operations: source IP, bind DN, operation type, filter string, base DN, result code, number of results returned. Detection opportunities:

- Single source making >1,000 LDAP `searchRequest` operations in <5 minutes
- Search base DN targeting `DC=domain,DC=com` with `scope: subtree` and `attributes: [*]`
- LDAP bind followed immediately by large batches of searchRequests (SharpHound pattern)
- Anonymous LDAP binds (should be blocked; if seen, alert immediately)
- LDAP searches from non-standard ports or non-DC source IPs

**SIEM / KQL hunting query (Microsoft Sentinel):**

```kql
// Detect high-volume LDAP enumeration via Event 1644
SecurityEvent
| where EventID == 1644
| parse EventData with * "Filter:" Filter ";" * "StartingNode:" StartingNode ";" * "CallerIP:" CallerIP ";" *
| summarize QueryCount=count(), UniqueFilters=dcount(Filter) by CallerIP, bin(TimeGenerated, 15m)
| where QueryCount > 50
| project TimeGenerated, CallerIP, QueryCount, UniqueFilters
```

### Defenses

1. **LDAP Signing Required** — Configure via GPO: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → "Domain controller: LDAP server signing requirements" = Require signing`. Prevents unsigned LDAP connections; forces tools to use authenticated+signed sessions.

2. **LDAP Channel Binding** — Enable `LdapEnforceChannelBinding = 2` on all DCs to require LDAPS with channel binding token validation. Blocks relay of LDAP authentication.

3. **Protected Users Group** — Add sensitive accounts (Domain Admins, service accounts with privileged access) to this group. Members cannot use NTLM, DES, or RC4; Kerberos TGTs expire after 4 hours; no delegation; credentials never cached. This limits what enumeration can surface about these accounts.

4. **AdminSDHolder ACL review** — Run quarterly audits of AdminSDHolder permissions. Any unexpected principals with `GenericAll`, `GenericWrite`, `WriteDacl`, or `WriteOwner` represent backdoors. The SDProp process runs every 60 minutes and propagates AdminSDHolder ACL to all adminCount=1 objects.

5. **Fine-Grained Password Policies (FGPP)** — Separate policies for service accounts, admin accounts, and regular users. Enforcing long passwords on service accounts makes Kerberoasting less effective.

6. **Tiered administration model** — Prevent Tier 0 (DC/PKI/ADFS) admin accounts from logging into Tier 1/2 assets, reducing the value of enumeration that finds these accounts.

7. **Block unnecessary LDAP access** — Use Windows Firewall or network segmentation to restrict LDAP (389/636) access to only systems that legitimately need it (management workstations, SIEM collectors, etc.).

---

## 2. Kerberoasting

### Overview

Kerberoasting targets Active Directory service accounts that have a Service Principal Name (SPN) registered. When a domain user requests a Kerberos Ticket Granting Service (TGS) ticket for a service, the KDC encrypts a portion of that ticket using the service account's password hash. Any domain user can request these tickets, and the encrypted blob can be extracted and cracked offline without any interaction with the target service — making this technique particularly dangerous.

### Mechanism

**Protocol walkthrough:**

1. Attacker (any valid domain account) sends a **TGS-REQ** to the KDC (port 88) requesting a service ticket for a target SPN (e.g., `MSSQLSvc/sqlserver.corp.local:1433`)
2. The KDC looks up the account associated with that SPN
3. KDC responds with a **TGS-REP** containing a service ticket where the `EncPart` is encrypted with the service account's password hash
4. Attacker extracts the encrypted blob from the TGS-REP and submits it to offline password cracking (Hashcat, John the Ripper)
5. If cracked, attacker now has the plaintext password of the service account

**Encryption type matters critically:**
- **RC4-HMAC (type 0x17 / etype 23):** Legacy encryption using NT hash as key. Much faster to crack offline (~10 billion hashes/second on consumer GPU). Hashcat mode `13100`.
- **AES-128 (etype 17) / AES-256 (etype 18):** Stronger encryption using AES-derived keys. Far slower to crack. Hashcat modes `19600`/`19700`.
- Attackers explicitly request RC4 downgrade even when AES is available by omitting AES from the `etype` list in the TGS-REQ — a key detection indicator.

### Attacker Tooling

**Impacket GetUserSPNs.py:**
```
GetUserSPNs.py -dc-ip 192.168.1.10 CORP/user:pass -outputfile hashes.txt
GetUserSPNs.py -dc-ip 192.168.1.10 CORP/user:pass -request-user svcSQL
```

**Rubeus (C#/.NET, runs on Windows):**
```
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /user:svcSQL /rc4opsec     # request RC4 specifically
Rubeus.exe kerberoast /aes                        # request AES (stealth)
Rubeus.exe kerberoast /ldapfilter:'adminCount=1'  # target privileged accounts only
```

**PowerView / Invoke-Kerberoast:**
```powershell
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File hashes.txt
```

### Detection

**Event ID 4769 — Kerberos Service Ticket Requested:**

This is the primary detection event. Logged on the DC that processed the TGS-REQ. Key fields:

| Field | Suspicious Value |
|---|---|
| `Ticket Encryption Type` | `0x17` (RC4-HMAC) — gold standard indicator |
| `Service Name` | Non-DC service (not `krbtgt`, not `$MACHINE`) |
| `Client Address` | Source IP — should correlate to the requesting workstation |
| `Failure Code` | `0x0` (success) |

**KQL (Microsoft Sentinel / Log Analytics):**

```kql
// Kerberoasting detection — RC4 TGS requests for non-computer accounts
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"       // exclude machine accounts
| where ServiceName !startswith "krbtgt"
| where IpAddress !in (DCIpList)        // exclude DCs requesting for themselves
| summarize RequestCount=count(), Services=make_set(ServiceName) by IpAddress, Account, bin(TimeGenerated, 10m)
| where RequestCount > 3                 // multiple SPNs = bulk roast
| order by RequestCount desc
```

**Splunk SPL:**

```
index=windows EventCode=4769 TicketEncryptionType="0x17" 
| where NOT like(ServiceName, "%$")
| stats count by src_ip, Account, ServiceName
| where count > 1
| sort - count
```

**MDI alert:** *Suspected Kerberos SPN exposure (Kerberoasting)* — triggered when MDI observes multiple TGS-REQ operations with RC4 cipher from a single account in a short window. Severity: High.

**Behavioral indicators:**
- Single account requesting TGS tickets for 5+ different SPNs within minutes
- RC4 TGS requests for accounts in privileged groups (Domain Admins, etc.)
- TGS requests from service accounts or machine accounts (anomalous — these don't normally Kerberoast)
- Requests from hosts that are not in the expected workstation fleet

### Prevention

1. **Long random service account passwords (25+ characters)** — Makes offline cracking computationally infeasible even with RC4 tickets. Use `Set-ADAccountPassword` with `[System.Web.Security.Membership]::GeneratePassword(30, 5)`.

2. **Managed Service Accounts / Group Managed Service Accounts (gMSA)** — gMSAs have 240-character random passwords rotated automatically by AD every 30 days. Cannot be cracked in any practical timeframe. Migrate all service accounts to gMSAs where possible.
   ```powershell
   New-ADServiceAccount -Name "gmsa-sql" -DNSHostName "sqlserver.corp.local" `
     -PrincipalsAllowedToRetrieveManagedPassword "sqlserver$" `
     -ServicePrincipalNames "MSSQLSvc/sqlserver.corp.local:1433"
   ```

3. **Enforce AES-only Kerberos (msDS-SupportedEncryptionTypes)** — Set `msDS-SupportedEncryptionTypes` to `24` (AES128+AES256) on service accounts, removing RC4 support. This prevents RC4 downgrade. Verify clients and services support AES first.
   ```powershell
   Set-ADUser svcSQL -KerberosEncryptionType AES128,AES256
   ```

4. **Audit SPNs regularly** — Remove unnecessary SPNs. Validate every SPN is associated with an actively running service.
   ```powershell
   Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,AdminCount
   ```

5. **Protected Users group** — Add highly privileged service accounts. Prevents RC4 Kerberos for these accounts entirely.

6. **Privileged service account isolation** — Service accounts should not be members of privileged groups (Domain Admins, Schema Admins). If a service needs elevated rights, scope those rights minimally via delegation.

---

## 3. AS-REP Roasting

### Overview

AS-REP Roasting targets accounts configured with "Do not require Kerberos preauthentication" (`UF_DONT_REQUIRE_PREAUTH`). Normally, Kerberos preauthentication requires the client to prove it knows the password before the KDC will issue a TGT, preventing offline cracking of the KDC's response. When preauthentication is disabled, any unauthenticated user on the network can request an AS-REP for these accounts and receive an encrypted blob that can be cracked offline.

### Mechanism

**Normal Kerberos AS-REQ/AS-REP flow:**
1. Client sends AS-REQ with preauthentication data (timestamp encrypted with user's password hash)
2. KDC validates the preauthentication timestamp
3. KDC issues TGT encrypted with krbtgt hash + session key encrypted with user's hash

**AS-REP Roasting flow (no preauthentication):**
1. Attacker sends AS-REQ for target account **without** preauthentication data
2. KDC issues AS-REP regardless, because `DONT_REQ_PREAUTH` is set
3. AS-REP contains `enc-part` encrypted with the **user's password hash** (RC4: NT hash; AES: derived key)
4. Attacker extracts the encrypted blob (Hashcat mode `18200` for RC4 AS-REP)
5. Offline cracking proceeds without any network interaction with the target

**Critical difference from Kerberoasting:** AS-REP Roasting does not require any valid domain credentials — it can be performed anonymously from the network. This makes it particularly valuable in scenarios where no credentials are yet held.

### Attacker Tooling

**Impacket GetNPUsers.py:**
```bash
# With credentials (to enumerate which accounts have preauth disabled)
GetNPUsers.py CORP/user:pass -dc-ip 192.168.1.10 -format hashcat -outputfile asrep.txt

# Without credentials (requires list of usernames)
GetNPUsers.py CORP/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10 -format hashcat

# Single user
GetNPUsers.py CORP/targetuser -no-pass -dc-ip 192.168.1.10
```

**Rubeus:**
```
Rubeus.exe asreproast /outfile:asrep.txt
Rubeus.exe asreproast /user:targetuser /format:hashcat
Rubeus.exe asreproast /domain:corp.local /dc:dc01.corp.local
```

**PowerView enumeration (pre-attack):**
```powershell
Get-DomainUser -UACFilter DONT_REQ_PREAUTH -Properties samaccountname,admincount,memberof
```

### Detection

**Event ID 4768 — Kerberos Authentication Ticket (TGT) Requested:**

This event fires on DCs when an AS-REQ is received. Key detection fields:

| Field | Suspicious Value |
|---|---|
| `Pre-Authentication Type` | `0` — indicates NO preauthentication was used |
| `Ticket Encryption Type` | `0x17` (RC4) |
| `Client Address` | Source of the request |
| `Result Code` | `0x0` (success) — failure codes `0x6`/`0x18`/`0x24` for invalid accounts |

A `Pre-Authentication Type` of `0` is abnormal in virtually all environments and should alert immediately.

**KQL query:**

```kql
// AS-REP Roasting detection — no preauthentication
SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"           // No preauthentication
| where ResultCode == "0x0"          // Successful
| where TargetUserName !endswith "$" // Not machine accounts
| project TimeGenerated, TargetUserName, IpAddress, TicketEncryptionType
| order by TimeGenerated desc
```

**Splunk SPL:**

```
index=windows EventCode=4768 Pre_Authentication_Type=0
| stats count by Account, src_ip, Pre_Authentication_Type
| sort - count
```

**Hunting query — find vulnerable accounts before attackers do:**

```kql
// Identify accounts with preauthentication disabled (from AD data source or SecurityEvent 4738)
// Also run PowerShell audit:
// Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,Enabled,PasswordLastSet,AdminCount
IdentityInfo
| where AccountUpn != ""
| join kind=inner (
    SecurityEvent | where EventID == 4738 | where UserAccountControl contains "DONT_REQ_PREAUTH"
    ) on $left.AccountUpn == $right.TargetUserName
| project TimeGenerated, TargetUserName, SubjectUserName
```

**MDI detection:** *Account Enumeration Reconnaissance* fires when unauthenticated AS-REQ requests are sent to probe account validity. MDI also has specific logic for AS-REP Roasting patterns.

**UEBA baseline:** Accounts that have `DoesNotRequirePreAuth=true` should be extremely rare. Build a baseline of these accounts and alert on any new additions.

### Prevention

1. **Enforce Kerberos preauthentication for all accounts** — This is the primary mitigation. Audit and remediate:
   ```powershell
   # Find all accounts with preauth disabled
   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,Enabled | 
     Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth
   
   # Re-enable preauthentication
   Set-ADAccountControl -Identity "targetuser" -DoesNotRequirePreAuth $false
   ```

2. **Scheduled audit** — Run monthly audit of `UF_DONT_REQUIRE_PREAUTH` flag. Alert via email or SIEM when any account gains this flag (detect via Event ID 4738 with `UserAccountControl` change containing `DONT_REQ_PREAUTH`).

3. **Event ID 4738 monitoring** — This event fires when user account properties change, including the preauthentication flag. Create alerts for any occurrence of `DONT_REQ_PREAUTH` appearing in 4738 events.

4. **Strong password policy** — Even if accounts are vulnerable, long random passwords prevent successful cracking. But this is defense-in-depth; disabling the vulnerability is the correct fix.

5. **Separate service accounts** — Legacy applications sometimes require preauthentication disabled. If unavoidable, isolate these accounts: do not grant them any elevated rights, monitor them closely, and use Fine-Grained Password Policies to enforce maximum password length.

6. **Honeypot accounts** — Create a fake account with `DoesNotRequirePreAuth=true` and an alert on any AS-REP request for that account. Any request is malicious — the account is not used for any legitimate purpose.

---

## 4. Kerberos Ticket Attacks

### Overview

Beyond stealing and cracking tickets, attackers can forge Kerberos tickets entirely by obtaining cryptographic keys from domain controllers or service accounts. These forged tickets allow long-term persistent access that survives password resets and is extremely difficult to detect.

### Pass-the-Ticket (PTT)

**Mechanism:** Kerberos tickets (TGTs and TGS tickets) are stored in memory by the Windows LSASS process in the Credential Cache (CCACHE). Attackers extract these tickets and inject them into their own session without knowing the associated password.

**Extraction tools:**

```
# Mimikatz — list and export all tickets from current session
mimikatz # sekurlsa::tickets
mimikatz # sekurlsa::tickets /export     # writes .kirbi files to disk

# Rubeus — list tickets
Rubeus.exe triage
Rubeus.exe dump /service:krbtgt /nowrap  # extract TGT

# Impacket (Linux, from CCACHE file)
export KRB5CCNAME=/path/to/ticket.ccache
```

**Injection:**
```
# Mimikatz — inject .kirbi ticket
mimikatz # kerberos::ptt ticket.kirbi

# Rubeus — inject from base64 or .kirbi
Rubeus.exe ptt /ticket:doIFuj...base64...
```

**Detection:** PTT itself doesn't generate a unique event — the injected ticket looks like a normal TGS use. Detection relies on:
- Event ID 4769 from source IPs/hosts that don't match the account's normal workstation
- Event ID 4624 Logon Type 3 (network logon) with mismatched workstation/account patterns
- MDI *Pass-the-Ticket* alert — MDI correlates ticket requests with subsequent ticket use and detects geographic/host anomalies
- Sysmon Event ID 10 — process accessing LSASS (ticket extraction precursor)

### Golden Ticket

**Mechanism:** The Golden Ticket is a forged Kerberos TGT encrypted with the **krbtgt account's NT hash**. Because the KDC validates TGTs using the krbtgt key, a correctly forged ticket is indistinguishable from a legitimate one. Golden Tickets can specify any SIDs, groups, and lifetimes — including future-dated tickets that remain valid for 10 years.

**Attack sequence:**

1. Obtain krbtgt hash (via DCSync, NTDS.dit extraction, or domain compromise)
   ```
   mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
   # or
   secretsdump.py -just-dc-user krbtgt CORP/Administrator:pass@dc01.corp.local
   ```

2. Forge the Golden Ticket:
   ```
   mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
     /sid:S-1-5-21-... /krbtgt:<NT_HASH> /id:500 \
     /groups:512,513,518,519,520 /ptt
   
   # Rubeus
   Rubeus.exe golden /rc4:<krbtgt_NT_hash> /domain:corp.local \
     /sid:S-1-5-21-... /user:FakeAdmin /ptt
   ```

**Detection:**

- **Event ID 4769** — TGS requests using the forged TGT. Look for:
  - Account names that don't exist in AD
  - PAC validation failures (if PAC validation is enabled)
  - TGT lifetimes exceeding domain policy (default max 10 hours)
  - Missing or abnormal PAC structures (requires custom parsing)
- **Event ID 4672** — Special privileges assigned to new logon (using Golden Ticket for DA-level SIDs)
- **MDI alert:** *Forged PAC (MS14-068 exploitation)* and *Kerberos Golden Ticket activity* — MDI detects Golden Tickets by analyzing TGT properties that don't match what the KDC would have issued (wrong encryption type, impossible account attributes, etc.)
- **KQL — Golden Ticket hunt:**
  ```kql
  SecurityEvent
  | where EventID == 4769
  | where AccountName !endswith "$"
  | join kind=leftouter (
      IdentityInfo | project AccountSID, AccountUpn
    ) on $left.SubjectLogonId == $right.AccountSID
  | where isempty(AccountUpn)   // Account in ticket doesn't exist in directory
  | project TimeGenerated, AccountName, ServiceName, IpAddress
  ```

**krbtgt Double Rotation Procedure:**

After detecting a Golden Ticket or krbtgt compromise, rotate krbtgt **twice** (not once — old hash is still valid for one rotation):
```powershell
# Step 1: Reset krbtgt password (AD replication must complete between steps)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (New-Object SecureString)
# Wait 10+ hours (max TGT lifetime) OR force replication and wait for all DCs to sync
# Step 2: Reset krbtgt password again
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (New-Object SecureString)
```
The New-School approach uses the **New-KrbtgtKeys.ps1** script from Microsoft, which automates detection of replication lag and the double-rotation sequence.

### Silver Ticket

**Mechanism:** A Silver Ticket is a forged TGS (service ticket) encrypted with a **service account's NT hash** rather than the krbtgt key. It bypasses the KDC entirely — the forged ticket is presented directly to the target service. Silver Tickets are more targeted (specific service only) but harder to detect since the KDC never sees them.

**Common targets:** `cifs/server` (SMB), `host/server` (WMI/PSRemote), `HTTP/server` (WinRM web), `ldap/dc` (LDAP)

**Detection:**
- Silver Tickets are not logged on the KDC at all — no Event 4768/4769
- Detection requires PAC validation: enable `KDC Kerberos PAC validation` via `KerberosValidateKdcPacSignature` registry key on services — causes service to send PAC to KDC for validation, generating Event 4770
- Event ID 4627 on the target service for logon with mismatched PAC
- MDI correlates Kerberos traffic patterns and detects Silver Tickets via behavioral analysis

### Diamond and Sapphire Tickets

**Diamond Ticket:** Rather than creating a ticket from scratch, the attacker requests a legitimate TGT then modifies its PAC in memory to add elevated SIDs/groups, re-encrypting with the krbtgt key. Harder to detect because the core ticket structure is legitimate.

**Sapphire Ticket:** The attacker requests a legitimate TGT for a highly privileged account (using S4U2Self trick or by compromise), then uses it as-is without modification. The legitimate ticket itself contains all desired privileges.

Both techniques evade detection methods that look for accounts that don't exist or impossible PAC data, since the underlying ticket is real.

### MS14-068 (Historical)

CVE-2014-6324 — A now-patched vulnerability allowing a standard domain user to forge a Kerberos PAC claiming Domain Admin membership. All DCs should be patched; include in vulnerability scanning baseline verification.

---

## 5. Pass-the-Hash & NTLM Relay

### Overview

NTLM authentication uses the NT hash of a user's password as the credential. Unlike Kerberos, NTLM is a challenge-response protocol where the server sends a challenge, and the client responds with an HMAC computed using the NT hash. Attackers who obtain an NT hash can authenticate as the user without knowing the plaintext password. NTLM Relay takes this further — attackers intercept NTLM authentication attempts and relay them to target services.

### Pass-the-Hash (PTH)

**Mechanism:** NTLM authentication: server sends 8-byte challenge → client responds with `HMAC-MD5(NT_hash, challenge)` (NTLMv2) or `DES(NT_hash, challenge)` (NTLMv1). An attacker with the NT hash can compute the correct response without the password.

**Hash extraction:**
```
# Mimikatz — dump from LSASS
mimikatz # sekurlsa::logonpasswords     # requires LSASS debug privilege
mimikatz # lsadump::lsa /patch          # dumps all hashes from LSA

# From NTDS.dit + SYSTEM hive
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

**PTH execution:**
```
# Mimikatz — open session with hash
mimikatz # sekurlsa::pth /user:Administrator /domain:CORP /ntlm:<hash> /run:cmd.exe

# Impacket suite
psexec.py -hashes :NThash CORP/Administrator@192.168.1.10
wmiexec.py -hashes :NThash CORP/Administrator@192.168.1.10
smbexec.py -hashes :NThash CORP/Administrator@192.168.1.10
atexec.py -hashes :NThash CORP/Administrator@192.168.1.10 "whoami"

# CrackMapExec
crackmapexec smb 192.168.1.0/24 -u Administrator -H NThash --local-auth
crackmapexec smb 192.168.1.10 -u Administrator -H NThash -x "whoami"
```

**Detection:**

- **Event ID 4624 (Logon Success) + 4672 (Special Privileges):** PTH generates a Type 3 (Network) logon or Type 9 (NewCredentials) logon. Characteristics:
  - Logon Type `3` with NTLM authentication from unusual source host
  - `LmPackageName`: `NTLM V1` or `NTLM V2` when Kerberos would normally be used
  - `LogonProcessName`: `NtLmSsp` — this should be `Kerberos` for legitimate domain auth
  - Workstation name mismatch: ticket claims workstation X but event source is Y

- **NTLMv1 detection (high priority):**
  ```kql
  SecurityEvent
  | where EventID == 4624
  | where AuthenticationPackageName == "NTLM"
  | where LmPackageName == "NTLM V1"
  | project TimeGenerated, TargetUserName, WorkstationName, IpAddress, LogonType
  ```

- **MDI alert:** *Pass-the-Hash (PTH)* — MDI compares NTLM hashes observed in traffic and detects hash reuse across different source machines.

### NTLM Relay

**Mechanism:** Attackers force victims to authenticate to an attacker-controlled server, then relay those credentials to a target service (SMB → SMB, NTLM → LDAP, etc.). Because NTLM doesn't protect against relay by default, the relayed authentication succeeds at the target as if the victim authenticated directly.

**Step 1 — Poisoning (force authentication):**

Tools like **Responder** poison name resolution to redirect authentication attempts:
- **LLMNR** (Link-Local Multicast Name Resolution, UDP 5355) — responds to any name query
- **NBT-NS** (NetBIOS Name Service, UDP 137) — responds to NetBIOS queries
- **mDNS** (UDP 5353) — Multicast DNS for .local names
- **WPAD** (Web Proxy Auto-Discovery) — fake proxy autoconfigure response forces NTLM auth

```bash
# Responder — listen and poison
responder -I eth0 -rdw   # LLMNR + NBT-NS + WPAD
```

**Step 2 — Relay:**
```bash
# ntlmrelayx.py — relay to target
ntlmrelayx.py -t smb://192.168.1.10 -smb2support         # relay to SMB
ntlmrelayx.py -t ldap://dc01.corp.local --no-da          # relay to LDAP (add user, etc.)
ntlmrelayx.py -t mssql://sqlserver.corp.local            # relay to SQL
ntlmrelayx.py -t https://exchange.corp.local/EWS/        # relay to Exchange
ntlmrelayx.py -t ldaps://dc01.corp.local --add-computer  # create machine account
```

**NTLM Relay to LDAP is particularly dangerous** because it can be used to:
- Add new computer accounts (used for RBCD attacks)
- Modify ACLs on AD objects
- Read sensitive attributes
- Add members to privileged groups

**Detection:**

- **Event ID 4648 (Explicit Credential Logon)** — fires when credentials are passed explicitly, which happens during relay scenarios
- **Event ID 5156 / 5158 (Windows Filtering Platform)** — connection allowed/blocked; correlate NTLM auth events with network connection events
- **Network detection:** LLMNR/NBT-NS responses from non-authoritative sources; mDNS responses; NTLM auth to unusual targets; multiple NTLM authentications from same source in short window
- **Zeek/NDR:** `ntlm.log` shows all NTLM handshakes — alert on NTLM to servers that normally use Kerberos; alert on NTLM auth where source workstation ≠ authenticated machine name

### Prevention

1. **Block LLMNR via GPO:** `Computer Configuration → Administrative Templates → Network → DNS Client → Turn Off Multicast Name Resolution = Enabled`

2. **Block NBT-NS:** Disable NetBIOS over TCP/IP via DHCP option 001 or adapter settings; block UDP 137-138 at perimeter/host firewall.

3. **SMB Signing Required:** GPO: `Microsoft network server: Digitally sign communications (always) = Enabled`. Prevents relay of SMB auth to SMB targets (relay still possible to LDAP/HTTP).

4. **LDAP Signing + Channel Binding:** As described in Section 1 — prevents NTLM relay to LDAP/LDAPS.

5. **Disable NTLMv1:** `Network security: LAN Manager authentication level = Send NTLMv2 response only; refuse LM & NTLM`. NTLMv1 hashes are trivially cracked with rainbow tables.

6. **Extended Protection for Authentication (EPA):** Enforces channel binding for HTTP-based authentication (OWA, ADFS). Configure in IIS and Exchange to prevent relay to these endpoints.

7. **Disable NTLM where possible:** Use Kerberos for all internal authentication. Audit NTLM usage via Event ID 4776 and NetLogon logging (`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\NtlmMinClientSec`).

8. **Credential Guard:** Windows Credential Guard protects NTLM hashes and Kerberos tickets in an isolated VM, preventing memory extraction via LSASS access.

---

## 6. DCSync Attack

### Overview

DCSync is a technique that abuses the legitimate Active Directory replication protocol to extract password hashes directly from a domain controller — without running any code on the DC itself. It exploits the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights that domain controllers use to synchronize the NTDS.dit database. Any account granted these rights can impersonate a DC and request credential data for any domain account.

### Mechanism

**AD Replication protocol background:**

Domain controllers replicate directory changes using the **Microsoft Directory Replication Service (DRS) Remote Protocol** (MS-DRSR). The key RPC call is `DRSGetNCChanges` (opnum 3) which one DC calls on another to request updates since a given USN. The replicated data includes attribute values including `unicodePwd` (NT hash), `supplementalCredentials` (additional credential formats), and `currentValue` of Kerberos keys.

**Rights required:**
- `DS-Replication-Get-Changes` (also known as `Replicate Directory Changes`) — required
- `DS-Replication-Get-Changes-All` (also known as `Replicate Directory Changes All`) — required for sensitive attributes (passwords)
- These are granted by default to: Domain Controllers, Domain Admins, Enterprise Admins, Administrators (domain)
- **Attackers who gain any of these permissions through ACL abuse can DCSync without being a DA**

**Attack execution:**

```bash
# Mimikatz — DCSync specific user
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /all /csv    # dump entire domain

# Impacket secretsdump.py
secretsdump.py CORP/Administrator:pass@dc01.corp.local
secretsdump.py -hashes :NThash CORP/Administrator@dc01.corp.local
secretsdump.py -just-dc-user krbtgt CORP/Administrator:pass@dc01.corp.local
secretsdump.py -just-dc-ntlm CORP/Administrator:pass@dc01.corp.local

# CrackMapExec
crackmapexec smb dc01.corp.local -u Administrator -p pass --ntds
```

### Detection

**Event ID 4662 — An operation was performed on an object:**

This is the primary detection event for DCSync. Logged on the Domain Controller receiving the replication request. Fields:

| Field | DCSync indicator |
|---|---|
| `Object Type` | `%{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (domainDNS class GUID) |
| `Access Mask` | `0x100` (Control Access right) |
| `Properties` | Contains replication right GUIDs: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes) AND `1131f6ab-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) |
| `Subject Account Name` | Should be a domain controller machine account (`DC$`) — anything else is suspicious |

**Enabling Event 4662:** Requires "Audit Directory Service Access" to be enabled AND an appropriate SACL on the domain NC head (added by default via Default Domain Controllers Policy).

**KQL detection query:**

```kql
// DCSync detection — non-DC account exercising replication rights
SecurityEvent
| where EventID == 4662
| where ObjectType contains "19195a5b-6da0-11d0-afd3-00c04fd930c9"   // domainDNS
| where Properties has "1131f6aa" and Properties has "1131f6ab"       // replication GUIDs
| where SubjectAccount !endswith "$"          // non-machine-account performing replication
| where SubjectDomainName != "NT AUTHORITY"
| project TimeGenerated, SubjectAccount, SubjectDomainName, IpAddress, Computer
| order by TimeGenerated desc
```

**Splunk SPL:**

```
index=windows EventCode=4662
| where like(Object_Type, "%19195a5b%")
| where like(Properties, "%1131f6aa%") AND like(Properties, "%1131f6ab%")
| where NOT like(Account_Name, "%$")
| table _time, Account_Name, host, Object_Type, Properties
```

**MDI alert:** *Suspected DCSync attack (replication of directory services)* — MDI specifically monitors DRS traffic and alerts when replication requests originate from non-DC IPs or accounts. This is one of MDI's highest-fidelity alerts. **Severity: High.**

**Hunting for accounts with replication rights (pre-compromise audit):**

```powershell
# Find all accounts with DCSync rights
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:$domainDN"
$acl.Access | Where-Object {
    $_.ObjectType -eq [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
    $_.ObjectType -eq [Guid]"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

Non-DC/non-built-in-admin accounts with these rights must be investigated and remediated immediately.

### Prevention

1. **Audit replication rights quarterly** — Run the PowerShell query above on schedule. Alert on any changes via Event ID 5136 (Directory Service Object Modified) for the domain NC head ACL.

2. **Remove unnecessary replication rights** — No service account, application account, or user account should have `DS-Replication-Get-Changes-All` unless absolutely required by a documented business need.

3. **Protected Users for krbtgt and Administrator** — Even if DCSync succeeds, Protected Users group membership increases the difficulty of using extracted hashes.

4. **Tier 0 isolation** — Ensure accounts that legitimately need replication rights (AAD Connect sync accounts, Azure AD Connect, some backup solutions) are isolated to Tier 0 administration and cannot be compromised from Tier 1/2 systems.

5. **Network segmentation** — MS-DRSR RPC traffic (dynamic ports, RPC endpoint mapper port 135) between non-DC systems and DCs should be blocked or alerted at the network layer.

6. **Monitor NTDS.dit access on DCs** — Any process reading `C:\Windows\NTDS\ntds.dit` or `C:\Windows\System32\config\SYSTEM` on a DC (other than the NTDS service itself) is suspicious. Sysmon File Read events or EDR file access monitoring will catch VSS-based extraction.

---

## 7. Active Directory Certificate Services Attacks

### Overview

Active Directory Certificate Services (AD CS) is Microsoft's PKI implementation, deeply integrated with Active Directory authentication. Certificates issued by enterprise CAs can be used for Kerberos PKINIT authentication (obtaining TGTs), smart card logon, and EFS encryption. Misconfigurations in certificate templates, CA permissions, and enrollment settings create numerous privilege escalation and persistence paths collectively categorized as ESC1 through ESC11+.

### ESC1 — Misconfigured Certificate Template (Enrollee Supplies SAN)

**Vulnerability:** A certificate template is configured with:
- `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` — allows the requester to specify a Subject Alternative Name (SAN) in the CSR
- Authentication EKU (Client Authentication, Smart Card Logon, etc.)
- Enrollment rights for low-privileged users or `Domain Users`

**Impact:** Any domain user can request a certificate claiming to be any other user (Domain Admin) in the SAN. This certificate can be used for Kerberos PKINIT to obtain a TGT as the spoofed user.

**Tooling:**
```bash
# Certipy — enumerate vulnerable templates
certipy find -u user@corp.local -p pass -dc-ip 192.168.1.10 -vulnerable

# Request certificate with spoofed SAN
certipy req -u user@corp.local -p pass -dc-ip 192.168.1.10 \
  -ca CORP-CA -template VulnerableTemplate \
  -upn administrator@corp.local

# Authenticate with obtained certificate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

**Certify.exe (C#):**
```
Certify.exe find /vulnerable
Certify.exe request /ca:CA\CA-Name /template:VulnerableTemplate /altname:administrator
```

**Remediation:** Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from templates that grant enrollment to unprivileged users, OR require CA Manager approval for such requests.

### ESC2 — Any Purpose / SubCA EKU

**Vulnerability:** Template has the `Any Purpose` EKU or the `Certificate Request Agent` EKU with broad enrollment rights. Certificates with `Any Purpose` can be used for any EKU including client authentication. Templates with no EKU act as SubCA certificates.

**Remediation:** Remove overly broad EKUs. Apply principle of least privilege for EKU configuration.

### ESC3 — Certificate Request Agent Abuse

**Vulnerability:** An enrollment agent certificate (OID 1.3.6.1.4.1.311.20.2.1) allows requesting certificates on behalf of other users. If a low-privileged user can obtain this certificate AND another template allows enrollment by certificate request agents, they can request a certificate as any user.

**Two-step attack:**
1. Obtain enrollment agent certificate from ESC3 template
2. Use that certificate to enroll in another template on behalf of `Administrator`

**Remediation:** Restrict enrollment agent templates. Configure "Issuance Requirements" to limit which templates allow agent-based enrollment and which agents are trusted.

### ESC4 — Template ACL Write Access

**Vulnerability:** A low-privileged principal has `Write` rights over a certificate template object in AD (GenericWrite, WriteProperty, WriteDacl). They can modify the template to introduce ESC1 conditions, then exploit it.

**Detection:** Event ID 4899 (Certificate Services template changed) and Event ID 5136 (AD object modified — pKICertificateTemplate class).

**Remediation:** Audit template ACLs. Remove unexpected write permissions. Only PKI administrators should have write access to certificate templates.

### ESC5 — Vulnerable PKI AD Objects

**Vulnerability:** Write access to PKI-related AD objects beyond just templates: the CA server object, the NTAuthCertificates container, or the Public Key Services container. Modification of these objects can compromise the entire PKI.

**Remediation:** Restrict write access to `CN=Public Key Services,CN=Services,CN=Configuration,DC=...` and its children.

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA

**Vulnerability:** The CA is configured with the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag, which allows SAN specification for ALL certificate requests regardless of template settings. Equivalent to ESC1 but affects the entire CA.

**Check:**
```
certutil -config "CA-Server\CA-Name" -getreg policy\EditFlags
```
Look for `EDITF_ATTRIBUTESUBJECTALTNAME2` in the output.

**Remediation:** Remove this flag: `certutil -config "CA\CAName" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`

### ESC7 — Manage CA Right

**Vulnerability:** A low-privileged user has `Manage CA` or `Manage Certificates` rights on the CA. `Manage CA` allows enabling `EDITF_ATTRIBUTESUBJECTALTNAME2` (leading to ESC6). `Manage Certificates` allows approving pending certificate requests.

**Remediation:** Audit CA Officers/Managers membership. Restrict these roles to dedicated PKI administrators.

### ESC8 — NTLM Relay to AD CS HTTP Enrollment

**Vulnerability:** Many AD CS deployments include the Certificate Enrollment Web Service (CES) or Web Enrollment (certsrv) accessible via HTTP without requiring HTTPS + EPA. NTLM authentication to this endpoint can be relayed.

**Attack:** Responder captures NTLM auth → ntlmrelayx relays to `http://ca-server/certsrv/certfnsh.asp` → obtains certificate for the victim account → use for Kerberos auth.

```bash
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support \
  --adcs --template UserAuthentication
```

**Remediation:** Enforce HTTPS on all enrollment endpoints. Enable Extended Protection for Authentication (EPA) on IIS. Disable HTTP (non-SSL) enrollment.

### ESC9 / ESC10 / ESC11

- **ESC9:** `CT_FLAG_NO_SECURITY_EXTENSION` on template prevents the szOID_NTDS_CA_SECURITY_EXT extension from being included. With ESC9 plus the ability to modify the victim's `userPrincipalName` (UPN), an attacker can obtain a cert as another user.
- **ESC10:** Domain controller misconfiguration where `StrongCertificateBindingEnforcement` is not set to `2`, allowing certificate mapping bypass.
- **ESC11:** IF_ENFORCEENCRYPTICERTREQUEST is not set — allows relaying RPC-based certificate requests.

### Detection for AD CS Attacks

**Windows Event IDs (Certificate Services log):**
- **Event ID 4886** — Certificate Services received a certificate request
- **Event ID 4887** — Certificate Services approved and issued a certificate
- **Event ID 4888** — Certificate Services denied a certificate request
- **Event ID 4899** — Certificate Services template was changed
- **Event ID 4900** — Certificate Services template security permission changed

**KQL hunting query — detect anomalous certificate issuance:**

```kql
// Certificates issued with SAN (potential ESC1/ESC6)
SecurityEvent
| where EventID == 4887
| where RequestAttributes contains "san:"    // SAN specified in request
| project TimeGenerated, Computer, TargetUserName, RequestAttributes, CertificateTemplate
| order by TimeGenerated desc
```

**MDI alerts:**
- *Suspicious certificate usage over Kerberos (PKINIT)* — detects certificate-based TGT requests that don't match normal user behavior
- *Active Directory attributes reconnaissance* — Certipy enumeration generates LDAP queries

**Certipy shadow credentials detection (Event ID 4662):**
When Certipy modifies `msDS-KeyCredentialLink` for shadow credential attacks, Event ID 4662 fires with `msDS-KeyCredentialLink` in the Properties field — same as Section 9 coverage.

---

## 8. Lateral Movement Techniques

### Overview

Once attackers establish a foothold, they move laterally to expand access toward high-value targets. Each lateral movement technique uses different protocols and generates distinct telemetry. Defenders should monitor for composite behavioral signals across multiple event sources, as individual events may be benign in isolation.

### PsExec / SMB-based Lateral Movement

**Mechanism:** PsExec (Sysinternals) and its variants copy a service binary to the target's `ADMIN$` share, create a Windows service, and use that service to execute commands. The technique requires SMB access (port 445) and admin rights.

**Network path:** Attacker → SMB → `\\target\ADMIN$` (write binary) → Service Control Manager → Service execution

**Key Event IDs on the TARGET system:**

| Event ID | Source | Description |
|---|---|---|
| 7045 | System | New service installed (service name often random for impacket variants) |
| 4624 | Security | Logon Type 3 (network) from attacker IP |
| 4648 | Security | Explicit credential use |
| 5140 | Security | Network share `ADMIN$` accessed |
| 5145 | Security | Share access check (file/directory within share) |
| 4688 | Security | New process created (attacker's command executed as service) |

**Detection query — PsExec composite signal:**
```kql
let psexec_logons = SecurityEvent | where EventID == 4624 | where LogonType == 3;
let new_services = SecurityEvent | where EventID == 7045;
psexec_logons
| join kind=inner new_services on $left.Computer == $right.Computer
| where TimeGenerated between (ago(5m) .. now())
| project Computer, IpAddress, ServiceName, ServiceFileName, TimeGenerated
```

### WMI Lateral Movement

**Mechanism:** Windows Management Instrumentation allows process creation via `Win32_Process.Create()` (wmiexec.py, Invoke-WMIMethod). Uses DCOM over port 135 + dynamic RPC ports.

**Tools:**
```bash
wmiexec.py CORP/Administrator:pass@192.168.1.10 "whoami"
wmiexec.py -hashes :NThash CORP/Administrator@192.168.1.10
Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target
```

**Key Event IDs on TARGET:**
- **4624** — Logon Type 3 (network NTLM/Kerberos logon for WMI auth)
- **4688** — Process creation: `WmiPrvSE.exe` spawning `cmd.exe` or `powershell.exe` (abnormal parent-child relationship)
- **Microsoft-Windows-WMI-Activity/Operational** Event ID 5857/5858/5859/5860/5861 — WMI activity, consumer-to-filter binding (for persistence-type WMI, not execution)
- Sysmon Event ID 20 (WmiEvent Filter Activity), 21 (WmiEvent Consumer)

**Behavioral indicator:** `WmiPrvSE.exe` spawning command-line tools (`cmd.exe`, `powershell.exe`, `net.exe`) — this parent-child relationship is highly suspicious.

### WinRM / PowerShell Remoting

**Mechanism:** Windows Remote Management (WinRM) runs on ports 5985 (HTTP) and 5986 (HTTPS). PSRemoting sessions run in `wsmprovhost.exe`.

```powershell
# PSRemoting
Enter-PSSession -ComputerName target -Credential (Get-Credential)
Invoke-Command -ComputerName target -ScriptBlock {whoami} -Credential $cred

# Evil-WinRM (offensive)
evil-winrm -i 192.168.1.10 -u Administrator -p pass
evil-winrm -i 192.168.1.10 -u Administrator -H NThash
```

**Key Event IDs on TARGET:**
- **4624** — Logon Type 3 (Kerberos) from attacker
- **4688** — `wsmprovhost.exe` process creation (WinRM host for PS sessions)
- Child processes of `wsmprovhost.exe` — any command execution spawned via PSRemoting
- **Microsoft-Windows-WinRM/Operational** — detailed WinRM session events

**Behavioral indicator:** `wsmprovhost.exe` spawning enumeration tools, `net.exe`, `whoami.exe`, data-staging tools, or other offensive utilities.

### DCOM Lateral Movement

**Mechanism:** Distributed Component Object Model allows remote instantiation of COM objects. Several DCOM objects (MMC20.Application, ShellBrowserWindow, ShellWindows, Excel/Word via COM) can be abused for code execution.

```powershell
# MMC20.Application DCOM
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```

**Detection:** Event ID 4624 (Logon Type 3) followed by `mmc.exe` or `explorer.exe` spawning child processes on the target. DCOM connections appear in ETW provider `Microsoft-Windows-DCOM-Server`.

### RDP Lateral Movement

**Mechanism:** Remote Desktop Protocol (port 3389). Attackers use RDP for interactive access. Restricted Admin mode (`mstsc.exe /restrictedadmin`) allows RDP without sending credentials to the remote host — enabling PTH via RDP.

**Key Event IDs on TARGET:**

| Event ID | Source | Meaning |
|---|---|---|
| 4624 | Security | Logon Type 10 (RemoteInteractive) = RDP logon |
| 4778 | Security | Session reconnected (TS session connect) |
| 4779 | Security | Session disconnected |
| 4625 | Security | Failed logon — brute force indicator |
| 1149 | TerminalServices-RemoteConnectionManager | RDP auth success with source IP |
| 21 | TerminalServices-LocalSessionManager | Session logon successful |
| 24 | TerminalServices-LocalSessionManager | Session disconnected |

**Restricted Admin RDP (PTH via RDP):**
```
mstsc.exe /restrictedadmin /v:target-ip
# After starting with Restricted Admin, inject hash:
mimikatz # sekurlsa::pth /user:Admin /domain:CORP /ntlm:<hash> /run:"mstsc.exe /restrictedadmin"
```

Detection: Logon Type 10 with `NTLM` authentication package (normally RDP uses Kerberos with NLA). Also Event ID 4648 for restricted admin.

### Token Impersonation

**Mechanism:** Windows access tokens represent security context. Attackers with `SeImpersonatePrivilege` (held by service accounts, IIS worker processes) can impersonate tokens of other users. Tools: `incognito` (Metasploit module), `mimikatz token::elevate`.

```
meterpreter > use incognito
meterpreter > list_tokens -u
meterpreter > impersonate_token "CORP\\Administrator"

mimikatz # token::elevate /domainadmin
mimikatz # token::elevate /user:Administrator
```

**Detection:**
- Event ID 4624 Logon Type 9 (NewCredentials) — created when token is impersonated
- Event ID 4672 — special privileges assigned to new logon (if impersonating DA token)
- Sysmon Event ID 10 — suspicious process accessing LSASS (for token extraction from LSASS)

### Composite Behavioral Scoring

No single event definitively indicates lateral movement. Defenders should correlate:

1. 4624 (Type 3 network logon from external IP)
2. + 7045 (new service created within 60 seconds)
3. + 5145 (ADMIN$ access)
4. + 4688 (child process of service binary)

Or:
1. 4624 (network logon)
2. + 4688 (`WmiPrvSE.exe` child = `cmd.exe` / `powershell.exe`)
3. + 5156 (outbound connection from spawned process)

Assign risk scores to each component event and alert when composite score exceeds threshold. This approach dramatically reduces false positives vs alerting on any single Event ID.

---

## 9. Domain Persistence Techniques

### Overview

After achieving Domain Admin or equivalent access, attackers establish persistence mechanisms that survive password resets, account lockouts, and standard incident response procedures. These techniques exploit the trust relationships and replication mechanisms fundamental to AD's design, making them extremely difficult to fully eradicate without specific procedures.

### Golden Ticket Persistence

As covered in Section 4: possessing the krbtgt hash allows generation of valid TGTs indefinitely. The krbtgt hash only changes when explicitly rotated, and requires **two rotations** (with time between them) to fully invalidate outstanding Golden Tickets.

**Persistence signal:** If krbtgt was compromised but only rotated once, attackers may still have valid Golden Tickets for up to the maximum TGT lifetime (default 10 hours, or 10 years if forged without lifetime enforcement).

### SID History Injection

**Mechanism:** The `sIDHistory` attribute stores previous SIDs from domain migrations. Active Directory grants access based on all SIDs in a token, including SID History. Attackers add the Domain Admins SID (or Enterprise Admins SID) to a regular user's `sIDHistory`, granting DA-equivalent access while the account appears to be a normal user.

```
mimikatz # misc::addsid /target:normaluser /sid:S-1-5-21-...-512
```

**Detection:**
- **Event ID 4765** — SID History added to an account
- **Event ID 4766** — An attempt to add SID History to an account failed
- Monitor for any changes to `sIDHistory` attribute on user objects — this should be extremely rare outside documented migration periods

**KQL:**
```kql
SecurityEvent
| where EventID in (4765, 4766)
| project TimeGenerated, TargetAccount, SubjectAccount, SIDHistory
```

**Remediation:** Remove unauthorized SID History entries. Implement SID Filtering on domain trusts to prevent cross-trust SID History abuse.

### AdminSDHolder ACL Backdoor

**Mechanism:** The `AdminSDHolder` container (CN=AdminSDHolder,CN=System,DC=...) holds a template ACL. Every 60 minutes, the `SDProp` process copies this ACL to all accounts in protected groups (Domain Admins, etc.). Attackers add themselves to the AdminSDHolder ACL, causing SDProp to propagate their access to all protected accounts.

```powershell
# Add attacker account to AdminSDHolder ACL
Add-ObjectAcl -TargetAD "CN=AdminSDHolder,CN=System,DC=corp,DC=local" `
  -PrincipalSamAccountName attacker -Rights All
```

**After 60 minutes:** The attacker now has `GenericAll` on every DA/EA/Schema Admin account — they can reset passwords, disable protections, etc.

**Detection:**
- **Event ID 5136** (Directory Service Object Modified) on the AdminSDHolder object itself — any ACL modification here is critical
- Monitor `nTSecurityDescriptor` attribute changes on `CN=AdminSDHolder,CN=System`
- **Event ID 4662** with write access to AdminSDHolder

**Remediation:** Review AdminSDHolder ACL, remove all unexpected entries. No individual user accounts should appear there — only domain groups.

### DSRM Account Abuse

**Mechanism:** Each Domain Controller has a local Directory Services Restore Mode (DSRM) account (local Administrator). If the DSRM password is set to match a domain admin account's hash, or if the registry is configured to allow network logon using the DSRM account (`DsrmAdminLogonBehavior = 2`), attackers gain persistent backdoor access to the DC.

```
mimikatz # lsadump::lsa /patch     # Extract DSRM hash from DC
# Set DsrmAdminLogonBehavior = 2 to allow network logon
```

**Detection:** Monitor `HKLM\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` on DCs — value should be `0` or `1` (not `2`). Event ID 4624 with `DSRM` in logon data.

**Prevention:** Regularly rotate DSRM passwords (Microsoft recommends on AD DS upgrade or quarterly); ensure `DsrmAdminLogonBehavior != 2`.

### Skeleton Key

**Mechanism:** The skeleton key attack patches LSASS on a Domain Controller in memory to accept a universal password ("mimikatz" by default) for any account, while leaving existing passwords working. This is a memory-only implant; it doesn't survive DC reboots.

```
mimikatz # misc::skeleton
# Now ANY account can authenticate with password "mimikatz" (or configured password)
```

**Detection:**
- **Sysmon Event ID 10** — unexpected process accessing LSASS with `VM_READ` access from processes that aren't security products
- **EDR behavioral detection** — LSASS memory patching is a Tier-1 EDR alert across most vendors
- **Event ID 4611** — Trusted logon process registered (Mimikatz registers as trusted logon process)
- **Event ID 4673** — Privileged service called (SeDebugPrivilege used to access LSASS)
- Network anomaly: DC accepting passwords that don't match known hashes

**Prevention:** EDR on all DCs, Credential Guard (prevents userspace LSASS access), Protected Process Light (PPL) for LSASS: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`

### Group Policy Backdoors

**Mechanism:** Attackers with write access to GPOs or OUs can deploy backdoors to all systems in scope: adding local admin accounts, deploying malicious scripts, disabling security tools, or modifying audit policies.

**Detection:**
- **Event ID 5136** — Directory Service Object Modified on GPO objects (`groupPolicyContainer` class)
- **Event ID 5137** — Directory Service Object Created (new GPO)
- **Event ID 5141** — Directory Service Object Deleted
- Monitor `\\domain\SYSVOL` for modifications to GPO scripts (GPT.ini version changes, new script files)
- Alert on GPO link additions/removals to sensitive OUs (Domain Controllers OU, Tier 0 OU)

**Prevention:** AGPM (Advanced Group Policy Management) for change control; separate GPO edit rights from GPO link rights; review all GPOs quarterly.

### DCshadow

**Mechanism:** DCshadow (mimikatz) registers a rogue Domain Controller in AD and uses legitimate replication mechanisms to push malicious changes to real DCs. Unlike DCSync (which reads), DCshadow **writes** — it can modify any AD attribute including `sIDHistory`, group memberships, SPN values, or ACLs.

```
# Terminal 1 — register rogue DC
mimikatz # lsadump::dcshadow /object:CN=attacker,CN=Users,DC=corp,DC=local \
  /attribute:sIDHistory /value:S-1-5-21-...-519

# Terminal 2 — trigger replication push
mimikatz # lsadump::dcshadow /push
```

**Detection:**
- **Event ID 4742/4741** (Computer Account Changed/Created) — DCshadow must register a computer with DC nTDSSite settings
- **Replication traffic** from unexpected source IPs — not real DCs
- **Event ID 4928/4929** (AD Replica Source NC Established/Removed) on legitimate DCs
- MDI: Unusual DC registration or replication source
- Netlogon log on DCs: unexpected replication partner

**Prevention:** Monitor for new `nTDSDSA` objects in Sites/Servers; restrict replication rights; use MDI which has specific DCshadow detection.

### Shadow Credentials

**Mechanism:** The `msDS-KeyCredentialLink` attribute on user/computer objects stores Windows Hello for Business / passwordless auth keys. Attackers with `GenericWrite` or `WriteProperty` rights on a user object can add a rogue key credential, then authenticate as that user using the rogue certificate + private key, bypassing the password entirely.

```bash
# Certipy shadow credentials
certipy shadow add -u user@corp.local -p pass -account targetuser -dc-ip 192.168.1.10
certipy shadow auth -u user@corp.local -p pass -account targetuser -dc-ip 192.168.1.10

# Whisker (C#)
Whisker.exe add /target:targetuser /domain:corp.local /dc:dc01.corp.local
```

**Detection:**
- **Event ID 4662** — Object attribute write, with `msDS-KeyCredentialLink` in Properties field
- Any write to `msDS-KeyCredentialLink` by accounts other than the WHFB enrollment service or the target account itself should alert immediately

**KQL:**
```kql
SecurityEvent
| where EventID == 4662
| where Properties contains "5b47d60f-6090-40b2-9f37-2a4de88f3063"  // msDS-KeyCredentialLink GUID
| where AccessMask == "0x40000"   // WriteProperty
| where SubjectAccount !endswith "$"   // Not machine account
| project TimeGenerated, SubjectAccount, ObjectName, Computer
```

### Resource-Based Constrained Delegation (RBCD) Abuse for Persistence

**Mechanism:** RBCD allows a service to impersonate users to a specific resource. Attackers who can write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of a computer account can configure their controlled computer account to impersonate any domain user to that computer (using S4U2Proxy), effectively gaining persistent administrative access.

**Detection:** Monitor `msDS-AllowedToActOnBehalfOfOtherIdentity` writes via Event ID 4662 (similar to shadow credentials monitoring).

---

## 10. Detection & Hardening Summary

### Event ID Quick Reference — AD Attack Mapping

| Event ID | Source | AD Attack Technique |
|---|---|---|
| **4624** | Security | All lateral movement (Logon Type 3=network, 9=impersonation, 10=RDP); PTH; PTT |
| **4625** | Security | Password spray; brute force; RDP enumeration |
| **4648** | Security | PTH; explicit credential use; WMI/PSExec execution |
| **4662** | Security | DCSync (replication rights); AdminSDHolder ACL; RBCD; shadow credentials; Shadow Credential writes |
| **4663** | Security | Sensitive file/object access (NTDS.dit access, etc.) |
| **4765** | Security | SID History added to account |
| **4766** | Security | SID History add failed (enumeration/attempt) |
| **4768** | Security | AS-REQ / TGT request; AS-REP Roasting (PreAuthType=0) |
| **4769** | Security | TGS-REQ; Kerberoasting (EncType=0x17); Golden/Silver ticket use |
| **4770** | Security | Kerberos ticket renewal; anomalous renewal patterns |
| **4771** | Security | Kerberos pre-auth failed; password spray via Kerberos |
| **4776** | Security | NTLM auth attempt (DC validates credentials); NTLMv1 detection |
| **4886** | Security (CA) | Certificate request received — AD CS attack monitoring |
| **4887** | Security (CA) | Certificate issued — ESC1/ESC6 monitoring |
| **4899** | Security (CA) | Certificate template modified — ESC4 monitoring |
| **5136** | Security | DS Object Modified — GPO changes; AdminSDHolder; replication rights |
| **5137** | Security | DS Object Created — new GPO; new DC registration (DCshadow) |
| **5140** | Security | Network share accessed — ADMIN$ (PsExec); SYSVOL |
| **5145** | Security | Share access check — file-level share access during PsExec |
| **7045** | System | New service installed — PsExec/impacket service-based execution |
| **1644** | Directory Svc | Expensive LDAP query — BloodHound/SharpHound enumeration |
| **4611** | Security | Trusted logon process — skeleton key injection |
| **4672** | Security | Special privileges assigned — DA-equivalent logon; PTH with DA hash |

### MDI Alert Catalog — Technique Mapping

| MDI Alert | MITRE Technique | Severity |
|---|---|---|
| Active Directory attributes reconnaissance (LDAP) | T1069, T1087 | Medium |
| Account enumeration reconnaissance | T1087.002 | Medium |
| Suspected Kerberoasting activity | T1558.003 | High |
| Suspected AS-REP Roasting attack | T1558.004 | High |
| Suspected DCSync attack | T1003.006 | High |
| Suspected Golden Ticket usage | T1558.001 | High |
| Pass-the-Ticket | T1550.003 | High |
| Pass-the-Hash | T1550.002 | High |
| Suspected skeleton key attack | T1556.001 | High |
| Suspicious certificate request (AD CS) | T1649 | High |
| Suspicious network connection over Encrypting File System | T1187 | Medium |
| DCshadow attack | T1207 | High |
| Suspected NTLM relay attack | T1557.001 | High |
| Honeytoken activity | Various | High |

### KQL Hunting Queries — Five High-Value Scenarios

**1. Kerberoasting Detection (RC4 TGS bulk requests):**
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName !startswith "krbtgt"
| summarize RequestCount=count(), ServiceList=make_set(ServiceName, 20)
    by Account, IpAddress, bin(TimeGenerated, 5m)
| where RequestCount >= 3
| extend RiskScore = iif(RequestCount >= 10, "Critical", iif(RequestCount >= 5, "High", "Medium"))
| order by RequestCount desc
```

**2. DCSync Detection (non-DC account with replication rights):**
```kql
SecurityEvent
| where EventID == 4662
| where ObjectType contains "19195a5b-6da0-11d0-afd3-00c04fd930c9"
| where Properties has "1131f6aa" and Properties has "1131f6ab"
| where SubjectAccount !endswith "$"
| project TimeGenerated, SubjectAccount, SubjectDomainName, IpAddress, Computer
| join kind=leftouter (
    IdentityInfo | project AccountSid, AccountDisplayName, JobTitle
  ) on $left.SubjectAccount == $right.AccountDisplayName
| order by TimeGenerated desc
```

**3. Golden Ticket Hunt (anomalous TGT properties):**
```kql
// Look for TGS requests where the account has no corresponding TGT issuance
let TGT_issued = SecurityEvent
    | where EventID == 4768 and ResultCode == "0x0"
    | project TGT_Account=TargetUserName, TGT_IP=IpAddress, TGT_Time=TimeGenerated;
let TGS_requested = SecurityEvent
    | where EventID == 4769 and ResultCode == "0x0"
    | project TGS_Account=Account, TGS_IP=IpAddress, TGS_Time=TimeGenerated, ServiceName;
TGS_requested
| join kind=leftouter TGT_issued on $left.TGS_Account == $right.TGT_Account
| where isempty(TGT_Time) or TGT_Time > TGS_Time  // No TGT preceded this TGS
| where TGS_Account !endswith "$"
| project TGS_Time, TGS_Account, TGS_IP, ServiceName
| order by TGS_Time desc
```

**4. NTLM Relay Indicators (NTLM to atypical targets):**
```kql
SecurityEvent
| where EventID == 4776      // NTLM credential validation on DC
| where Status == "0x0"      // Successful
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AuthenticationPackageName == "NTLM"
    | where LogonType in (3, 9)
  ) on $left.TargetUserName == $right.TargetUserName
| where IpAddress !in (TrustedServerIPs)   // Auth from unexpected source
| summarize count() by TargetUserName, IpAddress, WorkstationName, bin(TimeGenerated, 15m)
| order by count_ desc
```

**5. AD CS Abuse — Anomalous Certificate Issuance:**
```kql
SecurityEvent
| where EventID == 4887   // Certificate issued
| extend CertTemplate = extract("Certificate Template: ([^\\r\\n]+)", 1, EventData)
| extend Requester = extract("Requester: ([^\\r\\n]+)", 1, EventData)
| extend SANField = extract("Subject Alternative Name[^\\r\\n]*: ([^\\r\\n]+)", 1, EventData)
| where isnotempty(SANField)   // Certificate issued with SAN
| where Requester !contains "AUTO_"   // Not auto-enrollment
| project TimeGenerated, Computer, Requester, CertTemplate, SANField
| order by TimeGenerated desc
```

### Microsoft Defender for Identity — Sensor Deployment

**Deployment requirements:**
- Sensor installed on **all Domain Controllers** (required for full coverage)
- Sensor installed on AD FS servers (for federation attack detection)
- Sensor installed on AD CS servers (for ESC attack detection — requires MDI 2.216+)
- Sensors on management servers with domain admin access (honey accounts, etc.)

**Sensor placement checklist:**
- [ ] All DCs in all domains and all sites
- [ ] AD FS / AD CS servers
- [ ] Microsoft Entra Connect (Azure AD Connect) server
- [ ] High-value admin jump servers
- [ ] Verify sensor health in MDI portal — all sensors reporting "Running"

**Key MDI configuration:**
- Define Sensitive Accounts/Groups for enhanced monitoring
- Configure Honeytoken accounts — any use generates immediate high alert
- Enable "Alert on suspicious authentication" for known attack patterns
- Review and tune entity tags: Sensitive, Honeytoken, Exchange Server

### Protected Users Group

The Protected Users security group applies non-configurable security protections. **Enroll all Tier 0 accounts:**

Protections applied automatically:
- Cannot use NTLM (forces Kerberos)
- Cannot use DES or RC4 Kerberos encryption
- Cannot be delegated (no unconstrained/constrained delegation)
- Kerberos TGT lifetime capped at 4 hours (non-renewable)
- Credentials are not cached in LSASS
- Cannot use CredSSP for credential delegation

**Accounts to enroll immediately:** Domain Admins, Enterprise Admins, Schema Admins, krbtgt (by default), DSRM Administrator accounts concept, PAM/PAW administrative accounts.

**Caution:** Test before adding service accounts — Protected Users breaks RC4 and NTLM, which some legacy services require.

### Authentication Policy Silos

Authentication Policy Silos (APS) are fine-grained Kerberos restrictions beyond Protected Users:

```powershell
# Create Authentication Policy restricting DA TGTs to PAW machines only
New-ADAuthenticationPolicy -Name "Tier0-TGT-Policy" -Description "Restrict DA TGTs to PAWs" `
  -UserTGTLifetimeMins 240 `
  -UserAllowedToAuthenticateFrom (Get-ADComputer PAW01).DNSHostName

# Create Silo and assign policy
New-ADAuthenticationPolicySilo -Name "Tier0Silo" `
  -UserAuthenticationPolicy "Tier0-TGT-Policy"
Set-ADAuthenticationPolicySilo "Tier0Silo" -Add (Get-ADUser "DA-account")
```

### Credential Guard Enforcement

Windows Credential Guard isolates LSASS in a virtualization-based security (VBS) container, preventing memory extraction via `sekurlsa::logonpasswords`, `sekurlsa::pth`, and LSASS process injection.

**Enablement via GPO:** `Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security = Enabled`, with Credential Guard = "Enabled with UEFI lock"

**Requirements:** UEFI Secure Boot, 64-bit OS, Hyper-V enabled, TPM 2.0 (recommended)

### LAPS (Local Administrator Password Solution)

LAPS manages unique, random passwords for local Administrator accounts on each domain-joined machine, stored in AD and accessible only to authorized principals.

```powershell
# Deploy LAPS
Import-Module LAPS
Update-LapsADSchema                     # Extend AD schema
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=corp,DC=local"
Set-LapsADReadPasswordPermission -AllowedPrincipals "CORP\HelpdeskAdmins" `
  -Identity "OU=Workstations,DC=corp,DC=local"

# Configure LAPS GPO settings
# Computer Config → Admin Templates → LAPS → Enable password management
```

**Windows LAPS (2023+):** Built into Windows 11 22H2+ and Server 2022+. Supports Azure AD and on-premises AD, Entra ID integration, encrypted password storage, and improved auditing.

### Tiered Administration Model Reference

The Tier model prevents credential exposure across security boundaries:

```
Tier 0: Domain Controllers, AD CA, ADFS, Azure AD Connect, PAM solutions
  ↕ (No credentials cross this boundary)
Tier 1: Servers, Application servers, SQL, Exchange
  ↕ (No credentials cross this boundary)  
Tier 2: Workstations, Helpdesk
```

**Implementation checklist:**
- [ ] Tier 0 admin accounts exist ONLY for DC/PKI/ADFS administration
- [ ] Tier 0 accounts cannot log into Tier 1/2 systems (GPO Logon Rights: "Deny log on locally", "Deny log on through RDS", etc.)
- [ ] No Tier 1/2 admin accounts are members of Tier 0 groups
- [ ] PAWs (Privileged Access Workstations) for all Tier 0 administration
- [ ] Jump servers with MFA for Tier 1 administration
- [ ] Dedicated workstations for Tier 2 helpdesk

### Privileged Access Workstations (PAWs)

PAWs are hardened, dedicated workstations used exclusively for administrative access to high-value systems. Never used for email, web browsing, or general productivity.

**PAW hardening checklist:**
- [ ] Windows Defender Application Control (WDAC) — allowlist only signed, approved applications
- [ ] Credential Guard + Device Guard enabled
- [ ] No local admin rights for end users
- [ ] Outbound firewall — only approved management protocols to approved targets
- [ ] AppLocker / WDAC blocks all non-approved PowerShell execution
- [ ] Microsoft Entra ID joined with Conditional Access requiring compliant device
- [ ] BitLocker full disk encryption with TPM
- [ ] Audit all logons and process executions (forward to SIEM)
- [ ] Monthly OS rebuild from clean image (optional but recommended for Tier 0)

---

*Last updated: 2026-05-06 — Covers techniques through 2025/2026 threat landscape.*  
*Reference sources: Microsoft Security documentation, Impacket/Certipy/Rubeus documentation (for defender awareness), MITRE ATT&CK Enterprise Matrix, SpecterOps research, MDI detection documentation.*
