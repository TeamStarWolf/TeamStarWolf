# Active Directory Security Reference

> **Security Operations Companion** — This document is a defense-focused companion to [Active Directory Attacks](ACTIVE_DIRECTORY_ATTACKS.md). It pairs every major attack technique with detection guidance, hardening controls, and response playbooks. Intended audience: blue teamers, SOC analysts, detection engineers, and AD administrators.

| | |
|---|---|
| **Read this when** | Triaging an AD attack alert (Kerberoasting, DCSync, Golden Ticket) and need the event IDs and hunting queries, hardening a domain or its DCs, or building AD detection coverage in your SIEM |
| **Start at** | [Critical Event IDs Reference Table](#_9-detection-engineering-for-ad), [Kerberos Attack Detection](#_3-kerberos-attack-detection), [AD Architecture & Security Fundamentals](#_1-ad-architecture-amp-security-fundamentals) |
| **Pairs with** | [ACTIVE_DIRECTORY_ATTACKS.md](ACTIVE_DIRECTORY_ATTACKS.md), [ACTIVE_DIRECTORY_ATTACK_REFERENCE.md](ACTIVE_DIRECTORY_ATTACK_REFERENCE.md), [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md), [IDENTITY_SECURITY_REFERENCE.md](IDENTITY_SECURITY_REFERENCE.md) |

---

## Table of Contents
1. [AD Architecture & Security Fundamentals](#_1-ad-architecture-amp-security-fundamentals)
2. [Reconnaissance & Enumeration Detection](#_2-reconnaissance-amp-enumeration-detection)
3. [Kerberos Attack Detection](#_3-kerberos-attack-detection)
4. [Lateral Movement Detection](#_4-lateral-movement-detection)
5. [Privilege Escalation & Persistence](#_5-privilege-escalation-amp-persistence)
6. [Domain Controller Security](#_6-domain-controller-security)
7. [Group Policy Security](#_7-group-policy-security)
8. [AD CS (Certificate Services) Security](#_8-ad-cs-certificate-services-security)
9. [Detection Engineering for AD](#_9-detection-engineering-for-ad)
10. [AD Tiering & Zero Trust](#_10-ad-tiering-amp-zero-trust)

---

## 1. AD Architecture & Security Fundamentals

### 1.1 Forest, Domain, and OU Structure

Active Directory uses a hierarchical namespace. The **forest** is the ultimate security boundary — all domains within a forest share a common schema, configuration partition, and Global Catalog. Trusts within a forest are transitive by default; trusts between forests are not.

| Object | Description | Security Implication |
|--------|-------------|----------------------|
| Forest | Top-level AD container; schema boundary | Compromise of forest root = compromise of all child domains |
| Domain | Authentication/policy boundary; Kerberos realm | Each domain has its own Domain Admins — but Enterprise Admins span all |
| OU (Organizational Unit) | Administrative delegation unit | Misconfigured OU ACLs allow privilege escalation |
| Site | Physical/network grouping | Affects replication topology; wrong site link config can cause auth failures |
| Trust | Cross-domain/forest authentication path | SID filtering must be enforced on all external trusts |

**Key hardening points:**
- Place sensitive assets in OUs with restricted delegation rather than the default Computers/Users containers.
- Use SID filtering (`Set-ADObject -SIDFilteringForestAware $true`) on all forest trusts.
- Audit the default containers (CN=Users, CN=Computers) — automated provisioning tools often place accounts there without GPO coverage.

### 1.2 Global Catalog

The Global Catalog (GC) holds a partial, read-only replica of all objects in every domain in the forest. It listens on TCP **3268** (LDAP) and TCP **3269** (LDAPS). The GC is used for universal group membership resolution during logon.

**Security implication:** Querying the GC with authenticated LDAP returns cross-domain objects that standard LDAP on a single DC would not expose. Attackers use this for forest-wide enumeration. Monitor for high-volume queries on port 3268/3269 from non-DC hosts.

### 1.3 FSMO Roles and Security Implications

| Role | Scope | Security Risk if Compromised |
|------|-------|------------------------------|
| Schema Master | Forest-wide | Attacker can add attributes that persist across the entire forest |
| Domain Naming Master | Forest-wide | Can add/remove domains; pivot point for SID injection |
| PDC Emulator | Domain | Processes password changes; source of time; Kerberos authentication issues if unavailable |
| RID Master | Domain | Allocates RID pools; SID forgery if compromised |
| Infrastructure Master | Domain | Resolves cross-domain references; less commonly targeted |

**Defensive control:** FSMO roles should reside exclusively on Tier 0 DCs. Use `netdom query fsmo` to verify placement. Alert on replication partner changes for FSMO holders.

### 1.4 AD Database — NTDS.dit

`NTDS.dit` is the Jet Blue ESE database that stores all AD objects, including password hashes. Located at `%SystemRoot%\NTDS\ntds.dit` on every DC.

**Critical contents:**
- User password hashes (NT hash, LM hash if enabled, Kerberos keys — AES256, AES128, DES, RC4/NTLM)
- Password history
- All object attributes including ACLs

**Attack vectors:** Volume Shadow Copy (VSS) theft, ntdsutil, `IFM` (Install from Media), DCSync. Refer to section 5 for DCSync detection.

**Defensive controls:**
- Enable VSS audit logging — Event 8222 (VSS provider error) and Sysmon Event 23 (File Delete).
- Alert on `ntdsutil.exe` execution outside of known maintenance windows.
- Restrict backup operator rights — members can read NTDS.dit via VSS.
- Encrypt the NTDS database with BitLocker on the DC volume.

### 1.5 Kerberos Authentication Flow

```
Client → KDC (AS-REQ): Encrypted timestamp (PA-DATA) + client principal
KDC → Client (AS-REP): TGT encrypted with krbtgt hash + session key encrypted with user hash
Client → KDC (TGS-REQ): TGT + SPN requested
KDC → Client (TGS-REP): Service ticket encrypted with service account hash
Client → Service (AP-REQ): Service ticket
```

**Key hashes involved:**
- **AS-REQ/AS-REP**: krbtgt AES256/RC4 encrypts TGT; user AES256/RC4 encrypts session key
- **TGS-REP**: Service account hash encrypts the service ticket (target of Kerberoasting)
- **AP-REQ**: No KDC contact — service validates ticket itself (enables Silver Ticket attacks)

**Event IDs:**

| Event | Meaning |
|-------|---------|
| 4768 | TGT requested (AS-REQ processed) |
| 4769 | Service ticket requested (TGS-REQ processed) |
| 4770 | Service ticket renewed |
| 4771 | Kerberos pre-authentication failed |
| 4820 | Kerberos policy check |

### 1.6 NTLM Authentication Flow

```
Client → Server (NEGOTIATE): NTLMSSP_NEGOTIATE
Server → Client (CHALLENGE): 8-byte nonce
Client → Server (AUTHENTICATE): NTHash(nonce) = NTLMv1 response OR HMAC-MD5(NTHash, nonce+timestamp) = NTLMv2
Server → DC (NetLogon): Pass-through authentication
DC → Server: Accept/Deny
```

NTLM is targeted by Pass-the-Hash (PTH), NTLM relay, and downgrade attacks. **Defensive controls:**
- Enforce NTLMv2 via GPO: `Network security: LAN Manager authentication level = Send NTLMv2 response only`.
- Block NTLM where possible using Authentication Policies (section 6.2).
- Enable `Network security: Restrict NTLM` audit mode, then blocking mode.
- Event 4624 LogonType 3 with `AuthenticationPackageName = NTLM` = NTLM network logon (suspicious from privileged accounts).

### 1.7 LDAP, LDAPS, and LDAP Signing

| Protocol | Port | Risk |
|----------|------|------|
| LDAP | 389 | Cleartext; susceptible to relay |
| LDAPS | 636 | TLS-encrypted; requires PKI |
| GC LDAP | 3268 | Forest-wide cleartext |
| GC LDAPS | 3269 | Forest-wide TLS |

**LDAP signing enforcement** (GPO path: `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options`):
- `Domain controller: LDAP server signing requirements` -> **Require signing**
- `Network security: LDAP client signing requirements` -> **Require signing**

Unsigned LDAP enables LDAP relay attacks (CVE-2017-8563 and similar). As of the March 2020 security update (KB4520412), DCs default to rejecting unsigned LDAP binds. **Verify** with `ldap_serverintegrity` registry check and the DC diagnostic event log.

### 1.8 AD Replication Protocol (MS-DRSR)

MS-DRSR (Directory Replication Service Remote Protocol) is used by DCs to replicate changes. The key RPC methods are:
- `DRSGetNCChanges` — pulls object changes from a source DC (abused by DCSync)
- `DRSReplicaAdd` / `DRSReplicaSync` — add replication partners

**Security implication:** Any account granted the rights `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` can call `DRSGetNCChanges` to extract all password hashes without touching NTDS.dit on disk. This is DCSync.

### 1.9 Trust Relationships and Security Boundaries

| Trust Type | Direction | Transitivity | SID Filtering Default |
|------------|-----------|-------------|----------------------|
| Parent-Child | Bidirectional | Transitive | Off (same forest) |
| Tree-Root | Bidirectional | Transitive | Off (same forest) |
| Shortcut | Configurable | Partial | Off (same forest) |
| External | Configurable | Non-transitive | On |
| Forest | Configurable | Transitive | On |
| Realm | Configurable | Configurable | On |

**Defensive controls:**
- Enable **Selective Authentication** on forest trusts to restrict which resources trusting-forest users can access.
- Audit trust SIDHistory attributes — attackers with DA in a child domain can forge SID history containing Enterprise Admin SID to escalate to forest root.
- Monitor for new trust creation: `Event 4706` (trust created), `4707` (trust removed).

### 1.10 Critical AD Ports

| Port | Protocol | Service | Attack Surface |
|------|----------|---------|----------------|
| 88 | TCP/UDP | Kerberos | Kerberoasting, PTT, Golden/Silver Ticket |
| 135 | TCP | RPC Endpoint Mapper | DCSync, WMI lateral movement |
| 389 | TCP/UDP | LDAP | Enumeration, relay attacks |
| 445 | TCP | SMB | PTH, PsExec, lateral movement |
| 636 | TCP | LDAPS | Encrypted LDAP (preferred) |
| 3268 | TCP | Global Catalog | Forest-wide enumeration |
| 3269 | TCP | GC LDAPS | Encrypted forest-wide LDAP |
| 5985/5986 | TCP | WinRM | PowerShell remoting lateral movement |
| 49152-65535 | TCP | RPC dynamic | Replication, WMI |

### 1.11 Privileged Groups

| Group | Scope | Risk Level |
|-------|-------|------------|
| Domain Admins | Domain | Critical — full domain control |
| Enterprise Admins | Forest | Critical — full forest control |
| Schema Admins | Forest | Critical — can modify schema |
| Group Policy Creator Owners | Domain | High — GPO persistence |
| Account Operators | Domain | High — can modify non-admin accounts |
| Backup Operators | Domain | High — can read NTDS.dit via VSS |
| Print Operators | Domain | Medium — can load kernel drivers on DCs |
| Server Operators | Domain | Medium — can log on locally to DCs |
| DNSAdmins | Domain | High — DLL injection into DNS service (running as SYSTEM on DC) |
| ENTERPRISE DOMAIN CONTROLLERS | Forest | High — can trigger replication |

**Hardening:** Use AdminSDHolder and SDProp (runs every 60 min) to protect privileged group members. Monitor `adminCount=1` attribute — objects inheriting from privileged groups get this set. Audit all members with `adminCount=1` that are NOT in privileged groups (orphaned protected objects).

---

## 2. Reconnaissance & Enumeration Detection

### 2.1 LDAP Queries Used for Reconnaissance

Tools like **BloodHound/SharpHound**, **ldapdomaindump**, **PowerView**, and **ADExplorer** perform automated LDAP enumeration. Common query patterns:

| Tool | Typical LDAP Filter | Purpose |
|------|--------------------|---------|
| SharpHound | `(objectCategory=computer)` | Enumerate all computers |
| SharpHound | `(objectClass=group)` | Enumerate all groups |
| SharpHound | `(objectCategory=person)(objectClass=user)` | Enumerate users |
| SharpHound | `(objectClass=trustedDomain)` | Trust enumeration |
| BloodHound ACL | `(objectCategory=*)` with SD control | ACL collection |
| ldapdomaindump | `(objectClass=organizationalUnit)` | OU structure |
| PowerView | `(servicePrincipalName=*)` | SPN enumeration |
| PowerView | `(msDS-AllowedToDelegateTo=*)` | Delegation discovery |

**Behavioral indicators:**
- Hundreds of LDAP queries within seconds from a single non-DC source IP
- Queries requesting all attributes (`*`) on large object sets
- Repeated queries for `nTSecurityDescriptor` attribute (ACL enumeration — SharpHound ACL collection)
- Queries using `LDAP_SERVER_SD_FLAGS_OID` control (OID `1.2.840.113556.1.4.801`)

### 2.2 Detecting Anonymous LDAP Bind

Anonymous LDAP bind allows unauthenticated enumeration. On Windows DCs, anonymous LDAP access is restricted by default, but misconfiguration can enable it.

**Check for anonymous LDAP:**
```powershell
$conn = New-Object System.DirectoryServices.Protocols.LdapConnection("dc.domain.com:389")
$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
$conn.Bind()
```

**Detection:** Event `4625` with `AuthenticationPackageName = -` (anonymous), or network capture showing LDAP BindRequest with empty credentials. **Hardening:** Set `DSHeuristics` to disable anonymous LDAP, and ensure `LDAP_SERVER_POLICY_OID` is configured.

### 2.3 Event IDs for LDAP Reconnaissance

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4661 | Security | A handle to an object was requested — indicates directory service object access |
| 1644 | Directory Service | Expensive/inefficient LDAP query logged on DC (requires registry enable) |
| 2887 | Directory Service | Unsigned LDAP bind received |
| 2888 | Directory Service | Client refused LDAP signing |
| 2889 | Directory Service | Client did not attempt LDAP signing |

**Enabling Event 1644 (expensive query logging):**
```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics
"15 Field Engineering" = 5
```
This logs queries taking more than 30ms or visiting more than 10,000 entries. Adjust thresholds:
```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
"Expensive Search Results Threshold" = 1000
"Inefficient Search Results Threshold" = 1000
```

### 2.4 PowerShell AD Module and Net Command Detection

**PowerShell AD module queries (commonly abused):**
```powershell
Get-ADUser -Filter * -Properties *          # Full user enumeration
Get-ADComputer -Filter * -Properties *      # Full computer enumeration
Get-ADGroupMember "Domain Admins"           # Privileged group membership
Get-ADTrust -Filter *                       # Trust enumeration
Get-ADObject -Filter {adminCount -eq 1}     # Find protected accounts
```

**Net commands (legacy but still common):**
```
net user /domain
net group "Domain Admins" /domain
net localgroup administrators
net view /domain
net accounts /domain
```

**Detection — Sysmon Event 1 (Process Create):**
- `ParentImage` = powershell.exe + `CommandLine` contains `Get-AD*`
- `Image` = net.exe or net1.exe + `CommandLine` contains `/domain`
- Flag `Get-ADObject` with `adminCount` filter — near-exclusive attacker usage

**KQL — Net domain commands:**
```kql
DeviceProcessEvents
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("/domain", "Domain Admins", "Domain Controllers")
| where AccountName != "SYSTEM"
| summarize count(), makeset(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 5m)
| where count_ > 3
```

### 2.5 SPN Enumeration Patterns

SPN enumeration precedes Kerberoasting. Attackers query LDAP for accounts with `servicePrincipalName` set.

**Native query:**
```
setspn -T domain.com -Q */*
```
**LDAP filter used:**
```
(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))
```

**Detection:** High-volume `4769` events with unique service names from a single source, or LDAP queries with `servicePrincipalName` filter observed in Event 1644 / network capture.

### 2.6 ADSI Queries

Attackers use ADSI (Active Directory Service Interfaces) via .NET or COM to bypass obvious tools:
```powershell
$searcher = [adsisearcher]"(objectClass=computer)"
$searcher.FindAll()
```

**Detection:** Sysmon Event 18 (Pipe Connected) or Event 3 (Network Connection) showing PowerShell or custom EXE connecting to DC on port 389/3268. Process access via `System.DirectoryServices.dll` loaded in unusual processes.

### 2.7 LDAP Query Audit Logging Setup

Full LDAP audit pipeline:
1. **Enable Directory Service Access auditing** (GPO): `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> DS Access -> Audit Directory Service Access = Success, Failure`
2. **Enable expensive query logging** (registry — see section 2.3)
3. **Forward Event 4661 and 1644** to SIEM via Windows Event Forwarding (WEF) or Winlogbeat
4. **Zeek LDAP logging** (if network tap available): Zeek's `ldap.log` captures bind DNs, filters, result codes
5. **LDAP traffic parsing** in Zeek produces: `ldap.log`, `ldap_search.log` — filter for `filter` field containing `servicePrincipalName`, `adminCount`, `nTSecurityDescriptor`

### 2.8 Detecting BloodHound Collection

SharpHound has distinct collection patterns:

**ACL collection indicator:** LDAP queries with `LDAP_SERVER_SD_FLAGS_OID` control and `(objectCategory=*)` base filter — queries the security descriptor of every AD object.

**Session collection:** SharpHound enumerates logged-on sessions via `NetSessionEnum` (SMB `srvsvc`) and `NetWkstaUserEnum`. This generates:
- Event `4624` LogonType 3 connections to many hosts in rapid succession from the collection host
- SMB named pipe `\\srvsvc` access (Sysmon Event 18)

**DCE/RPC enumeration detection:**
- Zeek `dce_rpc.log`: look for `SAMR` interface calls (`endpoint = samr`) from non-DC hosts
- Event `4624` + `4634` pairs from a host visiting more than 20 targets in 5 minutes = automated collection

**Network traffic signature:**
- Single host to multiple DCs on port 389 with high query volume
- LDAP `searchRequest` with `baseObject = DC=domain,DC=com`, `scope = wholeSubtree`, `filter = (objectCategory=*)`

### 2.9 Zeek LDAP Logging

Deploy Zeek on a span port or inline tap at the DC network segment:

```zeek
# ldap.log fields of interest:
# uid, ts, uid, id.orig_h, id.resp_h, id.resp_p
# bind_dn, result_code, diagnostic_message
# ldap_search.log: base_object, scope, deref_aliases, filter, attributes
```

**Detection rule (Zeek + Sigma):**
```yaml
title: Mass LDAP Enumeration
detection:
  filter_condition:
    ldap_search.base_object|contains: 'DC='
    ldap_search.scope: 'wholeSubtree'
  condition: filter_condition | count(uid) by id.orig_h > 500 in 60s
```

### 2.10 Network Traffic Patterns for Domain Enumeration

| Pattern | Protocol | Detection |
|---------|----------|-----------|
| Single source to DC:389, 1000+ queries/min | LDAP | Zeek ldap_search.log volume |
| Single source to DC:445, SAM-R calls | SMB/DCE-RPC | Zeek dce_rpc.log endpoint=samr |
| Source to many hosts:445 srvsvc | SMB | Event 5140 across multiple targets |
| Source to DC:88, many TGS-REQ | Kerberos | Event 4769 volume spike |
| Source to DC:3268, wholeSubtree | GC LDAP | Global Catalog enumeration |
| DNS zone transfer attempt | DNS/TCP | DNS Event 6702 |
| LLMNR/NBNS poisoning | UDP 5355/137 | Zeek dns.log + dhcp.log |

**Baselining approach:** Establish normal LDAP query rates per source IP using a 30-day rolling window. Alert on 3-sigma deviations. Non-DC hosts generating more than 100 LDAP queries per minute are high-confidence anomalies.

---

## 3. Kerberos Attack Detection

### 3.1 Kerberoasting

**Attack chain:** Enumerate SPNs -> request TGS for service account -> offline brute-force RC4 ticket.

**Detection — Event 4769:**
```
Event 4769: A Kerberos service ticket was requested
  Account Name: attacking_user
  Service Name: MSSQLSvc/sql01.domain.com
  Ticket Encryption Type: 0x17  <- RC4-HMAC (the tell)
  Ticket Options: 0x40810000
  Client Address: 10.x.x.x
```

**KQL detection query:**
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"    // RC4-HMAC
| where ServiceName !endswith "$"          // Exclude machine accounts
| where ServiceName !startswith "krbtgt"
| summarize count(), makeset(ServiceName) by AccountName, IpAddress, bin(TimeGenerated, 10m)
| where count_ > 1 or array_length(set_ServiceName) > 1
```

**Splunk SPL:**
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| search NOT Service_Name="*$" NOT Service_Name="krbtgt*"
| stats count values(Service_Name) as SPNs by Account_Name, Client_Address, _time span=10m
| where count > 2
```

**Hardening controls:**
- Use **AES-only** service accounts: `Set-ADUser svc_sql -KerberosEncryptionType AES128,AES256` — eliminates RC4 TGS issuance
- Enable **Protected Users** security group for service accounts where possible
- Use **Managed Service Accounts (MSA)** or **Group Managed Service Accounts (gMSA)** — 240-char random passwords make offline cracking infeasible
- **Audit SPNs** quarterly: `Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName`

### 3.2 AS-REP Roasting

**Attack:** Accounts with `DONT_REQUIRE_PREAUTH` flag set respond to AS-REQ without requiring encrypted timestamp — the AS-REP contains material encryptable offline.

**Detection — Event 4768:**
```
Event 4768: A Kerberos authentication ticket (TGT) was requested
  Pre-Authentication Type: 0        <- No preauth required
  Result Code: 0x0 (success)
  Account Name: vuln_user
  Client Address: 10.x.x.x
```

**KQL:**
```kql
SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"
| where ResultCode == "0x0"
| where AccountName !endswith "$"
| summarize count() by AccountName, IpAddress, bin(TimeGenerated, 1h)
```

**Hardening:**
- Audit accounts with no-preauth flag: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth`
- Enable preauth on all accounts unless technically required (legacy NFS clients may need it)
- Add such accounts to Protected Users group to force AES and preauth

### 3.3 Pass-the-Ticket (PTT)

**Attack:** Stolen TGT or service ticket injected into LSASS using `Rubeus.exe ptt` or Mimikatz `kerberos::ptt`.

**Detection indicators:**
- Event 4769 requests from a host where the user has no associated Event 4768 (TGS without prior TGT from same IP)
- `klist.exe` equivalent behavior — ticket injection does not generate standard logon events
- Sysmon Event 10: LSASS process access with `GrantedAccess = 0x1010 or 0x1438` from unusual process
- Rubeus leaves named pipe artifacts (Sysmon Event 17/18)

**KQL (TGS without preceding TGT from same source):**
```kql
let tgt = SecurityEvent | where EventID == 4768 | project AccountName, IpAddress, TimeGenerated;
SecurityEvent
| where EventID == 4769
| join kind=leftanti (tgt) on AccountName, IpAddress
| where TimeGenerated > ago(1h)
| where ServiceName !startswith "krbtgt"
```

### 3.4 Overpass-the-Hash (OPtH)

**Attack:** Convert NT hash to Kerberos TGT using Mimikatz `sekurlsa::pth`. Results in a new process with a Kerberos ticket obtained using the hash.

**Detection:** Event 4768 originating from a **workstation** (non-DC) where the client address is the workstation but `LogonType` context does not match. In normal environments, workstations obtain TGTs from DC — the 4768 event appears on the DC with the workstation IP. The suspicious indicator is a brand-new TGT request from an unexpected host for a privileged account during off-hours.

Combine with: Sysmon Event 1 for `mimikatz.exe` or `sekurlsa` command-line strings, and Event 4624 LogonType 9 (NewCredentials — `runas /netonly`).

### 3.5 Golden Ticket

**Attack:** Forge TGT using the `krbtgt` account's NT hash. The forged ticket can include arbitrary SIDs, arbitrary PAC data, and arbitrarily long validity.

**Detection challenges:** Golden Tickets do not require KDC contact for TGT issuance — the forgery is presented directly to services. However, detection is possible:

| Indicator | Event | Notes |
|-----------|-------|-------|
| Ticket lifetime greater than domain maximum | 4769 | Compare ticket lifetime field vs domain policy |
| Non-existent account name in ticket | 4769 | Username not found in AD but ticket accepted |
| PAC validation failure | 4769 result 0x1f | Service detects invalid PAC |
| 4769 + 4672 with no 4768 | Security | No TGT issuance, but service ticket and elevated rights appear |
| RC4 ticket for privileged account | 4769 | When domain enforces AES, RC4 = forged |

**KQL (4769 with no preceding 4768):**
```kql
let tgt_events = SecurityEvent | where EventID == 4768 | project AccountName, IpAddress, TimeGenerated;
SecurityEvent
| where EventID == 4769
| where AccountName has_any ("Administrator", "admin", "DA")
| join kind=leftanti (tgt_events) on AccountName, IpAddress
| where TimeGenerated > ago(2h)
```

**Hardening — Double krbtgt reset:**
```powershell
# Reset krbtgt password — must be done TWICE with replication delay between resets
# This invalidates ALL existing golden tickets
$krbtgt = Get-ADUser krbtgt
Set-ADAccountPassword $krbtgt -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)" -Force)
# Wait for AD replication (minimum replication cycle) then repeat
```

### 3.6 Silver Ticket

**Attack:** Forge service ticket using service account's NT hash. No KDC contact required.

**Detection:** Silver Tickets bypass the KDC entirely — there is no 4769 event on the DC. Detection relies on:
- Service-side event logging: Windows Kerberos service validation failure (Event `4820` on the target)
- Network-level: Kerberos AP-REQ to service with no preceding TGS-REQ to DC for that SPN
- PAC validation: Enable `ValidateKdcPacSignature` on services (requires KDC contact for PAC verification — breaks Silver Ticket forging)

**Registry to enforce PAC validation:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
ValidateKdcPacSignature = 1
```

### 3.7 Diamond Ticket and Sapphire Ticket

**Diamond Ticket:** Requests a legitimate TGT then modifies PAC in-memory using krbtgt key. More stealthy than Golden Ticket as it starts from a real ticket.

**Sapphire Ticket:** Uses `S4U2Self` + `S4U2Proxy` extension to impersonate high-privilege users with legitimate tickets, avoiding krbtgt hash requirement.

**Detection differences:**
- Diamond: 4768 event IS present (real ticket requested), but PAC modification leaves traces in ticket structure
- Sapphire: Multiple `S4U2Self` and `S4U2Proxy` service ticket requests (4769) for high-privilege targets — alert on S4U extension tickets for DA-equivalent accounts

**KQL (S4U service ticket requests):**
```kql
SecurityEvent
| where EventID == 4769
| where TicketOptions has "0x40800010"   // S4U flag pattern
| where ServiceName !endswith "$"
| where AccountName has_any ("Administrator", "krbtgt")
```

### 3.8 Summary — Kerberos Attack Detection Matrix

| Attack | Key Event | Indicator | Priority |
|--------|-----------|-----------|----------|
| Kerberoasting | 4769 | EncType=0x17, non-machine SPN | High |
| AS-REP Roasting | 4768 | PreAuth=0, success | High |
| Pass-the-Ticket | 4769 | TGS without 4768 from same host | Medium |
| Overpass-the-Hash | 4768 | TGT request from workstation for privileged account | High |
| Golden Ticket | 4769+4672 | No 4768, anomalous ticket lifetime | Critical |
| Silver Ticket | Service events | No 4769 on DC, service auth failure | High |
| Diamond Ticket | 4768+4769 | Valid ticket + PAC anomaly | High |
| Sapphire Ticket | 4769 | S4U flags on privileged service names | High |

---

## 4. Lateral Movement Detection

### 4.1 Pass-the-Hash (PTH)

**Attack:** Use NT hash directly for NTLM authentication without knowing plaintext password.

**Detection — Event 4624:**
```
Event 4624 LogonType 3 (Network):
  Authentication Package: NTLM
  LM Authentication: NTLMv1 or NTLMv2
  Logon Account: Administrator
  Source IP: attacker workstation
```

**High-confidence indicators:**
- `LogonType = 3` + `AuthPackage = NTLM` for privileged accounts (Domain Admins, local Admin)
- NTLMv1 usage — `LmPackageName = NTLM V1` (implies `/lm` hash use, older attack tools)
- Admin account appearing at multiple hosts within 5 minutes with NTLM auth
- Local administrator account (same name/hash) authenticating to multiple hosts — indicates shared local admin credentials

**KQL:**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName has_any ("Administrator", "admin")
| summarize count(), makeset(Computer) by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 2 or array_length(set_Computer) > 2
```

**Hardening:**
- Deploy **LAPS** (Local Administrator Password Solution) — unique local admin passwords per host eliminate lateral spread via shared hashes
- Enable **Protected Users** group for privileged accounts — disables NTLM authentication entirely for members
- Block NTLM outbound from workstations using Authentication Policies

### 4.2 PsExec and Remote Service Creation

**Attack chain:** Attacker copies binary to `\\target\ADMIN$`, creates service via SCM, executes binary as SYSTEM.

**Detection:**

| Event ID | Source | Description |
|----------|--------|-------------|
| 7045 | System | New service installed |
| 4688 | Security | `services.exe` spawning child process |
| 5140 | Security | Network share `ADMIN$` accessed |
| 5145 | Security | `ADMIN$` share with write access |

**KQL (PsExec pattern):**
```kql
SecurityEvent
| where EventID == 7045
| where ServiceFileName has_any ("PSEXESVC", "\\ADMIN$", "\\IPC$", "cmd.exe", "powershell.exe")
| project TimeGenerated, Computer, ServiceName, ServiceFileName, AccountName
```

### 4.3 WMI Lateral Movement

**Attack:** `wmic /node:target process call create "cmd.exe"` or PowerShell `Invoke-WMIMethod`.

**Detection:**
- Event 4624 LogonType 3 + Event 4688 `WmiPrvSE.exe` spawning child process on **target** host
- WMI-Activity Operational log: `Microsoft-Windows-WMI-Activity/Operational` Event 5857 (provider loaded) and Event 5861 (registration failed — often seen during exploitation attempts)
- Sysmon Event 20 (WmiEvent) and Event 21 (WmiEventConsumer) — indicates WMI persistence

**KQL:**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 4.4 PowerShell Remoting (WinRM)

**Attack:** `Enter-PSSession` or `Invoke-Command -ComputerName target -ScriptBlock {...}`.

**Detection:**
- Event 4624 LogonType 3 (or LogonType 2 for `-Credential`) from source host
- Event 4648 (explicit credential logon) if `-Credential` used
- WSMan provider log: `Microsoft-Windows-WinRM/Operational` Event 6 (WSMan session created)
- PowerShell Operational log (Event 4103/4104) on **target** — ScriptBlock logging captures commands

**KQL (PSRemoting from unusual hosts):**
```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where ProcessName has "wsmprovhost.exe"
| where TargetUserName !endswith "$"
| summarize count(), makeset(Computer) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
```

### 4.5 RDP Lateral Movement

**Attack:** `mstsc.exe` or `xfreerdp` to target; attackers may use `/pth` or stolen tickets.

**Detection:**
- Event 4624 LogonType 10 (RemoteInteractive) — RDP logon
- Event 4778 (session reconnected) / 4779 (session disconnected) — track session lifecycle
- TerminalServices-LocalSessionManager Event 21 (session logon), 23 (session logoff), 25 (session reconnect)
- Unusual source IPs for RDP: workstation to server (acceptable), workstation to workstation (suspicious), server to DC (very suspicious)

**Hardening:**
- Restrict RDP access via GPO to specific security groups
- Enable **Network Level Authentication (NLA)** — requires credentials before establishing session (Event 4625 occurs before full RDP connection, preventing credential harvest from login screen)
- Use **Remote Credential Guard** to prevent credential caching on target

### 4.6 DCOM Lateral Movement

**Attack:** COM objects accessible remotely (MMC20.Application, ShellWindows, ShellBrowserWindow).
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```

**Detection:**
- Event 4688: `mmc.exe` or `dllhost.exe` spawning unusual child processes
- Event 4624 LogonType 3 from source to target using DCOM (RPC dynamic ports)
- Sysmon Event 3: outbound network connection from `mmc.exe` to non-standard ports

### 4.7 Token Impersonation

**Attack:** `Invoke-TokenManipulation`, `incognito`, `PrintSpoofer` — abuse tokens from other processes.

**Detection:**
- Event 4624 LogonType 2 (Interactive) with an impersonation level of `Impersonation` or `Delegation`
- Event 4648 — explicit credential use (often accompanies token operations)
- Sysmon Event 8 (CreateRemoteThread) — injecting into process to steal token
- Sysmon Event 10 — process access to acquire token from another process

### 4.8 Admin Share Access Detection

| Event ID | Description | Alert Condition |
|----------|-------------|----------------|
| 5140 | Network share object accessed | `ADMIN$`, `C$`, `IPC$` from non-admin host |
| 5145 | Network share object access check | WriteData or Delete access to `ADMIN$` |
| 4624 LogonType 3 | Network logon | Followed by 5140 on `ADMIN$` — lateral movement |

**KQL:**
```kql
SecurityEvent
| where EventID == 5145
| where ShareName has_any ("ADMIN$", "C$")
| where AccessMask has_any ("0x2", "0x40")    // Write/Delete
| where SubjectUserName !endswith "$"
```

### 4.9 Lateral Movement Scoring Model

Build a composite risk score for lateral movement detection:

| Indicator | Score |
|-----------|-------|
| NTLM auth to new host (first time in 30 days) | +20 |
| Admin share access (ADMIN$, C$) | +25 |
| New service created within 60s of logon | +30 |
| PowerShell remoting (WSMan) | +20 |
| WMI execution (WmiPrvSE child process) | +25 |
| Source = workstation, target = DC | +40 |
| User is member of Domain Admins | +20 |
| Logon occurred outside business hours | +15 |
| Multiple distinct targets within 10 minutes | +35 |

**Alert threshold:** Score >= 60 = investigation; Score >= 80 = high-priority incident.

---

## 5. Privilege Escalation & Persistence

### 5.1 DCSync Attack

**Attack:** Account with `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` rights calls `DRSGetNCChanges` to extract all password hashes — equivalent to having NTDS.dit access without touching disk.

**Mimikatz command:** `lsadump::dcsync /user:krbtgt /domain:domain.com`

**Detection — Event 4662:**
```
Event 4662: An operation was performed on an object
  Object Type: domainDNS
  Access Mask: 0x100 (Control Access)
  Properties: {1131f0aa-9c07-11d1-f79f-00c04fc2dcd2}  <- DS-Replication-Get-Changes
              {1131f0ab-9c07-11d1-f79f-00c04fc2dcd2}  <- DS-Replication-Get-Changes-All
  Account Name: compromised_account
```

**Critical GUIDs for DCSync detection:**

| GUID | Right | Meaning |
|------|-------|---------|
| `1131f0aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes | Replicate directory changes |
| `1131f0ab-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All | Replicate all directory changes (secrets) |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set | Filtered replication |

**KQL:**
```kql
SecurityEvent
| where EventID == 4662
| where Properties has_any ("1131f0aa", "1131f0ab", "89e95b76")
| where SubjectUserName !endswith "$"    // Exclude machine accounts (legitimate DC replication)
| project TimeGenerated, SubjectUserName, SubjectDomainName, ObjectName, Properties, IpAddress
```

**Hardening:** Audit who has replication rights on the domain NC:
```powershell
(Get-Acl "AD:\DC=domain,DC=com").Access | Where-Object {$_.ObjectType -eq "1131f0aa-9c07-11d1-f79f-00c04fc2dcd2"}
```

### 5.2 AdminSDHolder Abuse

**AdminSDHolder** is a template object (`CN=AdminSDHolder,CN=System,DC=...`) whose ACL is propagated to all protected objects every 60 minutes by `SDProp`. Attackers add themselves to AdminSDHolder ACL to gain persistent access to all privileged accounts.

**Detection:**
- Event 5136 (Directory Service object modified) on `CN=AdminSDHolder`
- Event 4662 on AdminSDHolder object
- Baseline AdminSDHolder ACL and alert on any change

**PowerShell audit:**
```powershell
$adminSDHolder = "AD:\CN=AdminSDHolder,CN=System,$(([adsi]'').distinguishedName)"
(Get-Acl $adminSDHolder).Access | Where-Object {
    $_.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins|Schema Admins"
}
```

### 5.3 ACL-Based Persistence

Common dangerous ACL rights abused for persistence:

| Right | GUID | Abuse |
|-------|------|-------|
| GenericAll | N/A | Full control over target object |
| WriteDACL | N/A | Can modify target's ACL to grant self GenericAll |
| WriteOwner | N/A | Can take ownership, then modify ACL |
| ForceChangePassword | 00299570-246d-11d0-a768-00aa006e0529 | Change target's password without knowing current |
| GenericWrite | N/A | Modify non-protected attributes (e.g., scriptPath, servicePrincipalName) |
| Self-Membership | bf9679c0-0de6-11d0-a285-00aa003049e2 | Add self to group |

**Detection:** Event 4662 (object accessed/modified) + Event 5136 (attribute modified) — monitor modifications to `nTSecurityDescriptor` on privileged objects.

**BloodHound ACL edges to monitor:** GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword, AllExtendedRights on DA/EA/Schema Admin groups, Domain object, AdminSDHolder.

### 5.4 AD CS ESC Attacks (Certificate Services)

See section 8 for full AD CS coverage. Summary of ESC escalation paths:

| ESC | Vulnerability | Impact |
|-----|--------------|--------|
| ESC1 | Template allows subject alt name (SAN) from request + low-priv enrollment | Authenticate as any user |
| ESC2 | Template has SubCA EKU | Certificate works for any purpose |
| ESC3 | Enrollment agent template abuse | Issue certs on behalf of any user |
| ESC4 | Misconfigured template ACL | Write template to enable ESC1 |
| ESC5 | Vulnerable CA server ACL | Control CA to issue arbitrary certs |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA | Same as ESC1 for any template |
| ESC7 | CA officer/manager role abuse | Approve pending requests |
| ESC8 | NTLM relay to HTTP enrollment endpoint | Coerce machine auth to cert for machine account |

### 5.5 Shadow Credentials (msDS-KeyCredentialLink)

**Attack:** Write to `msDS-KeyCredentialLink` attribute of a user/computer to add a certificate-based credential. Then authenticate using the PKINIT protocol to obtain an NT hash via `U2U` (User-to-User authentication).

**Prerequisites:** Write access to target object's `msDS-KeyCredentialLink` attribute.

**Detection:**
- Event 5136 (attribute modified): `AttributeLDAPDisplayName = msDS-KeyCredentialLink`
- Event 4768 with PKINIT pre-authentication from unusual source
- Any modification to `msDS-KeyCredentialLink` on high-value accounts (Domain Admins, krbtgt) = critical alert

**KQL:**
```kql
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| where SubjectUserName !endswith "$"
| where ObjectDN has_any ("Domain Admins", "krbtgt", "Administrator")
```

### 5.6 Resource-Based Constrained Delegation (RBCD)

**Attack:** If attacker has write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of a computer object, they can configure RBCD to allow an attacker-controlled machine account to impersonate any user to that computer (including Domain Admins).

**Detection:**
- Event 5136: `AttributeLDAPDisplayName = msDS-AllowedToActOnBehalfOfOtherIdentity` modified
- Event 4769: `S4U2Self` + `S4U2Proxy` ticket requests for high-privilege targets
- New machine account creation (Event 4741) followed quickly by RBCD modification = high confidence attack

### 5.7 SID History Injection

**Attack:** Mimikatz `misc::addsid` or LDAP modification to add high-privilege SID (e.g., Enterprise Admin SID) to a low-privilege account's `sIDHistory` attribute. Enables privilege escalation across domain trusts.

**Detection:**
- Event 4765/4766 (SID history added/failed to add) — rarely fires legitimately post-migration
- Event 5136: `AttributeLDAPDisplayName = sIDHistory` modified
- Alert on ANY modification to `sIDHistory` outside of documented migration windows

### 5.8 GPO and Scheduled Task Persistence

**Persistence methods:**
- **GPO logon/startup scripts** — see section 7
- **Scheduled tasks via GPO** — deployed to all machines in scope
- **Scheduled tasks via schtasks.exe** — Event 4698 (task created), Event 4702 (task updated)
- **Registry Run keys** — Sysmon Event 13 (registry value set) on `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- **WMI subscriptions** — Sysmon Event 20/21

**KQL (new scheduled task):**
```kql
SecurityEvent
| where EventID in (4698, 4702)
| where TaskContent has_any ("powershell", "cmd", "http", "\\Temp\\", "\\AppData\\")
| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskContent
```

### 5.9 DSRM Account Abuse

Each DC has a local administrator account whose password is the **DSRM (Directory Services Restore Mode)** password. If an attacker dumps this hash and the `DSRMAdminLogonBehavior` registry key is set to `2` (allows network logon with DSRM account), they can authenticate to the DC as local admin.

**Detection:**
- Event 4624 on a DC with `SubjectUserName = Administrator` and `LogonType = 3` (NTLM network logon) — DSRM account does not have Kerberos, so NTLM network logon to DC is suspicious
- Registry audit: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DSRMAdminLogonBehavior = 2` should alert

**Hardening:** Set `DSRMAdminLogonBehavior = 0` (default — only allows DSRM logon in safe mode). Rotate DSRM passwords regularly using `ntdsutil set dsrm password`.

---

## 6. Domain Controller Security

### 6.1 DC Hardening Checklist

**Operating System:**
- [ ] Latest cumulative updates installed; patch within 30 days of release
- [ ] Windows Server 2019/2022 preferred; Server 2016 minimum
- [ ] Minimal role installation — only AD DS, DNS, required roles
- [ ] No user-facing applications on DC (no IIS, SQL, RDP Gateway)
- [ ] AppLocker/WDAC allowlist — only signed, approved binaries execute
- [ ] Secure Boot enabled, TPM 2.0 required
- [ ] BitLocker on all volumes with TPM+PIN protector

**Network:**
- [ ] DC firewall enabled with restrictive inbound rules (only required AD ports from authorized subnets)
- [ ] Block outbound internet from DCs entirely
- [ ] LDAP signing required (both DC and client GPO settings)
- [ ] LDAP channel binding required (KB4520412)
- [ ] SMB signing required on DCs
- [ ] Disable LLMNR and NetBIOS on DC NICs

**Authentication:**
- [ ] Protected Users group — all privileged accounts enrolled
- [ ] Authentication Policies configured to restrict logon hosts
- [ ] Credential Guard enabled on all DCs
- [ ] LSASS PPL (Protected Process Light) enabled
- [ ] NTLMv2 only — LM and NTLMv1 disabled

**Audit:**
- [ ] Advanced Audit Policy — all relevant subcategories enabled
- [ ] Security event log size minimum 1GB, forwarded to SIEM
- [ ] Sysmon deployed with DC-specific config
- [ ] PowerShell ScriptBlock logging enabled
- [ ] Command-line process auditing enabled

### 6.2 Protected Users Security Group

Members of **Protected Users** receive enhanced protection:
- Cannot authenticate using NTLM (only Kerberos)
- Kerberos tickets use only AES encryption (no RC4/DES)
- TGT lifetime reduced to 4 hours (non-renewable)
- Cannot use CredSSP or Digest authentication
- Credentials NOT cached by Windows Credential Manager
- Cannot be delegated (blocks constrained/unconstrained delegation abuse)

**Enrollment:**
```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "Domain Admins member accounts"
```

**Caveat:** Service accounts requiring NTLM, delegation, or cached credentials cannot be enrolled. Test thoroughly before production enrollment.

### 6.3 Authentication Policies and Silos

**Authentication Policies** (requires Windows Server 2012 R2 DFL+) allow you to:
- Restrict which hosts privileged accounts can authenticate from (TGT only issued if source host meets claim)
- Enforce short TGT lifetimes
- Restrict NTLM usage per account

**Authentication Policy Silos** group accounts and policies together.

```powershell
# Create silo for Tier 0 accounts
New-ADAuthenticationPolicySilo -Name "Tier0Silo" -Enforce $true

# Create policy: DA accounts can only get TGTs from PAW hosts
New-ADAuthenticationPolicy -Name "DAPolicy" `
  -UserTGTLifetimeMins 60

# Assign
Set-ADAuthenticationPolicySilo -Identity "Tier0Silo" -UserAuthenticationPolicy "DAPolicy"
Grant-ADAuthenticationPolicySiloAccess -Identity "Tier0Silo" -Account (Get-ADUser "da_account")
```

### 6.4 Credential Guard

Windows Defender Credential Guard uses Hyper-V virtualization (VBS — Virtualization Based Security) to isolate LSASS secrets in a separate, hardware-protected process (`LSAIso`).

**What it protects:** NT hashes, Kerberos TGTs/tickets, and NTDS secrets are not accessible to the normal OS, preventing Mimikatz `sekurlsa::logonpasswords` from dumping credentials.

**Deployment:**
```
GPO: Computer Configuration -> Administrative Templates -> System -> Device Guard
-> "Turn On Virtualization Based Security"
  -> Secure Boot and DMA Protection
  -> Credential Guard: Enabled with UEFI lock
```

**Known bypass techniques (for detection):**
- Downgrade attack: reboot to pre-Credential Guard state requires physical access
- Custom hypervisor attacks (rare, require sophisticated capability)
- Credential Guard does NOT protect credentials in memory of processes running in the regular OS (only LSASS-managed secrets)

### 6.5 LSASS Protection (PPL)

Protected Process Light (PPL) prevents non-PPL processes from reading LSASS memory. Combined with Credential Guard, this defeats most Mimikatz variants.

**Enable via registry:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RunAsPPL = 1
```

**Verify:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
# Should return 1
```

**Bypass techniques to detect:**
- Loading a vulnerable signed kernel driver to bypass PPL (e.g., `RTCore64.sys` BYOVD — Bring Your Own Vulnerable Driver)
- Sysmon Event 6 (Driver loaded) with unsigned or unusual drivers on DCs = critical alert
- Monitor for `mimidrv.sys` hash signatures

### 6.6 ETW-Based Credential Monitoring

**Microsoft-Windows-LSASS ETW provider** emits events on credential access. Enable via:
```powershell
logman create trace "lsass-monitoring" -p "Microsoft-Windows-LSASS" 0xffffffffffffffff 0xff -ets
```

**Windows Security Center / Defender for Identity** uses ETW to detect credential dumping without relying solely on event logs. MDI sensors monitor for:
- Process injecting into LSASS
- Reading LSASS memory (ReadProcessMemory API calls)
- Opening LSASS handle with `PROCESS_VM_READ` access

### 6.7 DC Firewall Rules

Minimum required inbound rules on DC Windows Firewall:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 88 | TCP/UDP | Domain member subnets | Kerberos |
| 135 | TCP | Domain member subnets | RPC endpoint mapper |
| 389 | TCP/UDP | Domain member subnets | LDAP |
| 445 | TCP | Domain member subnets | SMB/SYSVOL/NETLOGON |
| 636 | TCP | Domain member subnets | LDAPS |
| 3268/3269 | TCP | Domain member subnets | Global Catalog |
| 49152-65535 | TCP | DC subnets only | RPC dynamic (replication) |
| 53 | TCP/UDP | Domain member subnets | DNS |
| 3389 | TCP | PAW subnet ONLY | RDP (emergency) |

Block all other inbound. Block ALL outbound internet from DC CIDR.

### 6.8 RODC (Read-Only Domain Controller) Security

RODCs are appropriate for branch offices and DMZ scenarios. Key security properties:
- **Credential caching:** Only explicitly listed accounts' credentials are cached — use RODC Password Replication Policy (PRP) to restrict to required accounts
- **Staged compromise:** Compromising an RODC does NOT give attacker writable access or credentials for non-cached accounts
- **Delegated administration:** Local IT can administer RODC without Domain Admin rights

**Security considerations:**
- If RODC is compromised, immediately run `Get-ADDomainControllerPasswordReplicationPolicyUsage` to determine which credentials were cached, then force password resets for those accounts
- Monitor for unauthorized replication attempts from RODC via Event 4928/4929

### 6.9 DCshadow Detection

**Attack:** DCshadow registers a rogue replication partner temporarily to inject arbitrary object changes into AD.

**Detection:**
- Network: RPC replication traffic from a non-DC IP to a DC (port 135 + dynamic RPC)
- Event 4929 (source directory service removed) or 4928 (source directory service added) from unexpected IP
- SPN changes: DCshadow temporarily adds `GC/` and `E3514235-4B06-11D1-AB04-00C04FC2DCD2/` SPNs to the attacking machine's account

**KQL:**
```kql
SecurityEvent
| where EventID in (4928, 4929)
| where SubjectUserName !endswith "$"
```

---

## 7. Group Policy Security

### 7.1 GPO Security Hardening

Key GPO settings for AD security (applied to all domain-joined systems):

**Account Policies:**
- Minimum password length: 14+ characters
- Password complexity: Enabled
- Password history: 24 passwords
- Maximum password age: 60 days (or use Fine-Grained Password Policies per role)
- Account lockout threshold: 5 attempts / 15 min observation window / 30 min lockout

**Local Policies — Security Options:**
- `Interactive logon: Do not display last username` = Enabled
- `Interactive logon: Machine inactivity limit` = 900 seconds
- `Network security: LAN Manager authentication level` = Send NTLMv2 response only. Refuse LM & NTLM
- `Network security: LDAP client signing requirements` = Require signing
- `Network access: Do not allow anonymous enumeration of SAM accounts` = Enabled
- `Network access: Restrict anonymous access to Named Pipes and Shares` = Enabled
- `User Account Control: Admin Approval Mode for the Built-in Administrator account` = Enabled
- `Audit: Force audit policy subcategory settings` = Enabled

**Windows Defender / AV:**
- Real-time protection: Enabled
- Cloud-delivered protection: Enabled
- Tamper protection: Enabled via Intune/MDE
- Attack Surface Reduction (ASR) rules: Deploy in audit mode first, then enforce

### 7.2 GPO Modification Attack Surface

BloodHound identifies **GPO delegation abuse** through edges:
- `WriteProperty` on GPO object = modify GPO settings
- `GenericWrite` on GPO = full GPO modification
- `CreateChild` on OU = create GPOs linked to OU

**Attack scenario:** Attacker with `WriteProperty` on a GPO linked to Domain Controllers OU adds a startup script that establishes persistence on all DCs.

**Detection:**
- Event 5136 (directory service object modified) where `ObjectClass = groupPolicyContainer`
- Event 5141 (directory service object deleted) for GPO deletion
- SYSVOL change monitoring: Sysmon Event 11 on DC SYSVOL path (`C:\Windows\SYSVOL\`)
- GPO version counter changes: `versionNumber` attribute increase on GPO object

**KQL (GPO modified):**
```kql
SecurityEvent
| where EventID == 5136
| where ObjectClass == "groupPolicyContainer"
| where AttributeLDAPDisplayName in ("gPCFileSysPath", "versionNumber", "flags", "gPCMachineExtensionNames")
| project TimeGenerated, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
```

### 7.3 GPO Delegation Abuse Detection

**Audit GPO delegations:**
```powershell
Get-GPO -All | ForEach-Object {
    Get-GPPermission -Guid $_.Id -All | Where-Object {
        $_.Permission -in @('GpoEditDeleteModifySecurity', 'GpoEdit', 'GpoCustom') -and
        $_.Trustee.SidType -ne 'Unknown' -and
        $_.Trustee.Name -notmatch 'Domain Admins|SYSTEM|Enterprise Admins|Group Policy Creator Owners'
    } | Select-Object @{N='GPO';E={$_.GPOName}}, Trustee, Permission
}
```

Alert on any delegation grants outside of approved principals.

### 7.4 Detecting Unauthorized GPO Changes (Event 5136)

Full audit pipeline for GPO changes:
1. Enable GPO change auditing: `Advanced Audit Policy -> DS Access -> Audit Directory Service Changes = Success`
2. Monitor SYSVOL via Sysmon File Creation (Event 11) and File Modification
3. Forward Event 5136 with `ObjectClass = groupPolicyContainer` to SIEM
4. Implement **GPO versioning baseline** — store known-good GPO exports weekly and compare

**SYSVOL integrity monitoring:**
```powershell
# Baseline GPO files
Get-ChildItem -Recurse "\\domain.com\SYSVOL\domain.com\Policies\" -File |
    Get-FileHash -Algorithm SHA256 |
    Export-Csv "gpo_baseline_$(Get-Date -f yyyyMMdd).csv"
# Run nightly and diff against baseline
```

### 7.5 Startup/Logon Script Security

GPO scripts (logon/logoff/startup/shutdown) run as SYSTEM (startup/shutdown) or the logged-on user (logon/logoff). These are stored in SYSVOL and are a persistence target.

**Hardening:**
- Restrict SYSVOL write access to Domain Admins and SYSTEM only
- Scripts should be signed (AppLocker script rules + code signing)
- Audit script content — no hardcoded credentials, no internet downloads
- Monitor changes to `\\domain.com\SYSVOL\domain.com\scripts\`

### 7.6 AppLocker vs WDAC via GPO

| Feature | AppLocker | WDAC (Windows Defender Application Control) |
|---------|-----------|---------------------------------------------|
| GPO deployment | Computer Config -> Windows Settings -> Security Settings -> Application Control Policies | Computer Config -> Windows Settings -> Security Settings -> Windows Defender Application Control |
| Bypass resistance | Moderate (constrained language mode bypass exists) | High (kernel-enforced, much harder to bypass) |
| Management complexity | Low-Medium | High |
| Logging | Event log (AppLocker) | ETW + Event log |
| Recommended for | Workstations, servers | High-security (DCs, PAWs) |

Deploy WDAC in **audit mode** first (Event 3076), then **enforce mode** (Event 3077) after tuning policy.

### 7.7 Restricted Groups and Tiered Admin via GPO

**Restricted Groups GPO** (`Computer Configuration -> Windows Settings -> Security Settings -> Restricted Groups`):
- Define who must be in local `Administrators` group on each tier
- Tier 2 workstations: Tier 2 admin group only
- Tier 1 servers: Tier 1 admin group only
- Tier 0 DCs: Domain Admins only (no other accounts)

This enforces the tiered model and prevents tier-crossing (a Tier 2 admin logging onto a Tier 0 DC).

### 7.8 Fine-Grained Password Policies (FGPP)

FGPP (Password Settings Objects — PSO) allows different password policies per group/user:

```powershell
# Strict policy for privileged accounts
New-ADFineGrainedPasswordPolicy -Name "PrivilegedAccountPolicy" `
    -Precedence 1 `
    -MinPasswordLength 20 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "60.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 3 `
    -LockoutDuration "01:00:00" `
    -LockoutObservationWindow "00:30:00"

Add-ADFineGrainedPasswordPolicySubject -Identity "PrivilegedAccountPolicy" -Subjects "Domain Admins"
```

### 7.9 GPO Backup and Integrity Checking

```powershell
# Backup all GPOs
$backupPath = "C:\GPOBackups\$(Get-Date -Format yyyyMMdd)"
New-Item -ItemType Directory -Path $backupPath
Get-GPO -All | Backup-GPO -Path $backupPath
```

**Weekly integrity check:** Compare GPO backup with previous week using file hashes. Alert on any change not matching approved change ticket.

### 7.10 Microsoft Security Baseline GPOs

Microsoft provides Security Baseline GPOs via the **Security Compliance Toolkit (SCT)**:
- Windows Server 2022 Security Baseline
- Microsoft 365 Apps Security Baseline
- Windows 11 Security Baseline
- Windows Defender Antivirus Baseline

Download from the Microsoft Security Compliance Toolkit page. Import and merge with organizational GPOs using LGPO.exe. Review and test before production deployment — some settings may break legacy applications.

---

## 8. AD CS (Certificate Services) Security

### 8.1 AD CS Architecture

**CA Hierarchy:**
```
Root CA (offline, air-gapped)
    |-- Subordinate/Issuing CA (online, domain-joined)
            |-- Template: User Authentication
            |-- Template: Computer Authentication
            |-- Template: Code Signing
            |-- Template: Smart Card Logon
```

**CA Roles:**

| Role | Description | Security Risk |
|------|-------------|---------------|
| Root CA | Trust anchor; self-signed cert | Offline; compromise = rebuild entire PKI |
| Subordinate CA | Signed by Root; issues end-entity certs | Online; primary attack target |
| Issuing CA | Subordinate CA that directly issues to clients | Must be heavily hardened |
| OCSP Responder | Online certificate status checking | DoS target; must be HA |

**Active Directory Certificate Services integrates with AD via:**
- `CertificationAuthority` container in Configuration NC
- `PKIEnrollmentService` objects — published in `CN=Enrollment Services,CN=Public Key Services,CN=Services`
- Certificate templates — stored in `CN=Certificate Templates,CN=Public Key Services`

### 8.2 Certificate Templates and Permissions

Certificate templates define what a certificate can be used for, who can enroll, and what attributes enrollees can specify. Misconfigured templates are the root cause of most ESC vulnerabilities.

**Critical template settings:**
- **EKU (Extended Key Usage):** Defines certificate purpose — `Client Authentication (1.3.6.1.5.5.7.3.2)` enables Kerberos logon
- **Subject Name Source:** `Supplied in the request` vs `Active Directory information` — the former allows SAN specification (ESC1)
- **Enrollment rights:** Who can enroll — too broad = low-privilege users can request high-value certs
- **Requires CA approval:** Pending vs auto-issuance — auto-issuance is the attack scenario
- **Requires authorized signatures:** Enrollment agent requirements
- **Key archival:** Whether CA keeps a copy of the private key

### 8.3 ESC1-ESC8 Vulnerabilities

**ESC1 — Enrollee Supplies Subject (SAN):**
- Template allows `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`
- Template has Client Authentication EKU
- Low-privilege accounts can enroll
- **Impact:** Authenticate as any user (including DA) by specifying their UPN in SAN
- **Certipy detection:** `certipy find -u user@domain.com -p pass -dc-ip DC_IP -vulnerable`

**ESC2 — SubCA / Any Purpose EKU:**
- Template has `Any Purpose` EKU or SubCA EKU
- Low-privilege accounts can enroll
- **Impact:** Certificate can be used for any purpose, including acting as a CA

**ESC3 — Enrollment Agent Abuse:**
- Template 1: Enrollment Agent template (Certificate Request Agent EKU) — low-priv can enroll
- Template 2: Template allowing enrollment agent signatures + low-priv enrollment
- **Impact:** Issue certificates on behalf of any user

**ESC4 — Template ACL Misconfiguration:**
- Low-privilege users have `Write` rights on a certificate template object
- **Impact:** Attacker modifies template to add SAN flag (ESC1 condition), enrolls, then reverts

**ESC5 — CA Object ACL Misconfiguration:**
- Low-privilege users have ACL control over the CA object or server
- **Impact:** Modify CA configuration to enable ESC1-equivalent conditions

**ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2:**
- CA configured with flag that allows ANY template to accept SAN from request
- **Impact:** Any template with Client Auth EKU becomes ESC1-equivalent
- **Detection:** `certutil -getreg CA\editflags` — check bit 0x00040000

**ESC7 — CA Officer/Manager Role:**
- Attacker holds Certificate Manager role
- **Impact:** Approve or issue pending certificate requests for any user

**ESC8 — NTLM Relay to HTTP Enrollment:**
- Web enrollment endpoint (`http://CA/certsrv/`) allows NTLM authentication
- Coerce machine authentication (PetitPotam, PrinterBug) to relay to certsrv
- **Impact:** Certificate issued for machine account — DCSync equivalence for DCs

**Certipy audit commands:**
```bash
# Find vulnerable templates
certipy find -u 'user@domain.com' -p 'password' -dc-ip 10.0.0.1 -vulnerable -stdout

# ESC1 exploitation example
certipy req -u 'user@domain.com' -p 'password' -ca 'CA-Name' -template 'VulnTemplate' \
  -upn 'administrator@domain.com' -dc-ip 10.0.0.1

# Get NT hash from certificate
certipy auth -pfx 'administrator.pfx' -dc-ip 10.0.0.1
```

### 8.4 CA Server Hardening

```powershell
# CA service account — dedicated, non-interactive, no logon rights to other systems
# CA server — Tier 0; domain-joined but restricted; no browsing internet; no email

# Audit CA configuration
certutil -getreg CA\                    # All CA registry settings
certutil -getreg CA\editflags           # Check for ESC6 flag
certutil -getreg Policy\EditFlags       # Policy module flags
```

**Disable HTTP enrollment (certsrv over HTTP enables ESC8 relay):**
- Remove or require SSL for `http://CA/certsrv/` — enforce HTTPS-only enrollment
- Disable NTLM on the certsrv IIS application; require Kerberos or client certificate authentication

### 8.5 Certificate Template ACL Review

```powershell
# Get all certificate templates with their ACLs
$templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties *

$templates | ForEach-Object {
    $acl = Get-Acl "AD:\$($_.DistinguishedName)"
    $acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.ActiveDirectoryRights -match 'Write|GenericAll|GenericWrite' -and
        $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
    } | Select-Object @{N='Template';E={$using:_.Name}}, IdentityReference, ActiveDirectoryRights
}
```

### 8.6 Monitoring Certificate Issuance

| Event ID | Source | Description |
|----------|--------|-------------|
| 4886 | Security | Certificate Services received a certificate request |
| 4887 | Security | Certificate Services approved and issued a certificate |
| 4888 | Security | Certificate Services denied a certificate request |
| 4890 | Security | Certificate Services revoked a certificate |
| 4896 | Security | One or more rows have been deleted from the certificate database |

**KQL — Detect ESC8 (machine cert issued with alternate UPN):**
```kql
SecurityEvent
| where EventID == 4887
| where Requester !endswith "$"         // Non-machine account requested
| where CertificateTemplate has_any ("Computer", "Machine", "DomainController")
```

**KQL — High volume certificate requests (potential ESC enumeration):**
```kql
SecurityEvent
| where EventID in (4886, 4888)
| summarize count() by Requester, CertificateTemplate, bin(TimeGenerated, 5m)
| where count_ > 10
```

### 8.7 CRL/OCSP Hardening

Certificate revocation is critical — a revoked certificate must not be usable for authentication.

**Hardening:**
- CDP (CRL Distribution Points) and AIA (Authority Information Access) must be HA — outage prevents certificate validation
- OCSP responder: deploy minimum 2 for redundancy; use OCSP stapling where supported
- CRL freshness: publish delta CRLs every 1 hour; base CRL every 24 hours for issuing CAs
- Monitor for CRL expiration in `Microsoft-Windows-CertificationAuthority` operational log

### 8.8 PKI Health Monitoring

```powershell
# Enterprise PKI health check (GUI)
pkiview.msc

# Command-line health check
certutil -verify -urlfetch certificate.cer

# Check CRL validity
certutil -verify -crl crl.crl

# List all issued certs from CA DB
certutil -view -out "RequestID,RequesterName,CommonName,NotBefore,NotAfter,Template" csv

# PingCastle AD health (includes PKI checks)
PingCastle.exe --healthcheck --server domain.com
```

---

## 9. Detection Engineering for AD

### 9.1 Building an AD Detection Stack

**Recommended architecture:**

```
DCs / Member Servers
    -> Windows Event Forwarding (WEF) or Winlogbeat
Log Aggregation (Kafka / Logstash)
    ->
SIEM (Microsoft Sentinel / Splunk / Elastic)
    ->
Detection Rules -> Alert -> SOAR -> Incident Response
```

**Windows Event Forwarding (WEF) setup:**
```powershell
# On collector server
wecutil qc -quiet   # Configure Windows Event Collector service
```

**Subscription XML (critical events):**
```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4662 or EventID=4663 or
                EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4769 or
                EventID=4776 or EventID=5136 or EventID=7045)]]
    </Select>
    <Select Path="System">*[System[EventID=7045]]</Select>
  </Query>
</QueryList>
```

### 9.2 Critical Event IDs Reference Table

| Event ID | Log | Description | Attack Relevance |
|----------|-----|-------------|-----------------|
| 4624 | Security | Successful logon | All lateral movement (check LogonType) |
| 4625 | Security | Failed logon | Brute force, password spray |
| 4648 | Security | Explicit credential logon | Lateral movement, RunAs |
| 4662 | Security | Object operation (DS) | DCSync (check GUIDs), AdminSDHolder |
| 4663 | Security | Object access attempt | File/directory access on DC volumes |
| 4672 | Security | Special privileges assigned | Privilege escalation — DA logon |
| 4698 | Security | Scheduled task created | Persistence |
| 4702 | Security | Scheduled task updated | Persistence modification |
| 4706 | Security | New trust created | Trust attacks |
| 4720 | Security | User account created | Backdoor accounts |
| 4728 | Security | Member added to global security group | Privilege group modification |
| 4732 | Security | Member added to local security group | Local admin changes |
| 4738 | Security | User account changed | Account modification (enable no-preauth) |
| 4756 | Security | Member added to universal security group | DA/EA group modification |
| 4765 | Security | SID History added | SID history injection |
| 4768 | Security | Kerberos TGT requested | AS-REP roasting (PreAuth=0) |
| 4769 | Security | Kerberos service ticket requested | Kerberoasting (EncType=0x17) |
| 4771 | Security | Kerberos pre-auth failed | Brute force |
| 4776 | Security | NTLM authentication | Pass-the-Hash indicator |
| 5136 | Security | Directory service object modified | GPO tampering, ACL changes |
| 5140 | Security | Network share accessed | Lateral movement (ADMIN$) |
| 5145 | Security | Share object access check | Detailed share access |
| 7045 | System | New service installed | PsExec, malicious service |
| 1102 | Security | Audit log cleared | Anti-forensics |
| 4886 | Security | Certificate request received | AD CS attacks |
| 4887 | Security | Certificate issued | AD CS ESC detection |

### 9.3 Sysmon for AD Servers

Recommended Sysmon events for DCs and high-value servers:

| EventID | Description | AD-Specific Use |
|---------|-------------|----------------|
| 1 | Process Create | net.exe, mimikatz, sharphound, nltest |
| 3 | Network Connection | Lateral movement, C2 callbacks |
| 7 | Image Loaded | Suspicious DLL loads in LSASS |
| 8 | CreateRemoteThread | Injection into LSASS |
| 10 | ProcessAccess | LSASS credential dumping (GrantedAccess patterns) |
| 11 | FileCreate | NTDS.dit staging, script drops |
| 13 | RegistryValue Set | Run keys, LSA protection bypass |
| 17 | PipeCreated | Rubeus, CobaltStrike named pipes |
| 18 | PipeConnected | SharpHound, lateral tool connection |
| 20 | WmiEventFilter | WMI persistence |
| 21 | WmiEventConsumer | WMI persistence activation |
| 23 | FileDelete | NTDS staging file cleanup, log deletion |
| 25 | ProcessTampering | Process hollowing/doppelganging |

**Critical Sysmon rule — LSASS access:**
```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  <GrantedAccess condition="contains any">0x1010;0x1038;0x40;0x1400;0x1438;0x143a;0x1418;0x100000</GrantedAccess>
</ProcessAccess>
```

### 9.4 Microsoft Sentinel AD Analytics Rules

Key built-in Sentinel rules for AD:

| Rule Name | MITRE Tactic | Description |
|-----------|-------------|-------------|
| Multiple Password Reset | Credential Access | Password spray indicator |
| DCSync Attack | Credential Access | Event 4662 with replication GUIDs |
| Kerberoasting | Credential Access | Event 4769 RC4 service ticket spike |
| Golden Ticket | Privilege Escalation | 4769 without preceding 4768 |
| AdminSDHolder Modified | Persistence | Event 5136 on AdminSDHolder |
| New Privileged Group Member | Privilege Escalation | 4728/4756 on DA/EA |
| LSASS Memory Dump | Credential Access | Sysmon 10 on lsass.exe |
| Suspicious Service Installed | Persistence | Event 7045 with unusual binary path |

**Custom Sentinel KQL — Password spray detection:**
```kql
let threshold = 20;
SecurityEvent
| where EventID == 4625
| where LogonType in (2, 3, 7, 10)
| where AccountName != "-" and AccountName !endswith "$"
| summarize FailCount=count(), DistinctAccounts=dcount(AccountName) by IpAddress, bin(TimeGenerated, 30m)
| where DistinctAccounts >= threshold   // Many accounts = spray (vs brute force = one account)
| extend AttackType = "PasswordSpray"
```

### 9.5 Microsoft Defender for Identity (MDI)

MDI (formerly Azure ATP) is Microsoft's purpose-built AD threat detection product. Deployed as sensor agents on DCs, MDI monitors:

**Key MDI alert categories:**
- **Reconnaissance alerts:** LDAP enumeration, SPN discovery, user/group enumeration
- **Compromised credential alerts:** Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Kerberoasting, AS-REP Roasting, Brute force
- **Lateral movement alerts:** Remote code execution, suspected WMI/SMB/PowerShell remoting
- **Domain dominance alerts:** DCSync, Golden Ticket, Skeleton Key, DCShadow, AdminSDHolder modification
- **Exfiltration alerts:** Suspicious data replication (SMB)

**MDI deployment:**
```powershell
# Deploy MDI sensor on DC
# Download sensor from MDI portal, then install with workspace key
# Azure ATP Sensor Setup.exe /AccessKey <WorkspaceKey> /NetFrameworkCommandLineArguments "/q"
```

### 9.6 Honeypot Accounts and Honeytoken Techniques

**Canary/Honeytoken accounts** are accounts that should NEVER be used. Any authentication attempt = active attacker.

**Setup:**
```powershell
# Create honeytoken account
New-ADUser -Name "svc-backup-legacy" -Description "Legacy backup service - DO NOT USE" `
    -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true

# Set password — complex, stored securely but never provided to anyone
Set-ADAccountPassword svc-backup-legacy -NewPassword (ConvertTo-SecureString "$(New-Guid)$(New-Guid)" -AsPlainText -Force)

# Alert on Event 4768/4769/4625/4624 for this account
```

**MDI integration:** MDI has a built-in honeytoken account feature — designate accounts and MDI auto-alerts on any usage.

**Canary SPN:** Add an SPN to a honeytoken account. Any Kerberoasting scan will request a service ticket — Event 4769 — immediate alert.

### 9.7 KQL Hunting Queries for 15+ AD Attack Techniques

```kql
// 1. KERBEROASTING - RC4 service tickets
SecurityEvent | where EventID==4769 | where TicketEncryptionType=="0x17"
| where ServiceName !endswith "$" | summarize count() by AccountName, IpAddress

// 2. AS-REP ROASTING - no preauth accounts
SecurityEvent | where EventID==4768 | where PreAuthType=="0" | where ResultCode=="0x0"

// 3. GOLDEN TICKET - 4769 without prior 4768
let t = SecurityEvent | where EventID==4768 | project AccountName,IpAddress,TimeGenerated;
SecurityEvent | where EventID==4769
| join kind=leftanti (t) on AccountName,IpAddress
| where TimeGenerated > ago(1h)

// 4. DCSYNC - replication GUIDs
SecurityEvent | where EventID==4662
| where Properties has_any("1131f0aa","1131f0ab","89e95b76")
| where SubjectUserName !endswith "$"

// 5. PASS-THE-HASH - NTLM lateral movement
SecurityEvent | where EventID==4624 | where LogonType==3
| where AuthenticationPackageName=="NTLM" | where TargetUserName has "admin"

// 6. ADMIN SHARE ACCESS
SecurityEvent | where EventID==5145
| where ShareName has_any("ADMIN$","C$") | where SubjectUserName !endswith "$"

// 7. NEW PRIVILEGED GROUP MEMBER
SecurityEvent | where EventID in(4728,4756)
| where TargetUserName has_any("Domain Admins","Enterprise Admins","Schema Admins")

// 8. LSASS ACCESS (Sysmon 10)
Event | where Source=="Microsoft-Windows-Sysmon" | where EventID==10
| where TargetImage has "lsass" | where GrantedAccess has_any("0x1010","0x1438","0x143a")

// 9. MALICIOUS SERVICE INSTALL
SecurityEvent | where EventID==7045
| where ServiceFileName has_any("cmd","powershell","\\Temp","\\Users\\Public")

// 10. SHADOW CREDENTIALS - msDS-KeyCredentialLink modified
SecurityEvent | where EventID==5136
| where AttributeLDAPDisplayName=="msDS-KeyCredentialLink"

// 11. GPO MODIFIED
SecurityEvent | where EventID==5136 | where ObjectClass=="groupPolicyContainer"

// 12. NEW TRUST CREATED
SecurityEvent | where EventID==4706

// 13. SID HISTORY INJECTION
SecurityEvent | where EventID==4765

// 14. SCHEDULED TASK WITH SUSPICIOUS CONTENT
SecurityEvent | where EventID==4698
| where TaskContent has_any("http://","https://","powershell","cmd","\\Temp")

// 15. AUDIT LOG CLEARED
SecurityEvent | where EventID==1102

// 16. CERTIFICATE ISSUED TO PRIVILEGED ACCOUNT
SecurityEvent | where EventID==4887
| where SubjectAlternativeName has_any("Administrator","krbtgt","Domain Admins")
```

---

## 10. AD Tiering & Zero Trust

### 10.1 Tier 0 / 1 / 2 Model

The **Active Directory Tiered Administration Model** is a security architecture that prevents credential theft from lower tiers from compromising higher tiers.

```
+--------------------------------------------------+
|  TIER 0: Identity Control Plane                  |
|  Domain Controllers, AD CS (CA servers),          |
|  ADFS, Azure AD Connect (Entra Connect)           |
|  Privileged accounts: Domain Admins, EA, Schema   |
|  Admin hosts: PAWs only                           |
+--------------------------------------------------+
                   | ONE-WAY TRUST
+--------------------------------------------------+
|  TIER 1: Server Workloads                        |
|  Application servers, database servers,           |
|  file servers, infrastructure services            |
|  Privileged accounts: Server Admins (T1)          |
|  Admin hosts: Tier 1 SAWs or jump servers        |
+--------------------------------------------------+
                   | ONE-WAY TRUST
+--------------------------------------------------+
|  TIER 2: Client Devices & End Users              |
|  Workstations, laptops, helpdesk PCs             |
|  Standard user accounts, local admins via LAPS   |
|  Admin hosts: Helpdesk workstations              |
+--------------------------------------------------+
```

**Core rule:** Credentials from a lower tier MUST NOT be present on a higher-tier system. If a Tier 2 account logs onto a Tier 0 DC, the credentials are exposed to every process running on that DC.

**Enforcement via Authentication Policies:**
- Tier 0 accounts: TGT issuance only from Tier 0 PAW hosts
- Tier 1 accounts: Cannot logon to Tier 0 systems
- Tier 2 accounts: Cannot logon to Tier 0 or Tier 1 systems
- Alert on any tier-crossing logon event

### 10.2 PAW (Privileged Access Workstation) Design

**PAW requirements:**
- Dedicated hardware (not a VM on a shared hypervisor)
- Minimal software: OS + management tools only; no email, no browser for general browsing
- WDAC policy in enforce mode — allowlist only signed binaries
- BitLocker with TPM+PIN; SecureBoot; UEFI boot only (no USB boot)
- VPN/Always-On VPN back to management network; no split tunneling
- Credential Guard + LSASS PPL enabled
- Enrolled in Authentication Silo — only from this PAW can Tier 0 accounts obtain TGTs

**PAW network segmentation:**
```
PAW Network (isolated VLAN)
    <-> DC management subnet (ports 88, 135, 389, 445, 636, 3268, 49152-65535)
    <-> CA management (DCOM/RPC)
    DENY: internet access, user VLANs, workstation VLANs
```

### 10.3 Jump Server Architecture

For environments where dedicated PAWs are not feasible for all admins, jump servers provide a controlled intermediary:

```
Admin Laptop (standard) -> MFA VPN/bastion -> Jump Server (hardened) -> Target Systems
```

**Jump server hardening:**
- Session recording (audit all commands — CyberArk, BeyondTrust, Azure Bastion)
- Time-limited sessions with auto-termination
- No persistent credentials — just-in-time access
- Cannot be used for email or web browsing
- Alert on any jump server admin connecting outside business hours

### 10.4 Credential Hygiene

**LAPS (Local Administrator Password Solution):**
```powershell
# Windows LAPS (built-in, Windows Server 2022 / Windows 11 22H2+)
Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=com"
```

**Service account management:**
- Use **gMSA** (Group Managed Service Accounts) for all services: 240-char automatically rotated passwords, no human ever knows the password
- For legacy services requiring user accounts: FGPP with 25+ char password, rotate quarterly, restricted logon hours
- Never use Domain Admin accounts as service accounts — dedicated least-privilege service accounts only
- Audit service accounts: `Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties LastLogonDate,PasswordLastSet`

### 10.5 Microsoft Enterprise Access Model

Microsoft's modern evolution of the tiered model maps to cloud and hybrid environments:

| Plane | Assets | Controls |
|-------|--------|---------|
| Control Plane | Entra ID, AD, CA, ADFS | Most restrictive; PAW required |
| Management Plane | Servers, cloud subscriptions | Secure admin workstation |
| User Access Plane | Apps, data, workstations | Standard device security |

**Key principle:** Control plane compromise = everything compromised. Protect it disproportionately.

### 10.6 Entra ID (Azure AD) Hybrid Join Security

**Hybrid Joined devices** maintain both AD computer account and Entra ID device record. Security considerations:

- **PRT (Primary Refresh Token):** SSO token issued to hybrid-joined devices; compromise enables SSO to all cloud apps — protect like a TGT
- **Entra Connect / AD Connect sync account:** Has `DS-Replication-Get-Changes-All` right — DCSync equivalent. The `MSOL_` sync account is a high-value target
- **Pass-through Authentication (PTA) agent:** Runs on-prem; if compromised, attacker can validate any AD credential for cloud auth
- **Password Hash Sync (PHS):** Syncs NT hashes (a derived hash) to Entra ID — compromise of Entra allows offline attack on synced hashes

**Alert on Entra Connect sync account activity:**
```kql
SecurityEvent
| where EventID == 4662
| where SubjectUserName startswith "MSOL_"
| where Properties has_any("1131f0aa","1131f0ab")
```

### 10.7 Entra ID PIM for AD Privileged Roles

**Privileged Identity Management (PIM)** enforces just-in-time access for cloud roles, but can also govern on-prem AD role activation via **Privileged Access Groups**.

- Entra PIM -> PAG (Privileged Access Group) -> Domain Admins group
- Admins activate PIM request -> approved -> added to PAG -> AD group membership syncs -> TGT with DA rights issued
- Time-limited (e.g., 1 hour); requires MFA and justification; generates audit trail in Entra

### 10.8 Purple Team Exercises for AD

Regular purple team exercises validate detection coverage:

| Exercise | Tools | Detection Tested |
|----------|-------|-----------------|
| Kerberoasting | Rubeus, Impacket | Event 4769 RC4 alert |
| DCSync | Mimikatz, Impacket secretsdump | Event 4662 GUID alert |
| BloodHound collection | SharpHound | LDAP volume alert, SMB srvsvc |
| Lateral movement | PsExec, CrackMapExec | Event 7045, 5145 alert |
| Golden Ticket | Mimikatz | 4769 without 4768 alert |
| RBCD attack | Rubeus | 5136 on msDS-AllowedToActOnBehalf alert |
| AD CS ESC1 | Certipy | Event 4887 with alternate UPN |
| Password spray | Spray, kerbrute | Event 4625 volume alert |

### 10.9 AD Health Assessment Tools

| Tool | Purpose | URL |
|------|---------|-----|
| **PingCastle** | AD risk assessment; generates HTML report with scored findings | pingcastle.com |
| **Purple Knight** | Free; checks 80+ AD indicators of exposure; Semperis product | purpleknight.com |
| **BloodHound CE** | Continuous attack path analysis; graph-based visualization | github.com/SpecterOps/BloodHound |
| **Locksmith** | AD CS / PKI misconfiguration scanner | github.com/trimarcjake/locksmith |
| **ADRecon** | Comprehensive AD enumeration for assessment | github.com/adrecon/ADRecon |
| **Invoke-TrimarcADChecks** | Trimarc AD security checks | trimarcsecurity.com |

**Recommended schedule:**
- BloodHound CE: continuous (daily ingestion)
- PingCastle: monthly
- Purple Knight: quarterly
- Full purple team exercise: semi-annually

### 10.10 AD Incident Response Playbook

**Phase 1 — Containment (0-2 hours):**
1. Identify scope — which accounts/systems compromised
2. Disable compromised accounts (NOT delete — preserve evidence)
3. Isolate compromised hosts from network (keep for forensics)
4. Reset krbtgt password (if Golden Ticket suspected) — TWICE with replication delay
5. Force password reset for all accounts used on compromised hosts
6. Block attacker egress IPs at perimeter firewall

**Phase 2 — Eradication (2-24 hours):**
1. Full credential reset sweep — all accounts accessed on compromised systems
2. Review and rotate service account passwords
3. Audit privileged group membership — remove unauthorized members
4. Review AdminSDHolder ACL, GPOs, scheduled tasks for persistence
5. Check for new trusts, new accounts with adminCount=1
6. Review AD CS — revoke any certificates issued during breach window
7. Check `msDS-KeyCredentialLink` and `msDS-AllowedToActOnBehalfOfOtherIdentity` for unauthorized modifications

**Phase 3 — Recovery (24-72 hours):**
1. Restore from known-good backup if domain is fully compromised
2. Re-image compromised hosts
3. Update detection rules based on attacker TTPs observed
4. Verify Credential Guard and PPL re-enabled post-reimaging
5. Rotate DSRM passwords on all DCs
6. Document IOCs for threat intel sharing

**Phase 4 — Lessons Learned:**
1. Conduct root cause analysis — how did attacker gain initial access
2. Map attack path in BloodHound — identify and remediate chokepoints
3. Update purple team exercise scenarios to include observed TTPs
4. Review and update this playbook

---

*This reference is intended as a living document. Update quarterly and after any security incident. Cross-reference with [ACTIVE_DIRECTORY_ATTACKS.md](ACTIVE_DIRECTORY_ATTACKS.md) for offensive technique details.*
