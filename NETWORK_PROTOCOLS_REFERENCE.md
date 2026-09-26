# Network Protocols Reference — Security Perspective

> **Scope:** Operational reference for security engineers, penetration testers, and blue-teamers.
> All configuration examples target Linux/Cisco IOS unless noted.

| | |
|---|---|
| **Read this when** | Decoding a packet capture in Wireshark/tshark/tcpdump, hardening or reviewing a specific protocol (DNS, TLS, SSH, SNMP, BGP, SMTP, and more), investigating amplification DDoS, spoofing, or C2-over-DNS |
| **Start at** | [TCP/IP Fundamentals](#_1-tcpip-fundamentals), [Protocol Analysis Tools](#_10-protocol-analysis-tools), [Appendix: Quick Reference Commands](#appendix-quick-reference-commands) |
| **Pairs with** | [NETWORK_ATTACKS_REFERENCE.md](NETWORK_ATTACKS_REFERENCE.md), [PACKET_ANALYSIS_REFERENCE.md](PACKET_ANALYSIS_REFERENCE.md), [NETWORK_FORENSICS_REFERENCE.md](NETWORK_FORENSICS_REFERENCE.md), [CRYPTOGRAPHY_REFERENCE.md](CRYPTOGRAPHY_REFERENCE.md) |

---

## Table of Contents

1. [TCP/IP Fundamentals](#_1-tcpip-fundamentals)
2. [DNS Security](#_2-dns-security)
3. [TLS/SSL Security](#_3-tlsssl-security)
4. [HTTP/HTTPS Security](#_4-httphttps-security)
5. [Authentication Protocols](#_5-authentication-protocols)
6. [Network Management Protocols](#_6-network-management-protocols)
7. [Routing & Switching Security](#_7-routing-amp-switching-security)
8. [Email Protocol Security](#_8-email-protocol-security)
9. [Industrial & Specialized Protocols](#_9-industrial-amp-specialized-protocols)
10. [Protocol Analysis Tools](#_10-protocol-analysis-tools)

---

## 1. TCP/IP Fundamentals

### 1.1 IP Header Fields — Security Relevance

| Field | Size | Security Relevance |
|-------|------|--------------------|
| Version | 4 bits | IPv4 vs IPv6 — mixed stacks create bypass opportunities |
| IHL | 4 bits | Abnormal values (< 5) indicate malformed/crafted packets |
| DSCP/ECN | 8 bits | Covert channel potential via unused DSCP bits |
| Total Length | 16 bits | Inconsistency with actual data length → fragmentation attack |
| Identification | 16 bits | Used in fragmentation reassembly; predictable IDs leak OS info |
| Flags (DF/MF) | 3 bits | DF=1 enables path MTU probing; MF=1 signals fragmentation |
| Fragment Offset | 13 bits | Overlapping offsets → Teardrop, Rose, Jolt attacks |
| **TTL** | 8 bits | **OS fingerprinting**: Linux default 64, Windows 128, Cisco IOS 255 |
| Protocol | 8 bits | 6=TCP, 17=UDP, 1=ICMP — protocol tunneling uses unusual values |
| Header Checksum | 16 bits | Corrupt checksum → IDS evasion on some implementations |
| Source IP | 32 bits | Spoofable on networks without BCP 38 egress filtering |
| Destination IP | 32 bits | Broadcast addresses used in smurf amplification |

**TTL-based OS Fingerprinting:**
```
ttl=64   → Linux, Android, macOS (modern)
ttl=128  → Windows (all versions)
ttl=255  → Cisco IOS, Solaris, network equipment
ttl=255  → FreeBSD (varies)
```
Passive fingerprinting captures initial TTL; subtract hops to approximate. Tools: `p0f`, `nmap -O`, Zeek `os_fingerprint` log.

**IP Fragmentation Attacks:**
- **Teardrop**: Overlapping fragment offsets crash unpatched kernels (Windows 3.1–NT 4.0 era).
- **Tiny Fragment Attack**: TCP header split across two fragments to bypass ACL inspection.
- **Fragment Flooding**: Exhaust fragment reassembly buffers (default Linux: 262144 bytes).
- **Mitigation**: Stateful firewall reassembly before inspection; `iptables -A FORWARD -f -j DROP` for tiny fragments.

---

### 1.2 TCP Header and Security

**Header Fields:**

| Field | Size | Security Relevance |
|-------|------|--------------------|
| Source Port | 16 bits | Ephemeral range 32768–60999 (Linux); predictable ports aid spoofing |
| Destination Port | 16 bits | Service identification |
| Sequence Number | 32 bits | ISN prediction → session hijacking; RFC 6528 random ISN required |
| Acknowledgment | 32 bits | Must match seq+1; RST injection requires valid ACK within window |
| Data Offset | 4 bits | Options size; abnormal values cause parsing discrepancies |
| Flags | 9 bits | See table below |
| Window Size | 16 bits | OS fingerprinting (p0f uses window size + options) |
| Checksum | 16 bits | Validation bypass on some IDS implementations |
| Urgent Pointer | 16 bits | Rarely used; historically exploited for IDS evasion |

**TCP Flags:**

| Flag | Hex | Common Security Use |
|------|-----|---------------------|
| FIN | 0x01 | Port scan (FIN scan bypasses stateless ACLs) |
| SYN | 0x02 | Connection initiation; SYN flood target |
| RST | 0x04 | Forceful connection teardown; RST injection attacks |
| PSH | 0x08 | Immediate delivery; often set with ACK in data |
| ACK | 0x10 | Stateful tracking; ACK flood bypasses SYN-only rate limits |
| URG | 0x20 | IDS evasion via urgent data |
| ECE/CWR | 0x40/0x80 | ECN; covert channel in some implementations |
| Xmas (FIN+PSH+URG) | 0x29 | Port scan; elicits RST on closed ports |
| NULL (no flags) | 0x00 | Port scan; elicits RST on closed ports |

**TCP State Machine — Attacker View:**
```
LISTEN → [SYN] → SYN_RCVD → [SYN+ACK] → [ACK] → ESTABLISHED
         ↑ SYN flood targets this transition
ESTABLISHED → [FIN] → FIN_WAIT_1 → [ACK] → FIN_WAIT_2 → TIME_WAIT (2×MSL)
              ↑ RST injection valid here with seq in window
```

**Connection Tracking (conntrack):**
```bash
# View connection table
conntrack -L -p tcp --state ESTABLISHED
# Monitor new connections
conntrack -E --event-mask NEW
# Limits — tune for DDoS resistance
sysctl net.netfilter.nf_conntrack_max=262144
sysctl net.netfilter.nf_conntrack_tcp_timeout_established=86400
```

---

### 1.3 SYN Flood and SYN Cookies

**SYN Flood Mechanics:**
1. Attacker sends high-rate SYN packets (often spoofed source IPs).
2. Server allocates half-open connection state (SYN_RCVD) in backlog.
3. Backlog exhausted → legitimate connections dropped.
4. Default backlog: `net.ipv4.tcp_max_syn_backlog=256` (tunable to 65536+).

**SYN Cookie Defense (RFC 4987):**
```bash
# Enable kernel SYN cookies
sysctl net.ipv4.tcp_syncookies=1
# Verify (should show 1)
cat /proc/sys/net/ipv4/tcp_syncookies
```
- Cookie = hash(src_ip, src_port, dst_ip, dst_port, timestamp, secret) encoded in ISN.
- No backlog entry until valid ACK arrives with matching cookie.
- **Limitation**: TCP options (SACK, window scale, timestamps) not preserved in cookie-only mode.

**Additional Mitigations:**
```bash
# Increase SYN backlog
sysctl net.ipv4.tcp_max_syn_backlog=65536
# Reduce SYN-ACK retries
sysctl net.ipv4.tcp_synack_retries=2
# Enable TCP timestamps for PAWS protection
sysctl net.ipv4.tcp_timestamps=1
# Rate-limit new connections via iptables
iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

---

### 1.4 UDP Amplification/Reflection DDoS

**Attack Pattern:**
1. Attacker spoofs victim's IP as source.
2. Sends small query to open reflector.
3. Reflector sends large response to victim.
4. Bandwidth amplification = response_size / query_size.

**Amplification Factors by Protocol:**

| Protocol | Port | Amplification Factor | Notes |
|----------|------|---------------------|-------|
| DNS | UDP 53 | 28–54× (ANY query) | ANY query deprecated in RFC 8482 |
| NTP | UDP 123 | 556.9× | monlist command (CVE-2013-5211) |
| SSDP | UDP 1900 | 30.8× | Universal Plug and Play |
| Memcached | UDP 11211 | 50,000× | Peak amplification ever measured |
| CLDAP | UDP 389 | 56–70× | Connectionless LDAP |
| RIPv1 | UDP 520 | 131× | Routing Information Protocol |
| SNMP v1/v2c | UDP 161 | 6.3× | GetBulkRequest |
| NetBIOS | UDP 137 | 3.8× | Name service |
| CharGEN | UDP 19 | 358× | Character generator protocol |

**Mitigations:**
- **BCP 38** (RFC 2827): Ingress filtering — ISPs drop spoofed source IP packets.
- **BCP 84** (RFC 3704): Reverse path forwarding (uRPF): `ip verify unicast source reachable-via rx`
- Disable UDP services not in use (monlist: `noquery` in ntpd.conf).
- Rate-limit UDP response traffic at border.
- Scrubbing centers / anycast black-holing (RTBH — Remotely Triggered Black Hole).

---

### 1.5 ICMP Security

**ICMP Type/Code Security Reference:**

| Type | Code | Name | Attack Vector |
|------|------|------|---------------|
| 0 | 0 | Echo Reply | Ping sweep response |
| 3 | * | Destination Unreachable | Port scanning inference |
| 5 | 0/1 | Redirect | **ICMP Redirect attacks** — route table manipulation |
| 8 | 0 | Echo Request | Ping sweep, ICMP tunneling carrier |
| 11 | 0 | TTL Exceeded | Traceroute path disclosure |
| 13/14 | 0 | Timestamp Req/Reply | Time-based fingerprinting |
| 17/18 | 0 | Address Mask Req/Reply | Network information disclosure |

**ICMP Redirect Attacks:**
- Attacker sends Type 5 redirects to redirect victim's traffic through attacker router.
- Linux vulnerable by default: `sysctl net.ipv4.conf.all.accept_redirects=0` to disable.
- Windows: registry `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect=0`

**ICMP Tunneling:**
- Tools: `icmptunnel`, `ptunnel-ng`, `icmpsh`.
- Encapsulate TCP/data in ICMP payload (Echo Request/Reply).
- Detection: Payload size > 64 bytes, asymmetric request/reply ratio, high ICMP rate from single host.
- Wireshark filter: `icmp && data.len > 100`

**Ping Sweep Detection:**
```bash
# Zeek signature
event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
# Snort rule
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; itype:8; threshold:type threshold,track by_src,count 20,seconds 1; sid:1000001;)
```

---

### 1.6 IPv6 Security

**Extension Header Abuse:**
IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Destination) processed before transport layer — historically bypassed ACLs.

| Extension Header | Type | Security Issue |
|-----------------|------|----------------|
| Hop-by-Hop Options | 0 | Must be processed by every router; DoS via crafted options |
| Routing Header Type 0 | 43 | **Deprecated** (RFC 5095) — source routing to bypass firewalls |
| Fragment | 44 | Atomically fragmented headers bypass inspection |
| Destination Options | 60 | Padding options exploited for covert channels |

**RA Guard (Router Advertisement Guard):**
```
# Cisco IOS
ipv6 nd raguard policy CLIENTS
 device-role host
interface GigabitEthernet0/1
 ipv6 nd raguard attach-policy CLIENTS
```
Prevents rogue RA messages that can redirect IPv6 default gateway.

**DHCPv6 Snooping:**
```
# Enable DHCPv6 snooping
ipv6 dhcp snooping
ipv6 dhcp snooping vlan 10
interface GigabitEthernet0/24
 ipv6 dhcp snooping trust   # Uplink/server port only
```

**NDP Inspection (IPv6 ARP equivalent):**
```
ipv6 nd inspection policy NDP-POLICY
 device-role host
 validate source-mac
interface GigabitEthernet0/1
 ipv6 nd inspection attach-policy NDP-POLICY
```

**IPv6 First-Hop Security Checklist:**
- [ ] RA Guard on all access ports
- [ ] DHCPv6 snooping with trusted uplinks only
- [ ] NDP inspection / SEND (RFC 3971) where supported
- [ ] ACL blocking Router Advertisement from hosts (`ipv6 access-list BLOCK_RA`)
- [ ] Filter Routing Header Type 0 at border (`match ipv6 extension-header routing-type 0`)
- [ ] Disable IPv6 tunneling protocols (6to4, Teredo, ISATAP) if not required

---

### 1.7 Wireshark Display Filters — TCP/IP

```
# IP source/destination
ip.src == 192.168.1.100
ip.dst == 10.0.0.0/8
ip.ttl < 10               # Unusual TTL — possibly crafted

# TCP flags
tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN only (connection initiation)
tcp.flags.rst == 1                            # RST packets
tcp.flags == 0x029                            # Xmas scan
tcp.analysis.retransmission                   # Retransmissions
tcp.window_size_value == 0                    # Zero window (DoS indicator)

# Fragmentation
ip.flags.mf == 1          # More Fragments set
ip.frag_offset > 0        # Fragment with offset
ip.flags.df == 0          # DF not set (unusual for modern OS)

# ICMP
icmp.type == 8            # Echo request
icmp.type == 5            # Redirect
data.len > 100 && icmp    # Potential ICMP tunnel

# IPv6
ipv6.nxt == 43            # Routing extension header
icmpv6.type == 134        # Router Advertisement
icmpv6.type == 135        # Neighbor Solicitation
```

---

## 2. DNS Security

### 2.1 DNS Record Types — Security Relevance

| Record | Type # | Security Relevance |
|--------|--------|-------------------|
| A | 1 | IPv4 mapping; DNS hijacking target |
| AAAA | 28 | IPv6 mapping; often less monitored |
| CNAME | 5 | Alias; subdomain takeover via dangling CNAME |
| MX | 15 | Mail routing; target for phishing infrastructure |
| NS | 2 | Authoritative nameservers; NS takeover attacks |
| PTR | 12 | Reverse DNS; used in forward-confirmed rDNS checks |
| SOA | 6 | Zone authority; version info disclosure, zone transfer |
| TXT | 16 | SPF, DKIM, DMARC, domain validation tokens |
| SRV | 33 | Service discovery; exposes internal service topology |
| CAA | 257 | Certificate Authority Authorization |
| TLSA | 52 | DANE — TLS cert pinning in DNS |
| DNSKEY | 48 | DNSSEC public zone signing key |
| DS | 43 | Delegation Signer — links parent to child zone |
| RRSIG | 46 | DNSSEC resource record signature |
| NSEC | 47 | Next Secure — proves non-existence |
| NSEC3 | 50 | Hashed NSEC — prevents zone enumeration |
| ANY | 255 | **Deprecated** for amplification (RFC 8482) |

**Zone Transfer Enumeration:**
```bash
# Attempt zone transfer (AXFR) — should fail on properly configured servers
dig @ns1.example.com example.com AXFR
# Check if zone transfer is restricted
nmap --script dns-zone-transfer -p 53 ns1.example.com
```

---

### 2.2 DNS Cache Poisoning — Kaminsky Attack

**Classic Poisoning (Pre-2008):** Attacker guesses 16-bit Transaction ID → 1/65536 chance per attempt.

**Kaminsky Attack (2008) — CVE-2008-1447:**
1. Query a random, non-existent subdomain (`rand1234.example.com`).
2. Flood resolver with forged responses containing:
   - Matching TXID guess (0–65535)
   - Answer: `rand1234.example.com → attacker_ip`
   - Additional: poisoned NS record for `example.com`
3. Repeat with new random subdomain until TXID matches.
4. Result: Resolver's cache for `example.com` poisoned.

**Attack amplification via ports:**
- Pre-fix: Source port fixed (53) → only 65,536 TXID guesses needed.
- **Fix**: Randomize source port (0–65535) × TXID (0–65535) = 4.3 billion combinations.

**Mitigations:**
```bash
# Verify source port randomization (should show random ports)
tcpdump -n -i eth0 'src port 53' | head -20
# BIND — enable query source port randomization (default in modern versions)
# /etc/named.conf
query-source address * port *;    # Wildcard = random port
# Validate with dig
dig @8.8.8.8 example.com +additional
```
- **0x20 encoding**: Randomize case of query name (`eXaMpLe.CoM`) — response must match case.
- **DNSSEC**: Cryptographic validation eliminates poisoning (see section 2.4).

---

### 2.3 DNS Amplification Attack

**Query:** `dig ANY isc.org @open_resolver` → ~3,000 byte response to ~60 byte query (50× amplification)

**Attack flow:**
```
Attacker (spoofed src=victim_ip) → Open Resolver → Large DNS response → Victim
```

**Detection at resolver:**
- High rate of ANY queries or large TXT/DNSKEY responses
- Single source IP querying many different domains rapidly
- Response traffic >> query traffic (asymmetric ratio)

**Mitigations:**
- **Response Rate Limiting (RRL)** — BIND:
  ```
  rate-limit { responses-per-second 10; window 5; };
  ```
- Disable open recursion: `allow-recursion { 192.168.0.0/16; };`
- Deprecate ANY responses (RFC 8482): return HINFO or minimal response.
- BCP 38 at ISP level prevents source IP spoofing.

---

### 2.4 DNSSEC

**Record Chain of Trust:**
```
Root Zone (.) — signed by ICANN Root KSK
  └─ .com — DS record in root, DNSKEY in .com zone
       └─ example.com — DS record in .com, DNSKEY + RRSIG in example.com
```

**Key Record Types:**
- **DNSKEY**: Public key used to sign zone (KSK: Key Signing Key, ZSK: Zone Signing Key).
- **RRSIG**: Digital signature over an RRset, references signing DNSKEY.
- **DS**: Hash of child zone's KSK, stored in parent zone — establishes delegation trust.
- **NSEC**: Next Secure record proving a name/type does not exist (allows zone walking).
- **NSEC3**: Hashed names to prevent zone enumeration; `opt-out` for sparse zones.

**Validation with dig:**
```bash
# Query with DNSSEC
dig +dnssec example.com A
dig +dnssec example.com DNSKEY
dig +dnssec _dmarc.example.com TXT

# Verify chain of trust
dig +trace +dnssec example.com

# Check DS record in parent zone
dig example.com DS @a.gtld-servers.net

# Detect DNSSEC failures (SERVFAIL may indicate bogus response blocked)
dig +cd example.com A   # +cd = checking disabled, bypass DNSSEC validation
```

**Key Rollover:**
- **ZSK rollover** (recommended every 90 days): Pre-publish new ZSK → sign with both → remove old.
- **KSK rollover** (annually): Requires DS update at parent — RFC 5011 automated trust anchor update.
- Emergency rollover: Immediate key replacement + TTL flush required.

---

### 2.5 DNS over HTTPS (DoH) and DNS over TLS (DoT)

**DoH (RFC 8484):**
- Transport: HTTPS (TCP 443)
- Format: `application/dns-message` (binary) or JSON
- Endpoint: `https://cloudflare-dns.com/dns-query`, `https://dns.google/dns-query`
- **Enterprise monitoring implication**: DoH bypasses traditional DNS monitoring (Zeek dns.log, DNS firewall).

**Enterprise DoH Blocking:**
```
# Cisco Umbrella — enforces DNS via Umbrella resolvers; blocks direct DoH
# Palo Alto Networks — App-ID "dns-over-https" application block
# Windows Group Policy: Disable DoH
# HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
# EnableAutoDoh = 0
```

**DoT (RFC 7858):**
- Transport: TLS over TCP port **853**
- SNI reveals destination resolver but encrypts query content
- Less evasive than DoH (distinct port 853 vs 443)
- Detection: Monitor TCP 853 connections; certificate inspection

**Comparison:**

| Feature | Classic DNS | DoT | DoH |
|---------|-------------|-----|-----|
| Port | UDP/TCP 53 | TCP 853 | TCP 443 |
| Encryption | None | TLS | TLS in HTTPS |
| Monitoring ease | Easy | Medium | Hard |
| Enterprise control | Easy | Medium | Hard |
| Eavesdropping protection | No | Yes | Yes |

---

### 2.6 DNS-Based C2 Detection

**Indicators of C2 via DNS:**

| Indicator | Normal | Suspicious |
|-----------|--------|-----------|
| NXDOMAIN rate | <5% of queries | >15% — DGA beaconing |
| Subdomain length | <20 chars | >40 chars — encoded data |
| Query frequency | Irregular | Regular intervals (beaconing) |
| TTL values | 300–86400s | <60s — evasion |
| Unique subdomains | Few per domain | Thousands (DGA) |
| Payload in subdomain | None | Base32/hex encoded strings |
| Query type | A, AAAA, MX, TXT | TXT/NULL/CNAME for exfiltration |

**Domain Generation Algorithm (DGA) Detection:**
- Entropy analysis: Shannon entropy of subdomain > 3.5 bits/char suggests DGA.
- Consonant/vowel ratio abnormal.
- Known DGA families: Conficker, Necurs, Gozi, Suppobox.

**Zeek dns.log Analysis:**
```bash
# NXDOMAIN rate per client
zeek-cut id.orig_h rcode_name < dns.log | grep NXDOMAIN | sort | uniq -c | sort -rn | head 20

# Long subdomains (potential exfiltration)
zeek-cut query < dns.log | awk 'length($1) > 50' | sort | uniq -c | sort -rn

# Low TTL queries (evasion)
zeek-cut query TTLs < dns.log | awk '{split($2,a,","); if(a[1]<60) print $0}'

# Beaconing — regular query intervals
zeek-cut ts id.orig_h query < dns.log | sort -k1 | awk '{print $2,$3}' | sort | uniq -c
```

**Passive DNS Databases:**
- **Farsight DNSDB**: Historical DNS data, 100B+ records.
- **VirusTotal passive DNS**: Domain-to-IP history.
- **SecurityTrails**: DNS history + subdomain enumeration.
- **RiskIQ PassiveTotal**: Attribution and infrastructure analysis.
- Query: `curl -H "API-Key: $KEY" "https://api.securitytrails.com/v1/domain/example.com/history/a"`

---

### 2.7 DNS Hijacking and Rebinding

**DNS Hijacking Types:**
1. **Local**: Malware modifies hosts file or local resolver.
2. **Router**: Attacker modifies DHCP-served DNS server (router compromise).
3. **Registrar**: Account takeover → NS record modification.
4. **ISP**: ISP intercepts DNS queries (NXDOMAIN hijacking for ads).
5. **BGP-based**: Route hijack of DNS server IP prefix.

**DNS Rebinding Attack:**
1. Victim visits `attacker.com` (TTL=1s, resolves to attacker server).
2. Page loads JavaScript from attacker server.
3. TTL expires; `attacker.com` now resolves to `192.168.1.1` (internal target).
4. Browser same-origin policy allows JS to make requests to `attacker.com` = internal router.
5. Attacker JS reads internal admin interface via victim's browser.

**Rebinding Mitigations:**
- DNS resolver: Reject private RFC 1918 addresses in public DNS responses (DNS rebinding protection).
- BIND: `deny-answer-addresses { 10/8; 172.16/12; 192.168/16; };`
- Web servers: Validate `Host` header; reject requests with unexpected hostnames.
- Browsers: DNS rebinding protection (Firefox, Chrome check for private IP in public DNS response).

---

## 3. TLS/SSL Security

### 3.1 TLS 1.3 vs TLS 1.2 — Security Differences

**Removed in TLS 1.3:**

| Feature | TLS 1.2 | TLS 1.3 | Reason |
|---------|---------|---------|--------|
| RSA key exchange | ✓ | ✗ | No forward secrecy |
| DHE static | ✓ | ✗ | No forward secrecy |
| CBC mode ciphers | ✓ | ✗ | BEAST, POODLE vulnerabilities |
| RC4 | ✓ | ✗ | Statistically broken |
| MD5/SHA-1 in PRF | ✓ | ✗ | Collision vulnerabilities |
| Compression | ✓ | ✗ | CRIME attack |
| Renegotiation | ✓ | ✗ | CVE-2009-3555 |
| Export cipher suites | ✓ | ✗ | FREAK, Logjam |
| Session resumption (SessionID) | ✓ | ✗ | Replaced by PSK |

**TLS 1.3 Improvements:**
- **1-RTT handshake**: Client sends key share in ClientHello → server completes in one round trip.
- **0-RTT (Early Data)**: Resumption with no round trips — **replay attack risk** (see below).
- **AEAD only**: AES-GCM, ChaCha20-Poly1305 — no separate MAC.
- **Ephemeral key exchange only**: ECDHE or DHE — mandatory forward secrecy.
- **Encrypted handshake**: Certificate, CertificateVerify, Finished messages encrypted.

**TLS 1.3 Handshake (simplified):**
```
Client                              Server
  | ── ClientHello (key_share) ──→ |
  | ←─ ServerHello (key_share) ─── |
  | ←─ {EncryptedExtensions}  ─── |
  | ←─ {Certificate}          ─── |
  | ←─ {CertificateVerify}    ─── |
  | ←─ {Finished}             ─── |
  | ── {Finished}             ──→ |
  | ── {Application Data}     ──→ |
```

**0-RTT Replay Risk:**
- Early data sent before server confirmation — no replay protection.
- Mitigations: Single-use tokens, idempotent operations only, `anti-replay` window at server.
- Not suitable for non-idempotent operations (financial transactions, state changes).

---

### 3.2 Cipher Suite Analysis

**TLS 1.3 Cipher Suites (fixed set):**
```
TLS_AES_128_GCM_SHA256        (recommended)
TLS_AES_256_GCM_SHA384        (recommended)
TLS_CHACHA20_POLY1305_SHA256  (recommended)
TLS_AES_128_CCM_SHA256        (IoT/constrained)
TLS_AES_128_CCM_8_SHA256      (IoT/constrained)
```

**TLS 1.2 Cipher Suite Anatomy:**
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 │     │     │        │    │      │
 │     │     │        │    │      └─ MAC hash (SHA384)
 │     │     │        │    └─ Cipher mode (GCM = AEAD)
 │     │     │        └─ Key size (256-bit AES)
 │     │     └─ Bulk cipher (AES)
 │     └─ Authentication (RSA certificate)
 └─ Key Exchange (ECDHE = forward secrecy)
```

**Security Classification:**

| Rating | Key Exchange | Authentication | Cipher | MAC |
|--------|-------------|----------------|--------|-----|
| Strong | ECDHE, DHE | ECDSA, RSA-2048+ | AES-GCM, ChaCha20 | SHA-256+ |
| Acceptable | RSA | RSA-1024+ | AES-CBC | SHA-1 |
| Weak | DH-EXPORT | DSS-512 | 3DES, RC4 | MD5 |
| Prohibited | NULL, EXPORT | NULL, anon | NULL, DES | NULL |

**Perfect Forward Secrecy (PFS):**
- Ephemeral keys (ECDHE/DHE) ensure session keys not derivable from long-term private key.
- If private key compromised later, recorded sessions remain secure.
- Verify PFS: `openssl s_client -connect example.com:443 2>&1 | grep "Server Temp Key"`

---

### 3.3 Historic TLS Vulnerabilities

| Vulnerability | Year | Affected | Attack Summary |
|---------------|------|---------|----------------|
| **BEAST** | 2011 | TLS 1.0 CBC | Chosen-plaintext via predictable IV chaining |
| **CRIME** | 2012 | TLS compression | Compression oracle leaks session tokens |
| **BREACH** | 2013 | HTTP compression | HTTP-level compression oracle (not TLS-level) |
| **POODLE** | 2014 | SSL 3.0 CBC | Padding oracle via CBC malleability |
| **FREAK** | 2015 | Export RSA | Force RSA-EXPORT (512-bit) downgrade |
| **Logjam** | 2015 | DHE-EXPORT | Downgrade to 512-bit DH; state-level attacks on 1024-bit |
| **DROWN** | 2016 | SSLv2 shared key | Decrypt TLS using SSLv2 oracle on same key |
| **ROBOT** | 2017 | RSA-PKCS1v1.5 | Bleichenbacher oracle in RSA decryption |
| **Heartbleed** | 2014 | OpenSSL 1.0.1–1.0.1f | Buffer over-read via malformed heartbeat (CVE-2014-0160) |
| **LOGJAM** | 2015 | TLS DHE | Downgrade to 512-bit Diffie-Hellman |

**Heartbleed Deep Dive (CVE-2014-0160):**
- Missing bounds check in `tls1_process_heartbeat()`.
- Send heartbeat with `length=65535`, actual payload=1 byte.
- Server returns 65535 bytes from heap memory: private keys, session tokens, passwords.
- Detection: `nmap --script ssl-heartbleed -p 443 target`
- Verification: `openssl s_client -connect target:443 -tlsextdebug 2>&1 | grep heartbeat`

---

### 3.4 TLS Testing Tools

**testssl.sh:**
```bash
# Full assessment with HTML report
testssl.sh --htmlfile report.html https://example.com

# Specific checks
testssl.sh --protocols example.com      # Protocol versions
testssl.sh --ciphers example.com        # Cipher suites
testssl.sh --pfs example.com            # Perfect forward secrecy
testssl.sh --heartbleed example.com     # Heartbleed check
testssl.sh --drown example.com          # DROWN check
testssl.sh --robot example.com          # ROBOT check
testssl.sh --crime example.com          # CRIME check
```

**sslyze:**
```bash
# Comprehensive scan
sslyze --regular example.com

# Specific plugins
sslyze --certinfo example.com           # Certificate details
sslyze --sslv2 --sslv3 example.com     # Legacy protocol check
sslyze --elliptic_curves example.com   # ECC curve support
sslyze --http_headers example.com      # Security headers
sslyze --json_out results.json example.com  # JSON output for automation
```

**Nmap SSL:**
```bash
# Enumerate cipher suites with strength rating
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for specific vulnerabilities
nmap --script ssl-heartbleed,ssl-poodle,ssl-dh-params -p 443 example.com

# Certificate information
nmap --script ssl-cert -p 443 example.com
```

**SSL Labs API:**
```bash
# Trigger assessment
curl "https://api.ssllabs.com/api/v3/analyze?host=example.com&startNew=on"
# Poll for results
curl "https://api.ssllabs.com/api/v3/analyze?host=example.com" | jq '.status,.grade'
```

---

### 3.5 Certificate Transparency

**CT Log Infrastructure:**
- All publicly trusted CAs must submit certificates to CT logs (since April 2018 — Chrome policy).
- Browser verifies SCT (Signed Certificate Timestamp) from log is embedded in certificate.
- Two+ SCTs from different logs required for EV certificates.

**Monitoring with certstream:**
```bash
# Real-time certificate stream
pip install certstream
certstream --full
# Python monitoring for phishing domains
import certstream
def callback(message, context):
    if message['message_type'] == 'certificate_update':
        domains = message['data']['leaf_cert']['all_domains']
        for domain in domains:
            if 'paypal' in domain.lower() or 'bank' in domain.lower():
                print(f"[!] Suspicious: {domain}")
certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
```

**CAA DNS Records:**
```bash
# Restrict which CAs can issue for your domain
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issuewild ";"          # No wildcard certs
example.com. CAA 0 iodef "mailto:security@example.com"

# Check CAA records
dig example.com CAA
```

**Certificate Pinning:**
- **HPKP** (HTTP Public Key Pinning): **Deprecated** — catastrophic misconfiguration risk (bricked sites).
- **Certificate Pinning in apps**: Mobile apps hard-code expected cert hash; bypassed by Frida/objection.
- **Expect-CT header**: Enforces CT log submission; `max-age=86400, enforce, report-uri="..."`.

**CT Log Search:**
```bash
# Search crt.sh for certificates
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq '.[].name_value' | sort -u
# Find phishing certs registered for similar domains
curl -s "https://crt.sh/?q=paypa1.com&output=json" | jq '.[].name_value'
```

---

### 3.6 TLS Inspection (SSL Inspection)

**Enterprise TLS Inspection:**
- Device performs MITM: decrypts outbound TLS, inspects, re-encrypts with corporate CA.
- **Privacy implications**: All employee TLS traffic visible to inspection device.
- **Legal considerations**: Employee notification required in many jurisdictions (GDPR, CCPA).
- **Security risk**: Inspection device becomes high-value target; forward secrecy broken for inspected sessions.

**Detection by endpoint:**
```bash
# Check certificate issuer — should be legitimate CA, not corporate proxy
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -issuer
# If issuer is "Corporate CA" or "Forcepoint" etc. — inspection in place
```

**Bypass techniques (attacker perspective):**
- SNI-based routing: inspection only on known categories.
- ESNI/ECH (Encrypted Client Hello, RFC 9145): hides SNI from middleboxes.
- Certificate pinning: apps reject re-signed proxy certificate.
- Non-standard ports: inspection often limited to well-known ports.

---

## 4. HTTP/HTTPS Security

### 4.1 HTTP Security Headers Reference

**HSTS (HTTP Strict Transport Security):**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- `max-age`: Duration (seconds) browser enforces HTTPS-only. 31536000 = 1 year.
- `includeSubDomains`: Applies to all subdomains.
- `preload`: Submit to browser preload list (hstspreload.org) — hardcoded in browser.
- **Risk**: Misconfiguration can lock out users for `max-age` duration.

**Content Security Policy (CSP):**
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}';
  img-src 'self' data: https:; style-src 'self' 'unsafe-inline';
  frame-ancestors 'none'; base-uri 'self'; form-action 'self';
  report-uri https://csp-report.example.com/collect
```

| Directive | Purpose | Secure Value |
|-----------|---------|-------------|
| `default-src` | Fallback for unspecified directives | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-xyz'` (avoid `unsafe-inline`) |
| `style-src` | CSS sources | `'self'` (avoid `unsafe-inline`) |
| `img-src` | Image sources | `'self' data: https:` |
| `frame-ancestors` | Who can frame this page | `'none'` or `'self'` |
| `base-uri` | Restricts `<base>` tag | `'self'` |
| `form-action` | Form submission targets | `'self'` |
| `upgrade-insecure-requests` | Auto-upgrade HTTP to HTTPS | Always include |
| `block-all-mixed-content` | Block HTTP in HTTPS page | Always include |

**Other Security Headers:**

| Header | Secure Value | Purpose |
|--------|-------------|---------|
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking protection (legacy; prefer CSP `frame-ancestors`) |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer header leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Restrict browser feature access |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolate browsing context (Spectre mitigation) |
| `Cross-Origin-Resource-Policy` | `same-origin` or `same-site` | Prevent cross-origin resource reads |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Required for `SharedArrayBuffer` (Spectre isolation) |
| `X-XSS-Protection` | `0` | **Disable** — modern browsers; legacy header caused vulnerabilities |

**Testing Headers:**
```bash
# Check all security headers
curl -sI https://example.com | grep -Ei "strict-transport|content-security|x-frame|x-content|referrer|permissions|cross-origin"
# Mozilla Observatory
curl "https://http-observatory.security.mozilla.org/api/v1/analyze?host=example.com" | jq '.grade,.score'
# securityheaders.com API
curl "https://securityheaders.com/?q=example.com&followRedirects=on" -I | grep -i "x-grade"
```

---

### 4.2 HTTP/2 Security

**HTTP/2 Features:**
- **Multiplexing**: Multiple requests over single TCP connection (eliminates head-of-line blocking).
- **HPACK**: Header compression (eliminates CRIME-equivalent risk via static/dynamic tables).
- **Server Push**: Server proactively sends resources (security: CSRF if server pushes sensitive data).
- **Binary framing**: Not human-readable; requires specialized tools.

**h2c (HTTP/2 cleartext):**
- HTTP/2 without TLS — upgrade via `Upgrade: h2c` header or prior knowledge.
- **Security risk**: No encryption; rarely used in production but enabled in some frameworks.
- Detection: `curl --http2 http://example.com -v 2>&1 | grep "Using HTTP2"`

**CVE-2023-44487 — HTTP/2 Rapid Reset:**
- Attacker sends HEADERS frame immediately followed by RST_STREAM frame, repeated at high rate.
- Server must process each request start before receiving reset — CPU exhaustion.
- Amplification: Attacker can open thousands of requests/second with minimal bandwidth.
- **Record DDoS**: 398 million requests/second (Cloudflare, August 2023).
- **Mitigation**: Rate-limit RST_STREAM frames; limit concurrent streams; patch web servers (nginx 1.25.3+, Apache 2.4.58+).

```nginx
# Nginx HTTP/2 RST mitigation
http2_max_concurrent_streams 128;
limit_req_zone $binary_remote_addr zone=http2:10m rate=100r/s;
```

---

### 4.3 HTTP/3 and QUIC Security

**QUIC Protocol:**
- UDP-based transport (port 443 UDP) — eliminates TCP handshake overhead.
- **Integrated TLS 1.3**: No separate handshake; QUIC packet headers authenticated.
- **Connection migration**: Client IP change doesn't break connection (mobile use case).
- **0-RTT**: Same replay risks as TLS 1.3 0-RTT (section 3.1).

**Security Considerations:**
- **Firewall traversal**: UDP 443 often less filtered than TCP 443; may bypass DPI.
- **TLS inspection**: Most current SSL inspection solutions cannot inspect QUIC.
- **Alt-Svc header**: Server advertises QUIC support — client may switch mid-session.
- **Amplification**: QUIC Initial packets have minimum 1200-byte requirement (anti-amplification).

**Blocking QUIC (enterprise):**
```bash
# iptables — block UDP 443 to force HTTP/2 fallback
iptables -A FORWARD -p udp --dport 443 -j DROP
# Chrome respects this and falls back to TCP/HTTP2
```

---

### 4.4 Cookie Security

**Cookie Security Attributes:**

| Attribute | Description | Security Impact |
|-----------|-------------|-----------------|
| `Secure` | Only sent over HTTPS | Prevents cookie theft over HTTP |
| `HttpOnly` | Not accessible via JavaScript | Prevents XSS cookie theft |
| `SameSite=Strict` | Never sent cross-site | Full CSRF protection |
| `SameSite=Lax` | Sent on top-level navigation only | Partial CSRF protection (default in modern browsers) |
| `SameSite=None; Secure` | Sent cross-site with TLS | Required for cross-site use cases |
| `Domain` | Scope of cookie | Omitting restricts to exact host (more secure) |
| `Path` | URL path scope | `/` means all paths |
| `Max-Age` / `Expires` | Session vs persistent | Session cookies cleared on browser close |

**Cookie Prefixes:**
- `__Host-`: Must be `Secure`, no `Domain`, `Path=/` — strongest binding to exact host.
- `__Secure-`: Must be `Secure` — prevents HTTP cookie setting.

```
Set-Cookie: __Host-SessionId=abc123; Secure; HttpOnly; SameSite=Strict; Path=/
Set-Cookie: __Secure-XSRF-TOKEN=xyz789; Secure; SameSite=Lax; Path=/
```

**Secure Cookie Example (all attributes):**
```
Set-Cookie: session=TOKEN; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

---

### 4.5 CORS Security

**CORS Headers:**

| Header | Direction | Description |
|--------|-----------|-------------|
| `Origin` | Request | Sender's origin |
| `Access-Control-Allow-Origin` | Response | Permitted origins (`*` or specific) |
| `Access-Control-Allow-Methods` | Response | Permitted HTTP methods |
| `Access-Control-Allow-Headers` | Response | Permitted request headers |
| `Access-Control-Allow-Credentials` | Response | Allow credentialed requests |
| `Access-Control-Expose-Headers` | Response | Headers exposed to JS |
| `Access-Control-Max-Age` | Response | Preflight cache duration |

**Credentialed vs Non-Credentialed:**
- Non-credentialed: `*` wildcard allowed for `Allow-Origin`; cookies not sent.
- Credentialed (`withCredentials: true`): `Allow-Origin` must be explicit (not `*`); `Allow-Credentials: true` required.

**CORS Misconfiguration Vulnerabilities:**
```
# Vulnerable — reflects Origin header blindly
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
# Attacker can read authenticated cross-origin responses

# Vulnerable — null origin
Access-Control-Allow-Origin: null
# Sandboxed iframes have null origin; allows cross-origin reads

# Checking CORS misconfiguration
curl -H "Origin: https://evil.com" -I https://api.example.com/sensitive
```

**Preflight (OPTIONS) Request:**
- Triggered by: non-simple methods (PUT, DELETE), custom headers, or `Content-Type: application/json`.
- Browser sends OPTIONS → server responds with allowed methods/headers → browser sends actual request.
- **Security bypass attempt**: Some CORS checks only on preflight, not actual request — ensure validation on both.

---

## 5. Authentication Protocols

### 5.1 Kerberos

**Kerberos Architecture:**
```
Client ──AS-REQ──→ KDC (AS)  ──AS-REP──→ Client (TGT)
Client ──TGS-REQ─→ KDC (TGS) ──TGS-REP─→ Client (Service Ticket)
Client ──AP-REQ──→ Service    (authenticates with service ticket)
```

**Message Types:**

| Message | Contains | Key Used |
|---------|---------|---------|
| AS-REQ | Username, nonce, timestamp | None (preauthentication with user's key) |
| AS-REP | TGT (encrypted with KDC key), session key (encrypted with user key) | User's password hash (NTLM) |
| TGS-REQ | TGT, authenticator, target SPN | KDC session key |
| TGS-REP | Service ticket (encrypted with service key), session key | KDC session key |

**Privilege Attribute Certificate (PAC):**
- Embedded in TGT and service tickets; contains group memberships, privileges.
- Service validates PAC — if service trusts PAC without KDC verification, Silver Ticket works.
- PAC validation: `KERB_VERIFY_PAC_REQUEST` to KDC (not all services implement).

**Kerberos Attacks:**

| Attack | Mechanism | Detection |
|--------|-----------|-----------|
| **Kerberoasting** | Request service tickets for SPNs; offline crack RC4-encrypted ticket | Unusual TGS-REQ for service accounts; 4769 events with ticket encryption type 0x17 (RC4) |
| **AS-REP Roasting** | Accounts with "do not require preauth" — AS-REP crackable offline | 4768 events with preauth type 0; unusual off-hours |
| **Pass-the-Ticket** | Import stolen TGT/TGS into session | 4768/4769 from unusual source IPs |
| **Golden Ticket** | Forge TGT using KRBTGT hash — unlimited validity | 4768 from non-DC; ticket lifetime > policy |
| **Silver Ticket** | Forge service ticket using service account hash | No TGS-REQ logged; 4624 on service without preceding Kerberos |
| **Overpass-the-Hash** | Convert NTLM hash to Kerberos TGT | 4768 with RC4 encryption from workstation |
| **Diamond Ticket** | Modify existing TGT fields (PAC) — stealthier than Golden | Event ID 4769 with anomalous PAC |

**Kerberoasting Commands:**
```bash
# Impacket
GetUserSPNs.py domain.local/user:password -outputfile hashes.kerberoast
# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt /rc4opsec    # RC4-only filter
# Crack with hashcat
hashcat -m 13100 hashes.kerberoast rockyou.txt
```

**Detection Queries (Windows Event Log):**
```
# Kerberoasting — Event ID 4769, Encryption Type 0x17
EventID=4769 AND TicketEncryptionType=0x17 AND ServiceName!=krbtgt AND ServiceName!=$*
# AS-REP Roasting — Event ID 4768, Preauth Type 0
EventID=4768 AND PreAuthType=0
# Golden Ticket — Event ID 4768 from non-DC
EventID=4768 AND SourceIPAddress NOT IN (dc_ips)
```

---

### 5.2 NTLM

**NTLM Authentication Flow:**
```
Client          Server          DC
  │─NEGOTIATE──→│               │
  │←CHALLENGE───│               │
  │─AUTHENTICATE→│               │
  │             │─NETLOGON-──→ │
  │             │←ACCESS-OK──── │
```

**Hash Types:**

| Type | Algorithm | Cracking Speed (GPU) | Vulnerability |
|------|-----------|---------------------|---------------|
| LM Hash | DES, 7-char split, uppercase | >1T/s (trivially fast) | Deprecated, disabled by default since Vista |
| **NTLMv1** | MD4(password) used in HMAC-MD5 | ~100B/s | Crackable; no server nonce verification |
| **NTLMv2** | HMAC-MD5 with client+server nonce | ~5B/s | Current standard; still crackable offline |

**NTLM Relay Attacks:**
1. **LLMNR/NBT-NS Poisoning** (Responder): Client broadcasts name resolution; attacker responds → client sends NTLM creds to attacker.
2. Attacker relays creds to target server (not cracking hash — live relay).
3. No cracking needed — relay authentication to access resources.

```bash
# Responder — LLMNR/NBT-NS/mDNS poisoning
responder -I eth0 -dwv
# ntlmrelayx — relay to SMB/LDAP/HTTP targets
ntlmrelayx.py -tf targets.txt -smb2support
# Combine: Responder poisons, ntlmrelayx relays
```

**SMB Signing Mitigation:**
```
# Enforce SMB signing (prevents relay attacks)
# Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# PowerShell check
Get-SmbServerConfiguration | Select RequireSecuritySignature
# Should be True
```

**Disable LLMNR/NBT-NS:**
```
# Group Policy
Computer Configuration → Administrative Templates → Network → DNS Client
"Turn off multicast name resolution" = Enabled
# Registry — NBT-NS
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\[Interface]
NetbiosOptions = 2  (disabled)
```

---

### 5.3 OAuth 2.0

**Grant Types — Security Comparison:**

| Grant Type | Use Case | Security Rating | Notes |
|-----------|---------|----------------|-------|
| **Authorization Code + PKCE** | Web/mobile apps | Recommended | PKCE replaces client secret for public clients |
| Authorization Code (no PKCE) | Server-side web | Acceptable | Requires client secret |
| **Implicit** | SPA (legacy) | **Deprecated** | Tokens in URL fragment; no refresh token |
| Client Credentials | M2M/service accounts | Acceptable | No user involved |
| Resource Owner Password | Legacy migration | **Avoid** | App receives user credentials |
| **Device Code** | Smart TV/CLI | Acceptable | Polling-based; short-lived codes |

**PKCE (Proof Key for Code Exchange — RFC 7636):**
```
code_verifier  = random_string(43-128 chars)
code_challenge = BASE64URL(SHA256(code_verifier))

# Authorization request includes:
&code_challenge=xxx&code_challenge_method=S256

# Token request includes:
&code_verifier=xxx   (server verifies SHA256 matches challenge)
```
Prevents authorization code interception attacks in mobile apps.

**Common OAuth Vulnerabilities:**
- **State parameter missing**: CSRF against authorization flow.
- **Open redirect in redirect_uri**: Steal authorization code.
- **Token leakage in referrer**: Access token in URL fragment visible in logs.
- **Insufficient redirect_uri validation**: `example.com.evil.com` matches `example.com`.
- **Mix-up attacks**: Multiple IdPs — client confused about which token came from which server.

---

### 5.4 OpenID Connect (OIDC)

**OIDC vs OAuth 2.0:**
- OAuth 2.0: Authorization (access to resources).
- OIDC: Authentication (identity verification) built on OAuth 2.0.
- **ID Token**: JWT containing user identity claims (sub, iss, aud, exp, iat, nonce).

**ID Token Validation (MUST verify all):**
```python
import jwt
decoded = jwt.decode(
    id_token,
    jwks_client.get_signing_key_from_jwt(id_token).key,
    algorithms=["RS256"],
    audience=CLIENT_ID,          # aud must match client_id
    issuer=f"https://{IDP}/"    # iss must match expected IdP
)
# Additional checks:
assert decoded['nonce'] == session_nonce    # Prevent replay
assert decoded['exp'] > time.time()         # Not expired
assert decoded['iat'] > time.time() - 300   # Not future-issued
```

**Discovery Document:**
```bash
curl https://accounts.google.com/.well-known/openid-configuration | jq '.jwks_uri,.token_endpoint,.userinfo_endpoint'
```

**UserInfo Endpoint:**
```bash
curl -H "Authorization: Bearer {access_token}" https://idp.example.com/userinfo
# Returns additional claims: email, name, picture, etc.
```

---

### 5.5 SAML 2.0

**SAML Flow (SP-Initiated):**
```
User → SP (AuthnRequest) → IdP (login) → SP (SAMLResponse with Assertion)
```

**SAML Security Vulnerabilities:**

| Vulnerability | Description | Mitigation |
|--------------|-------------|-----------|
| **XML Signature Wrapping (XSW)** | Add unsigned XML nodes that change assertion meaning | Validate signature AFTER reference resolution |
| **Assertion Replay** | Reuse captured SAML assertion | Check `NotOnOrAfter`, `InResponseTo`, assertion ID cache |
| **Signature Validation Bypass** | Library ignores signature if not present | Require signed assertions; reject unsigned |
| **SAML Attribute Injection** | Malicious values in attributes (XML special chars) | Strict XML parsing; parameterized attribute handling |
| **Open Redirect in RelayState** | `RelayState` redirects to external URL after auth | Validate `RelayState` against allowed URLs |

**Testing SAML:**
```bash
# Decode SAML response (base64 encoded)
echo "${SAML_RESPONSE}" | base64 -d | xmllint --format -
# SAML testing tools
# SAML Raider (Burp Suite extension)
# SAMLExtractor
# xml-security-java tests
```

---

## 6. Network Management Protocols

### 6.1 SNMP

**Version Comparison:**

| Feature | SNMPv1 | SNMPv2c | SNMPv3 |
|---------|--------|---------|--------|
| Authentication | Community string (plaintext) | Community string (plaintext) | HMAC-MD5/SHA |
| Encryption | None | None | DES/AES |
| Message integrity | None | None | HMAC |
| Access control | Community-based | Community-based | USM + VACM |
| Security rating | **Insecure** | **Insecure** | Acceptable |

**Community String Attacks:**
```bash
# Brute-force community strings
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.0/24
# Walk MIB with known community
snmpwalk -v2c -c public 192.168.1.1
snmpwalk -v2c -c private 192.168.1.1 .1.3.6.1.4.1    # Vendor OIDs
# Get specific OID (system description)
snmpget -v2c -c public 192.168.1.1 .1.3.6.1.2.1.1.1.0
# SNMP enumeration with nmap
nmap -sU -p 161 --script snmp-info,snmp-interfaces,snmp-netstat 192.168.1.0/24
```

**SNMPv3 Configuration (Cisco IOS):**
```
! Create SNMPv3 user with AES-128 encryption
snmp-server group SECURE-GROUP v3 priv
snmp-server user MONITOR SECURE-GROUP v3 auth sha AuthPassword priv aes 128 PrivPassword
! Restrict access to management VLAN
snmp-server community DISABLED RO 99    ! Disable v1/v2c
no snmp-server community public
no snmp-server community private
```

**Hardening Checklist:**
- [ ] Disable SNMPv1 and SNMPv2c
- [ ] Use SNMPv3 with authPriv security level
- [ ] Restrict SNMP access via ACL to management IPs only
- [ ] Change default community strings (public/private)
- [ ] Monitor for SNMP brute-force (event 5777/5778 on some platforms)
- [ ] Use read-only community for monitoring (no write access)

---

### 6.2 SSH Security

**SSH-2 Key Exchange (simplified):**
```
Client                    Server
  │──SSH_MSG_KEXINIT──→  │  (algorithm negotiation)
  │←─SSH_MSG_KEXINIT──  │
  │──SSH_MSG_KEXDH_INIT→ │  (client DH public key)
  │←─SSH_MSG_KEXDH_REPLY─│  (server DH public key + host key signature)
  │ (verify host key fingerprint)
  │──SSH_MSG_NEWKEYS──→  │  (switch to new keys)
  │←─SSH_MSG_NEWKEYS──── │
  │──SSH_MSG_USERAUTH─→  │  (password/pubkey auth)
```

**Host Key Verification:**
```bash
# TOFU (Trust On First Use) — default behavior
# First connection: "The authenticity of host can't be established. fingerprint is SHA256:xxxx. Are you sure?"
# Saved to ~/.ssh/known_hosts

# CA-signed host keys (recommended for enterprise)
# Sign server host key with CA
ssh-keygen -s /etc/ssh/ssh_ca -I "server-hostname" -h -n "server.example.com" /etc/ssh/ssh_host_rsa_key.pub
# Client trusts CA instead of individual fingerprints
# ~/.ssh/known_hosts or /etc/ssh/known_hosts:
@cert-authority *.example.com ssh-rsa AAAAB3NzaC1yc2E... (CA public key)
```

**SSH Certificate Authority:**
```bash
# Create CA key pair
ssh-keygen -t ed25519 -f ssh_user_ca -C "SSH User CA"
# Sign user public key (valid 1 day, for user "alice", principal "admin")
ssh-keygen -s ssh_user_ca -I "alice@example.com" -n admin,alice -V +1d ~/.ssh/id_ed25519.pub
# Configure server to accept CA-signed certs
echo "TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub" >> /etc/ssh/sshd_config
```

**ssh-audit Assessment:**
```bash
# Assess SSH server configuration
ssh-audit server.example.com
# Check key exchange algorithms, host key types, MACs, ciphers
# Flag deprecated: diffie-hellman-group1-sha1, arcfour, hmac-md5
```

**Secure sshd_config:**
```
Protocol 2
PermitRootLogin no
PasswordAuthentication no          # Key-based only
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no              # Disable port forwarding if not needed
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers admin ops-team
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
```

**ProxyJump / Bastion:**
```bash
# Jump through bastion host
ssh -J bastion.example.com internal-server.lan
# ~/.ssh/config
Host internal-*
    ProxyJump bastion.example.com
    User admin
    IdentityFile ~/.ssh/id_ed25519
```

---

### 6.3 NetFlow/IPFIX Analysis

**Flow Record Fields:**

| Field | Security Use |
|-------|-------------|
| src/dst IP | Traffic baseline; detect lateral movement |
| src/dst Port | Service identification; anomalous ports |
| Protocol | Protocol distribution; covert channels |
| Bytes/Packets | Exfiltration detection; volume anomalies |
| Start/End Time | Duration; long-lived connections |
| TCP Flags | SYN floods, scanners |
| Input/Output IF | Traffic direction; ingress/egress |
| Next-Hop IP | Routing changes |
| ToS/DSCP | QoS manipulation; covert channels |
| BGP AS | Route-based attribution |

**nfdump Analysis:**
```bash
# Top 10 talkers by bytes
nfdump -R /data/netflow/2024/01/01 -n 10 -s record/bytes

# Find beaconing — regular connections to same destination
nfdump -R /data -A srcip,dstip,dstport -o "fmt:%ts %td %sa %da %dp %byt" 'proto tcp and bytes > 0'

# Detect port scanning (high unique destination ports from single source)
nfdump -R /data -A srcip -a -o "fmt:%sa %pkt %fl" 'flags S and not flags AFPU' | sort -k3 -rn | head 20

# Long duration connections (potential C2 beaconing or exfil)
nfdump -R /data 'duration > 3600 and proto tcp' -o "fmt:%ts %td %sa %da %dp %byt"

# Unusual protocols (not TCP/UDP/ICMP)
nfdump -R /data 'proto not in [6,17,1]' -o "fmt:%ts %pr %sa %da %byt"
```

**SiLK (System for Internet-Level Knowledge):**
```bash
# Find hosts communicating on non-standard ports
rwfilter --proto=6 --dport=0-1024 --pass=stdout | rwuniq --fields=dip,dport --values=bytes | sort -k3 -rn

# Detect beaconing (regular flow intervals)
rwfilter --saddress=192.168.1.100 --pass=stdout | rwcount --bin-size=300 | head 20
```

**Beaconing Detection:**
- Look for flows at regular intervals (±small jitter) to same C2 IP.
- Beacon period commonly: 60s, 300s, 600s (configurable in malware).
- Use Fourier transform / autocorrelation on flow timestamps.

---

### 6.4 LDAP/LDAPS Security

**LDAP Bind Types:**

| Bind Type | Security | Description |
|-----------|---------|-------------|
| Simple bind (cleartext) | **Insecure** | Password sent in plaintext |
| Simple bind over TLS (LDAPS:636) | Acceptable | Encrypted |
| Simple bind with STARTTLS | Acceptable | Upgraded to TLS |
| SASL GSSAPI (Kerberos) | Recommended | Kerberos ticket for AD |
| SASL DIGEST-MD5 | Deprecated | MD5 weakness |
| **Anonymous bind** | **Risk** | No authentication — information disclosure |

**Anonymous Bind Risk:**
```bash
# Test anonymous bind
ldapsearch -x -H ldap://192.168.1.10 -b "dc=example,dc=com" "(objectclass=*)"
# If results returned without credentials — anonymous bind enabled
# Microsoft AD: anonymous bind allowed but limited by default
```

**LDAP Enumeration:**
```bash
# Enumerate AD users
ldapsearch -x -H ldap://dc.example.com -D "user@example.com" -w password   -b "dc=example,dc=com" "(&(objectClass=user)(objectCategory=person))"   sAMAccountName userPrincipalName memberOf

# Find accounts with SPN (Kerberoast targets)
ldapsearch -x -H ldap://dc.example.com -D "user@example.com" -w password   -b "dc=example,dc=com" "(&(objectCategory=user)(servicePrincipalName=*))"   sAMAccountName servicePrincipalName

# Enumerate groups
ldapsearch -x -H ldap://dc.example.com -D "user@example.com" -w password   -b "dc=example,dc=com" "(objectClass=group)" cn member

# AD password policy
ldapsearch -x -H ldap://dc.example.com -D "user@example.com" -w password   -b "dc=example,dc=com" "(objectClass=domainDNS)" minPwdLength lockoutThreshold
```

**LDAP Injection:**
```
# Malicious input in search filter
username: *)(uid=*))(|(uid=*
# Resulting filter: (&(uid=*)(uid=*))(|(uid=*)(password=secret))
# Bypass authentication if application constructs filter from user input

# Mitigations:
# - Input validation: reject LDAP special characters: * ( ) \ NUL
# - Parameterized LDAP queries (if library supports)
# - Principle of least privilege for service account
```

---

## 7. Routing & Switching Security

### 7.1 BGP Security

**BGP Hijacking:**
1. Attacker AS announces more-specific prefix (longer /prefix length wins).
2. Or announces prefix with crafted AS path to appear closer.
3. Traffic reroutes through attacker AS — eavesdrop or blackhole.

**Notable BGP Incidents:**
- **2008 Pakistan Telecom**: Hijacked YouTube's prefix → global outage.
- **2010 China Telecom**: ~15% of Internet routes leaked for 18 minutes.
- **2018 MyEtherWallet**: BGP hijack of AWS DNS → cryptocurrency theft.

**RPKI (Resource Public Key Infrastructure):**
```bash
# ROA (Route Origin Authorization) — what you create as prefix owner
# Specifies: prefix, maximum prefix length, authorized origin AS

# Check ROA existence for a prefix
curl https://rpki-validator.ripe.net/api/v1/validity/AS15169/8.8.8.0/24

# Validate BGP announcement against RPKI
# On Cisco IOS XR:
router bgp 65001
 address-family ipv4 unicast
  bgp origin-as validation signal ibgp

# On bird2:
protocol rpki rpki_server {
    roa4 { table master4; };
    remote "rpki.example.com" port 3323;
}
```

**MANRS (Mutually Agreed Norms for Routing Security):**
Four actions: Filtering, Anti-Spoofing, Coordination, Global Validation (RPKI).

---

### 7.2 OSPF Authentication

**Authentication Types:**

| Type | Security | Configuration |
|------|---------|---------------|
| Type 0 (None) | No security | Default — insecure |
| Type 1 (Plaintext) | Password visible in packet | Legacy only |
| **Type 2 (MD5)** | HMAC-MD5 with key ID | Acceptable |
| **SHA-256** (OSPFv3) | SHA-256 | Recommended |

**Cisco IOS OSPF MD5 Authentication:**
```
! Interface-level MD5 authentication
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 StrongPassword123!
 ip ospf authentication message-digest

! Or area-level (all interfaces in area)
router ospf 1
 area 0 authentication message-digest

! Passive interfaces (no OSPF peers — suppress Hello packets)
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/0    ! Only active on uplinks
```

**OSPF Attack Surface:**
- **Rogue router**: Inject fake LSAs if authentication absent → route poisoning.
- **Hello flooding**: Exhaust neighbor table.
- **LSA flooding**: Consume CPU/memory with malformed LSAs.
- **Maxage flushing**: Prematurely age out valid routes.

---

### 7.3 Spanning Tree Security

**STP Attack — Yersinia:**
```bash
# Send crafted BPDU to become root bridge
yersinia stp -attack 1    # Claiming root role
# Impact: Traffic reroutes through attacker device — MITM
```

**BPDU Guard:**
```
! Enable BPDU Guard on access ports (no switches expected)
interface range GigabitEthernet0/1-24
 spanning-tree portfast
 spanning-tree bpduguard enable

! Global PortFast default with BPDU Guard
spanning-tree portfast default
spanning-tree portfast bpduguard default
! Port disabled (err-disabled) if BPDU received
```

**Root Guard:**
```
! Prevent port from accepting superior BPDUs (block unauthorized root)
interface GigabitEthernet0/1
 spanning-tree guard root
! Port transitions to root-inconsistent state if superior BPDU received
```

**Loop Guard:**
```
! Prevent loops from unidirectional link failures
spanning-tree loopguard default
! Port transitions to loop-inconsistent if BPDUs stop
```

---

### 7.4 VLAN Hopping

**Attack 1 — Switch Spoofing:**
1. Attacker sends DTP (Dynamic Trunking Protocol) frames.
2. Switch negotiates trunk link with attacker.
3. Attacker receives all VLAN traffic.

**Mitigation — Disable DTP:**
```
! Disable DTP negotiation on access ports
interface GigabitEthernet0/1
 switchport mode access
 switchport nonegotiate
 switchport access vlan 10
```

**Attack 2 — Double Tagging:**
1. Attacker adds two 802.1Q tags: outer = native VLAN, inner = target VLAN.
2. Switch strips outer tag (native VLAN = no tag processing).
3. Frame forwarded to target VLAN.
4. **Note**: One-directional only — response doesn't route back.

**Native VLAN Hardening:**
```
! Change native VLAN to unused VLAN ID (not VLAN 1, not any user VLAN)
interface GigabitEthernet0/24
 switchport trunk native vlan 999    ! Dedicated unused VLAN
 switchport trunk allowed vlan 10,20,30    ! Explicit allow list
 switchport nonegotiate

! Or tag native VLAN on trunk (dot1q native VLAN tagging)
vlan dot1q tag native    ! Global command — Cisco
```

**Additional VLAN Hardening:**
```
! Disable unused ports
interface range GigabitEthernet0/5-24
 shutdown
 switchport mode access
 switchport access vlan 999    ! Unused VLAN

! Remove VLAN 1 from trunks
interface GigabitEthernet0/24
 switchport trunk allowed vlan remove 1
```

---

### 7.5 ARP Spoofing and Dynamic ARP Inspection

**ARP Spoofing Attack:**
1. Attacker sends gratuitous ARP: "192.168.1.1 is at AA:BB:CC:DD:EE:FF" (attacker MAC).
2. Victims update ARP cache.
3. Traffic for gateway sent to attacker → MITM.

**Detection:**
```bash
# ARPwatch — detect ARP cache changes
arpwatch -i eth0 -f /var/lib/arpwatch/arp.dat
# Alert on new/changed MAC-IP pairs

# Manual check
arp -a    # View ARP cache
# Look for duplicate MAC addresses serving different IPs
arp -a | awk '{print $4}' | sort | uniq -c | sort -rn | head
```

**Dynamic ARP Inspection (DAI) — Cisco:**
```
! Enable DHCP snooping first (provides binding table)
ip dhcp snooping
ip dhcp snooping vlan 10,20

! Enable DAI
ip arp inspection vlan 10,20

! Trust uplink ports (DHCP server, router)
interface GigabitEthernet0/24
 ip arp inspection trust
 ip dhcp snooping trust

! Rate limit ARP on access ports (prevent ARP flooding)
interface range GigabitEthernet0/1-23
 ip arp inspection limit rate 100

! Verify
show ip arp inspection vlan 10
show ip arp inspection statistics
```

---

### 7.6 DHCP Attacks and Snooping

**DHCP Starvation Attack:**
```bash
# Exhaust DHCP pool with fake MAC requests
# Tool: dhcpstarv, yersinia
yersinia dhcp -attack 1    # DHCP starvation
# Then deploy rogue DHCP server
```

**Rogue DHCP Attack:**
- Attacker deploys rogue DHCP server.
- Victims receive attacker's DNS, default gateway.
- Result: Traffic redirection, DNS hijacking.

**DHCP Snooping — Cisco:**
```
! Enable globally and per VLAN
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
no ip dhcp snooping information option    ! Option 82 — remove if causing issues

! Trust ONLY uplink ports (legitimate DHCP server)
interface GigabitEthernet0/24    ! Uplink
 ip dhcp snooping trust

! Access ports — untrusted (rate limit DHCP messages)
interface range GigabitEthernet0/1-23
 ip dhcp snooping limit rate 15    ! 15 DHCP packets/second max

! Verify binding table
show ip dhcp snooping binding
! MAC Address    IP Address    Lease    Type        VLAN    Interface
! 00:11:22:33    10.0.0.100    86400    dynamic     10      Gi0/1
```

---

## 8. Email Protocol Security

### 8.1 SMTP Security — SPF, DKIM, DMARC

**SMTP Security Progression:**
```
SMTP (RFC 821, 1982) → ESMTP → STARTTLS → SPF → DKIM → DMARC
```

**STARTTLS:**
```bash
# Test STARTTLS support
openssl s_client -starttls smtp -connect mail.example.com:25
# Verify STARTTLS is advertised (look for STARTTLS in EHLO response)
telnet mail.example.com 25
EHLO test.com    # Should list STARTTLS in capabilities
```

**SPF (Sender Policy Framework) — TXT Record:**
```
v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/24 include:_spf.google.com include:mailchimp.com -all

Mechanisms:
  ip4/ip6    Direct IP authorization
  include    Delegate to another domain's SPF
  a          Domain's A/AAAA records
  mx         Domain's MX records
  ptr        Reverse DNS (deprecated — avoid)
  exists     Custom logic

Qualifiers:
  +all       Pass (default — insecure)
  ~all       Softfail (mark as suspicious but accept)
  -all       Fail (reject) — recommended
  ?all       Neutral

# SPF lookup limit: 10 DNS lookups max (includes includes, redirects)
# Exceed 10 → SPF PermError (treated as fail by some receivers)
```

**DKIM (DomainKeys Identified Mail):**
```
# DNS TXT record at selector._domainkey.example.com
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...

# Key generation (OpenSSL)
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem

# Test DKIM signature
dig TXT mail._domainkey.example.com
# Verify signed email header
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=mail header.b=ABC123def;
```

**DMARC:**
```
# DNS TXT record at _dmarc.example.com
v=DMARC1; p=reject; rua=mailto:dmarc-agg@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100; sp=reject; adkim=s; aspf=s

Parameters:
  p=none        Monitor only (no action)
  p=quarantine  Send to spam folder
  p=reject      Reject at MTA level
  rua           Aggregate report recipients (daily XML summary)
  ruf           Forensic report recipients (per-failure copy)
  pct           Percentage of messages to apply policy (100 = all)
  sp            Subdomain policy
  adkim=s       DKIM strict (header.d must match From)
  adkim=r       DKIM relaxed (organizational domain match)
  aspf=s        SPF strict
  aspf=r        SPF relaxed

# Enforcement progression
p=none → p=quarantine (pct=10) → p=quarantine (pct=100) → p=reject
```

**DMARC Report Analysis:**
```bash
# Tools: dmarcian, Google Postmaster Tools, Valimail
# Decompress aggregate reports
unzip dmarc_report.zip
gunzip dmarc_report.xml.gz
# Parse XML
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('dmarc_report.xml')
root = tree.getroot()
for record in root.findall('.//record'):
    source_ip = record.find('.//source_ip').text
    count = record.find('.//count').text
    dkim = record.find('.//dkim').text
    spf = record.find('.//spf').text
    print(f'{source_ip}: {count} messages, DKIM={dkim}, SPF={spf}')
"
```

---

### 8.2 Email Security Gateways

**Platform Comparison:**

| Platform | Detection Method | Key Features |
|----------|-----------------|--------------|
| **Proofpoint TAP** | Static+behavioral | Click-time URL rewrite, TAP dashboard, CLEAR |
| **Mimecast** | Targeted threat protection | URL Protection, Attachment Protection, Impersonation |
| **Microsoft Defender for O365** | ML + heuristics | Safe Links, Safe Attachments, Spoof Intelligence |
| **Cisco ESA (Email Security Appliance)** | IronPort SenderBase | AsyncOS, AMP integration, Graymail detection |
| **Barracuda ESS** | Cloud-based | Outbound scanning, DLP, encryption |

**Proofpoint TAP Integration:**
```bash
# Query Proofpoint SIEM API
curl -u "user:password" "https://tap-api-v2.proofpoint.com/v2/siem/all?sinceSeconds=3600&format=json"   | jq '.messagesBlocked[].messageID,.threatsInfoMap[].threatURL'
```

---

### 8.3 Email Header Forensics

**Received Header Chain (trace from bottom to top):**
```
Received: from mail.attacker.com (mail.attacker.com [1.2.3.4])
        by mx.example.com with ESMTP id abc123;
        Wed, 1 Jan 2025 10:00:00 +0000
Received: from [192.168.1.100] (malware.internal [192.168.1.100])
        by mail.attacker.com with SMTP id xyz789;
        Wed, 1 Jan 2025 09:59:55 +0000
```
- Read bottom-to-top: earliest hop at bottom.
- First trusted `Received` header: first one added by YOUR receiving MTA.
- Everything above first trusted hop could be forged.

**Key Headers for Forensics:**

| Header | Purpose | Forgery Risk |
|--------|---------|-------------|
| `From` | Display sender — easily forged | High |
| `Return-Path` | Envelope sender (SPF checks this) | Moderate |
| `Reply-To` | Hijack replies | High |
| `Message-ID` | Unique identifier — format leaks MUA | Low |
| `X-Originating-IP` | Client IP (webmail systems) | Medium |
| `X-Mailer` / `User-Agent` | Email client identification | Medium |
| `Authentication-Results` | SPF/DKIM/DMARC results (added by receiver) | Low (receiver-added) |
| `DKIM-Signature` | Cryptographic signature | Verifiable |
| `Received-SPF` | SPF evaluation result | Low (receiver-added) |

**Authentication-Results Analysis:**
```
Authentication-Results: mx.google.com;
       dkim=fail (signature did not verify) header.i=@example.com;
       spf=pass (google.com: domain of sender@legit.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=sender@legit.com;
       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE) header.from=example.com

# DMARC fail despite SPF pass = From domain ≠ SPF envelope domain (common phishing pattern)
```

---

### 8.4 Phishing Infrastructure Detection

**dnstwist — Typosquatting Detection:**
```bash
# Generate typosquatted domains and check registration
dnstwist --registered example.com
dnstwist --format csv example.com > typosquats.csv
# Flags: homoglyphs (rn→m), bitsquatting, hyphenation, transpositions
```

**Certificate Transparency for Phishing Detection:**
```bash
# Monitor crt.sh for similar domains
curl -s "https://crt.sh/?q=%25example.com&output=json" |   jq -r '.[].name_value' |   grep -v "^example.com$" | sort -u

# certstream monitoring (see section 3.5)
```

**urlscan.io:**
```bash
# Scan suspicious URL
curl -X POST "https://urlscan.io/api/v1/scan/"   -H "API-Key: $URLSCAN_KEY"   -H "Content-Type: application/json"   -d '{"url": "http://suspicious.example.com", "visibility": "private"}'
# Retrieve results
curl "https://urlscan.io/api/v1/result/{uuid}/" | jq '.verdicts.overall.malicious'
```

---

### 8.5 Modern Authentication for Email Clients

**Replacing Basic Auth:**
- Microsoft: Basic Auth for Exchange Online **deprecated** October 2022.
- Modern auth = OAuth 2.0 tokens via MSAL (Microsoft Authentication Library).
- **POP3S**: TCP 995 — TLS-wrapped POP3.
- **IMAPS**: TCP 993 — TLS-wrapped IMAP.
- **SMTPS (Submission)**: TCP 587 (STARTTLS) or 465 (implicit TLS).

**Certificate-Based Authentication for Email:**
```bash
# S/MIME: signing + encryption using X.509 certificates
# - Sign: proves sender identity (non-repudiation)
# - Encrypt: only recipient with private key can decrypt
# Verify S/MIME signature
openssl smime -verify -in signed_email.eml -CAfile ca_bundle.pem
```

---

## 9. Industrial & Specialized Protocols

### 9.1 OT/ICS Protocols

**Modbus TCP (Port 502):**
- **No authentication, no encryption** — designed for isolated networks.
- Attacker can read/write coils (discrete outputs), holding registers, input registers, discrete inputs.
- Function codes: 01 (Read Coils), 03 (Read Holding Registers), 06 (Write Single Register), 15/16 (Write Multiple).

```bash
# Nmap Modbus enumeration
nmap -sV -p 502 --script modbus-discover 192.168.1.0/24
nmap -p 502 --script modbus-enum 192.168.1.100

# Modbusclient (pymodbus) — read registers
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('192.168.1.100')
c.connect()
result = c.read_holding_registers(0, count=10, slave=1)
print(result.registers)
c.close()
"

# Shodan search for internet-exposed Modbus
# shodan search 'port:502 Modbus'
# shodan search 'port:102 S7'     # Siemens S7 protocol
```

**DNP3 (Distributed Network Protocol 3):**
- Commonly used in electric utilities, water/wastewater.
- **SAv5 (Secure Authentication version 5)**: Challenge-response authentication added in 2012.
- Without SAv5: spoofed control messages can trip breakers, open valves.
- Port: TCP/UDP 20000.

**IEC 61850:**
- Power systems automation standard.
- **GOOSE** (Generic Object-Oriented Substation Event): UDP multicast, no authentication — replay attacks possible.
- **MMS** (Manufacturing Message Specification): Application layer, optional TLS.
- **SV** (Sampled Values): High-speed protection functions — unauthenticated.

**PROFINET DCP:**
- **DCP flooding**: Broadcast discovery frames exhaust PROFINET device processing capacity — DoS.
- Mitigation: Storm control on switches, segment OT networks from IT.

**EtherNet/IP (Common Industrial Protocol — CIP):**
- TCP 44818 (explicit messaging), UDP 2222 (implicit/I/O messaging).
- No native encryption or authentication.
- CIP Safety: deterministic response timing for safety-rated networks.

**OT Security Monitoring Platforms:**

| Platform | Focus | Key Capabilities |
|----------|-------|-----------------|
| **Claroty** | OT/IoT | Protocol deep inspection, CVE correlation |
| **Nozomi Networks** | OT/IoT/ICS | AI anomaly detection, Guardian sensor |
| **Dragos** | ICS-specific | Threat intelligence, playbooks |
| **Tenable OT (ex-Indegy)** | Active+passive | Asset inventory, vulnerability assessment |
| **Microsoft Defender for IoT** | OT/IoT | Azure integration, formerly CyberX |

**Shodan Industrial Searches:**
```
port:502 Modbus           # Exposed Modbus
port:102 S7               # Siemens S7
port:44818 EtherNet/IP    # Allen-Bradley
port:20000 DNP3           # Utility DNP3
port:4840 OPC-UA          # Modern ICS API
port:9600 OMRON           # Omron PLCs
country:US port:502       # US-based Modbus
```

---

### 9.2 Medical Protocols

**HL7 (Health Level Seven):**
- HL7 v2: Pipe-delimited text messages; no native encryption.
- HL7 v3/FHIR: RESTful API with OAuth 2.0 (RFC 8693).
- **FHIR OAuth 2.0**: SMART on FHIR — authorization code flow with specific scopes (`patient/*.read`).
- PHI exposure risk: HL7 messages contain PII/PHI — must be encrypted in transit.

**DICOM (Digital Imaging and Communications in Medicine):**
- Legacy: No authentication, no encryption — common in legacy PACS systems.
- **FDA guidance**: Segment DICOM networks; use TLS-capable DICOM implementations.
- Shodan exposed DICOM: `port:11112 DICOM` — thousands of internet-exposed systems.
- DICOM PS3.15: Security profiles including TLS and digital signatures.

**Medical Device Network Segmentation:**
```
[Internet] → [Firewall] → [Clinical VLAN] → [Medical Device VLAN (isolated)]
                                          → [PACS/EMR VLAN]
                                          → [Administrative VLAN]
```
- Medical devices often cannot be patched (FDA cleared = locked version).
- Compensating controls: network isolation, application-layer gateways, anomaly monitoring.

---

### 9.3 VoIP Security

**SIP Protocol Security:**

| Attack | Tool | Description |
|--------|------|-------------|
| **SIP Enumeration** | `sipvicious svmap` | Discover SIP servers |
| **Extension Enumeration** | `sipvicious svwar` | Enumerate valid extensions (200 OK vs 404) |
| **Password Brute-force** | `sipvicious svcrack` | Crack SIP digest auth |
| **REGISTER flood** | `inviteflood` | DoS via registration flood |
| **INVITE flood** | `inviteflood` | DoS via call attempt flood |
| **Toll fraud** | Manual | Compromise PBX → international calls |
| **Eavesdropping** | `rtpbreak` | Capture unencrypted RTP streams |

```bash
# SIPVicious enumeration
svmap 192.168.1.0/24                    # Discover SIP servers
svwar -e100-200 192.168.1.10            # Enumerate extensions
svcrack -u 100 -d wordlist.txt 192.168.1.10   # Crack extension password

# Capture RTP (VoIP audio)
tshark -i eth0 -f 'udp portrange 10000-20000' -w voip_capture.pcap
# Decode in Wireshark: Telephony → RTP → Stream Analysis
```

**SRTP (Secure RTP):**
```
# SDP negotiation with SRTP
m=audio 49172 RTP/SAVP 0 8             # SAVP = Secure Audio-Video Profile
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj
# Key exchange via ZRTP (RFC 6189) or SDES (SDP Security Descriptions)
```

**PBX Security Hardening:**
- Restrict outbound calling to required countries only.
- Monitor for after-hours international calls.
- Rate-limit concurrent calls and call duration.
- Disable direct inward dial (DID) to voicemail without authentication.
- Regular audit of SIP credentials (change from defaults).

---

### 9.4 MQTT (IoT)

**MQTT Security Issues:**
- Default: No authentication, no encryption (TCP 1883).
- Unauthenticated brokers exposed on internet: industrial control, building automation, personal devices.
- Wildcard subscriptions: `#` subscribes to ALL topics on broker.

**Exposed MQTT on Shodan:**
```
# shodan search 'port:1883 MQTT'
# shodan search 'product:mosquitto'
```

**Accessing Unsecured Broker:**
```bash
# Connect and subscribe to all topics (attacker perspective)
mosquitto_sub -h vulnerable-broker.example.com -t '#' -v
# Publish malicious command
mosquitto_pub -h vulnerable-broker.example.com -t 'device/switch1/cmd' -m 'ON'
```

**Secure MQTT Configuration (Mosquitto):**
```ini
# /etc/mosquitto/mosquitto.conf
listener 8883          # TLS port
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
require_certificate true    # Mutual TLS

# Or password file authentication
password_file /etc/mosquitto/passwd
allow_anonymous false

# ACL — restrict topic access
acl_file /etc/mosquitto/acl
# acl file contents:
# user device-001
# topic readwrite devices/001/#
# topic read broadcast/#
```

**MQTT Security Checklist:**
- [ ] Disable anonymous connections (`allow_anonymous false`)
- [ ] Enable TLS on port 8883
- [ ] Use mutual TLS (client certificates) for device authentication
- [ ] Implement topic-level ACLs (per-device topic restrictions)
- [ ] Disable wildcard subscriptions for non-admin clients
- [ ] Rotate credentials on device onboarding
- [ ] Monitor for unusual topic patterns (# subscriptions from non-admin)

---

## 10. Protocol Analysis Tools

### 10.1 Wireshark

**Capture Filters (BPF syntax — applied at capture time):**
```
# Basic
host 192.168.1.100                        # All traffic to/from host
net 192.168.0.0/16                        # Subnet
port 443                                  # Port 443 only
tcp                                       # TCP only
not arp                                   # Exclude ARP

# Combined
host 192.168.1.100 and port 80
src host 10.0.0.1 and dst port 53
(port 80 or port 443) and host 192.168.1.100
not broadcast and not multicast and not arp
tcp[tcpflags] & (tcp-syn|tcp-rst) != 0   # SYN or RST flags
```

**Display Filters (Wireshark expression language — applied post-capture):**
```
# IP
ip.src == 192.168.1.100
ip.dst == 10.0.0.0/8
ip.ttl < 5
!(ip.src == 192.168.1.0/24)              # Exclude subnet

# TCP
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.rst == 1
tcp.port == 443
tcp.analysis.retransmission
tcp.analysis.zero_window
tcp.stream == 5                          # Specific TCP stream

# HTTP
http.request.method == "POST"
http.request.uri contains "/admin"
http.response.code == 200
http.host contains "example.com"
http.cookie contains "session"

# DNS
dns.qry.name contains "malware"
dns.flags.rcode == 3                     # NXDOMAIN
dns.qry.type == 255                      # ANY query
dns.resp.len > 512                       # Large responses

# TLS/SSL
tls.handshake.type == 1                  # ClientHello
tls.handshake.type == 2                  # ServerHello
tls.record.version == 0x0301             # TLS 1.0
tls.handshake.ciphersuite == 0x002f      # Specific cipher

# Misc
frame.len > 1400                         # Large frames (possible exfil)
data-text-lines                          # Plaintext data
```

**Wireshark Statistics:**
```
# IO Graph: Statistics → IO Graph → filter streams by color
# Conversations: Statistics → Conversations → sort by bytes
# Protocol Hierarchy: Statistics → Protocol Hierarchy
# Expert Info: Analyze → Expert Information → filter by severity
# Follow Stream: Right-click → Follow → TCP/UDP/TLS/HTTP Stream
```

**TLS Decryption with SSLKEYLOGFILE:**
```bash
# Set environment variable before launching browser
export SSLKEYLOGFILE=/tmp/ssl_keys.log
chromium-browser &
# In Wireshark: Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
# Point to /tmp/ssl_keys.log
# All TLS sessions will be decrypted in Wireshark
```

---

### 10.2 tshark CLI

**Basic Analysis:**
```bash
# Read pcap and apply display filter
tshark -r capture.pcap -Y 'http.request'

# Extract specific fields
tshark -r capture.pcap -Y 'http.request' -T fields   -e ip.src -e ip.dst -e http.host -e http.request.uri   -E header=y -E separator=, > http_requests.csv

# DNS queries
tshark -r capture.pcap -Y 'dns.flags.response == 0' -T fields   -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type   -E separator='|'

# TLS ClientHellos with SNI
tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields   -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Extract credentials from HTTP Basic Auth
tshark -r capture.pcap -Y 'http.authorization' -T fields   -e ip.src -e http.authorization
```

**Statistics:**
```bash
# IO statistics (60-second intervals)
tshark -r capture.pcap -qz io,stat,60

# Protocol hierarchy
tshark -r capture.pcap -qz io,phs

# Conversation statistics
tshark -r capture.pcap -qz conv,tcp

# Top talkers
tshark -r capture.pcap -qz conv,ip | sort -k6 -rn | head 20

# Follow TCP stream (hex)
tshark -r capture.pcap -qz follow,tcp,hex,0

# Follow HTTP stream (ascii)
tshark -r capture.pcap -qz follow,http,ascii,0
```

**Live Capture:**
```bash
# Capture on interface with ring buffer (10 files × 100MB)
tshark -i eth0 -b filesize:102400 -b files:10 -w /captures/traffic.pcap

# Capture with filter, save, display simultaneously
tshark -i eth0 -f 'not port 22' -w capture.pcap -Y 'http' 2>/dev/null
```

---

### 10.3 tcpdump

```bash
# Basic capture
tcpdump -i eth0 -w capture.pcap

# Capture with filter, no name resolution (-n), verbose (-v)
tcpdump -i eth0 -n -v 'port 80 or port 443'

# Capture specific host
tcpdump -i eth0 -n 'host 192.168.1.100 and (port 80 or port 443)' -w host_capture.pcap

# Rotate files (100MB each, 10 files max)
tcpdump -i eth0 -C 100 -W 10 -w /captures/capture.pcap

# Show packet contents (hex + ASCII)
tcpdump -i eth0 -XX -n 'port 80' | head -100

# Capture DNS queries
tcpdump -i eth0 -n 'port 53 and udp' -l | tee dns_queries.txt

# SYN flood detection
tcpdump -i eth0 -n 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0'   | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head 20

# Capture credentials (HTTP basic auth, FTP)
tcpdump -i eth0 -A -n 'port 21 or port 80' | grep -i 'user\|pass\|login\|authorization'
```

---

### 10.4 Scapy — Protocol Crafting

```python
from scapy.all import *

# Craft custom TCP packet
pkt = IP(dst="192.168.1.100") / TCP(dport=80, flags="S") / Raw(b"GET / HTTP/1.0

")
send(pkt)

# SYN scan
ans, unans = sr(IP(dst="192.168.1.0/24")/TCP(dport=80, flags="S"), timeout=2)
for sent, recv in ans:
    if recv.haslayer(TCP) and recv[TCP].flags == "SA":
        print(f"{recv[IP].src}:80 OPEN")

# Craft malformed packet (fragmentation test)
frag1 = IP(dst="192.168.1.100", flags="MF", frag=0) / TCP() / b"A"*100
frag2 = IP(dst="192.168.1.100", frag=13) / b"B"*100
send([frag1, frag2])

# ARP poison (for testing)
arp_poison = ARP(op=2, pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff",
                 psrc="192.168.1.1")  # Claim gateway MAC is ours
send(arp_poison, count=5)

# ICMP tunnel test
icmp_pkt = IP(dst="8.8.8.8") / ICMP() / Raw(b"hidden_data_" * 50)
send(icmp_pkt)
```

---

### 10.5 NetworkMiner — PCAP Artifact Extraction

- **Purpose**: Passive network forensics; extract files, credentials, images, certificates from PCAP.
- **Key tabs**: Hosts (OS fingerprint), Files (reassembled files), Credentials (cleartext auth), Sessions, DNS, Parameters.
- **Free version** (NetworkMiner 2.x): Windows + Mono Linux.
- **Professional**: Additional parsers, anomaly detection, command-line.

```bash
# NetworkMiner CLI (professional)
NetworkMinerCLI.exe -r capture.pcap -w /output/
# Extracts: files to /output/AssembledFiles/, credentials to /output/Credentials.csv
```

---

### 10.6 Zeek (formerly Bro)

**Zeek Log Files:**

| Log | Contents | Security Use |
|-----|---------|-------------|
| `conn.log` | All connections | Traffic baseline, scanning |
| `dns.log` | DNS queries/responses | C2 detection, DGA |
| `http.log` | HTTP requests | Web traffic analysis |
| `ssl.log` | TLS connections | Certificate anomalies, weak ciphers |
| `x509.log` | Certificate details | CA validation, expiry |
| `files.log` | File transfers | Malware detection |
| `smtp.log` | Email transactions | Phishing, spam |
| `weird.log` | Protocol anomalies | Policy violations |
| `notice.log` | Zeek notice events | Triggered detections |

**Zeek Analysis with zeek-cut:**
```bash
# Find long connections (C2 keepalive)
zeek-cut id.orig_h id.resp_h id.resp_p duration < conn.log |   awk '$4 > 3600' | sort -k4 -rn | head 20

# Find large outbound transfers (exfiltration)
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log |   awk '$5 > 10000000' | sort -k5 -rn | head 20

# DNS NXDOMAIN analysis
zeek-cut id.orig_h query rcode_name < dns.log |   awk '$3 == "NXDOMAIN"' | sort -k1,1 | uniq -c | sort -rn | head 20

# Self-signed certificate detection
zeek-cut id.orig_h id.resp_h validation_status < ssl.log |   grep "self signed" | sort | uniq -c | sort -rn

# Password in cleartext HTTP (basic auth)
zeek-cut id.orig_h username password < http.log | grep -v '-' | head 20
```

---

### 10.7 Hardware TAPs and SPAN Ports

**Hardware TAPs (Test Access Points):**
- Physical devices installed inline — passive optical or copper taps.
- **Passive optical TAP**: Splits fiber signal, no power required, fail-open.
- **Active copper TAP**: Requires power; regenerates signal.
- **Aggregation TAP**: Combines both directions into single monitoring port.
- No impact to monitored traffic; cannot be detected by monitored hosts.
- Vendors: Garland Technology, Ixia (Keysight), cPacket, APCON.

**SPAN Ports (Switched Port Analyzer):**
```
# Cisco SPAN configuration
monitor session 1 source interface GigabitEthernet0/1 both
monitor session 1 destination interface GigabitEthernet0/24
! Caution: SPAN may drop packets under high load
! Cannot monitor traffic between devices on same switch at wire speed

# Remote SPAN (RSPAN) — across switches
vlan 999
 name RSPAN-VLAN
 remote-span
monitor session 1 source interface Gi0/1
monitor session 1 destination remote vlan 999

# ERSPAN (Encapsulated RSPAN) — across layer 3
monitor session 1 type erspan-source
 source interface Gi0/1 both
 destination
  erspan-id 1
  ip address 192.168.10.100
  origin ip address 192.168.1.1
```

**TAP vs SPAN Comparison:**

| Feature | Hardware TAP | SPAN Port |
|---------|-------------|-----------|
| Accuracy | 100% — no drops | May drop under load |
| Cost | Higher ($500–5000) | Free (switch feature) |
| Detectability | Undetectable | May affect performance |
| Traffic type | All, including errors | Filtered by switch |
| Failure mode | Fail-open | Traffic continues |
| Installation | Inline (brief outage) | Configuration only |

---

## Appendix: Quick Reference Commands

### Port/Protocol Quick Reference

| Protocol | Port | Transport | Security Notes |
|----------|------|-----------|---------------|
| FTP | 20/21 | TCP | Cleartext — use SFTP or FTPS |
| SSH | 22 | TCP | Secure; audit key algorithms |
| Telnet | 23 | TCP | **Cleartext — disable** |
| SMTP | 25 | TCP | Require STARTTLS |
| DNS | 53 | UDP/TCP | Monitor for amplification/C2 |
| DHCP | 67/68 | UDP | Enable snooping |
| HTTP | 80 | TCP | Redirect to HTTPS |
| Kerberos | 88 | TCP/UDP | Monitor for roasting |
| POP3 | 110 | TCP | Use POP3S (995) |
| NNTP | 119 | TCP | Rarely used; disable |
| NTP | 123 | UDP | Disable monlist (CVE-2013-5211) |
| NetBIOS | 137-139 | TCP/UDP | Disable if not needed |
| IMAP | 143 | TCP | Use IMAPS (993) |
| SNMP | 161/162 | UDP | Use SNMPv3 only |
| LDAP | 389 | TCP | Use LDAPS (636) |
| HTTPS | 443 | TCP | TLS 1.2+ only |
| SMB | 445 | TCP | Enable signing; block external |
| SMTP TLS | 465/587 | TCP | Submission with TLS |
| LDAPS | 636 | TCP | LDAP over TLS |
| DoT | 853 | TCP | DNS over TLS |
| IMAPS | 993 | TCP | IMAP over TLS |
| POP3S | 995 | TCP | POP3 over TLS |
| OpenVPN | 1194 | UDP | VPN |
| RADIUS | 1812/1813 | UDP | Use strong shared secret |
| MySQL | 3306 | TCP | Restrict remote access |
| RDP | 3389 | TCP | NLA required; MFA |
| XMPP | 5222 | TCP | Enable TLS |
| MQTT | 1883/8883 | TCP | Require auth + TLS (8883) |
| SIP | 5060/5061 | UDP/TCP | Use SRTP for media |
| HTTP alt | 8080/8443 | TCP | Often dev/proxy — audit |
| Modbus | 502 | TCP | Network isolation required |
| DNP3 | 20000 | TCP/UDP | SAv5 authentication |

---

*Document generated: 2026-05-06 | Classification: Internal Security Reference*
*For updates, vulnerability reports, or corrections: security-docs@teamstarwolf.com*
