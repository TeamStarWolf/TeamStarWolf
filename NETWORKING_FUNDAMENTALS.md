# Networking Fundamentals for Security Practitioners

> This reference is written for cybersecurity practitioners who need to understand **how** networking works — not just what it is — so they can reason about attacks, build detections, and design defenses. OSI layers, TCP/IP internals, Layer 2 behavior, routing protocols, DNS, and security architecture are covered with operational depth.

---

## Table of Contents

1. [The OSI Model — Security Perspective](#the-osi-model--security-perspective)
2. [TCP/IP Deep Dive](#tcpip-deep-dive)
   - [IP (IPv4)](#ip-ipv4)
   - [IPv4 Subnetting](#ipv4-subnetting-complete-reference)
   - [TCP](#tcp-transmission-control-protocol)
   - [UDP](#udp-user-datagram-protocol)
   - [ICMP](#icmp-internet-control-message-protocol)
3. [Ethernet and Layer 2](#ethernet--layer-2)
   - [MAC Addresses](#mac-addresses)
   - [ARP](#arp-address-resolution-protocol)
   - [VLANs (802.1Q)](#vlans-8021q)
   - [Spanning Tree Protocol](#spanning-tree-protocol-stprstp)
4. [Routing](#routing)
   - [Static vs Dynamic Routing](#static-vs-dynamic-routing)
   - [OSPF](#ospf-open-shortest-path-first)
   - [BGP](#bgp-border-gateway-protocol)
   - [NAT](#nat-network-address-translation)
5. [DNS](#dns-domain-name-system)
6. [Switching and Network Devices](#switching--network-devices)
   - [Firewalls](#firewalls)
   - [IDS/IPS](#idsips)
   - [Network Access Control (NAC)](#network-access-control-nac)
7. [Wireless Networking](#wireless-networking-security-fundamentals)
8. [Network Troubleshooting Commands](#network-troubleshooting-commands-security-context)
9. [Network Security Architecture](#network-security-architecture)
10. [ATT&CK Technique Quick Reference](#attck-technique-quick-reference)

---

## The OSI Model — Security Perspective

The OSI model is not just an academic framework. Each layer has a distinct attack surface and a set of tools used to exploit or defend it. Understanding which layer an attack operates at tells you what visibility you need and which controls can stop it.

| Layer | Name | PDU | Key Protocols | Attack Surface | Security Tools |
|---|---|---|---|---|---|
| 7 | Application | Data | HTTP, DNS, SMTP, SSH, HTTPS, LDAP, Kerberos | XSS, SQLi, command injection, SSRF, protocol abuse | Burp Suite, Wireshark, curl, ZAP |
| 6 | Presentation | Data | SSL/TLS, encoding (Base64, gzip, Unicode) | SSL stripping, certificate attacks, encoding abuse, deserialization | testssl.sh, sslscan, sslyze |
| 5 | Session | Data | NetBIOS, SMB sessions, RPC, SQL sessions, NFS | Session hijacking, token stealing, replay attacks, NTLM relay | Responder, Wireshark, Impacket |
| 4 | Transport | Segment / Datagram | TCP, UDP | SYN flood, port scanning, fragmentation attacks, session hijacking | nmap, hping3, scapy, tcpdump |
| 3 | Network | Packet | IP, ICMP, routing protocols (OSPF, BGP) | IP spoofing, ICMP tunneling, route injection, TTL manipulation | scapy, traceroute, arpspoof |
| 2 | Data Link | Frame | Ethernet, 802.11, 802.1Q (VLAN), STP, ARP | MAC flooding, ARP poisoning, VLAN hopping, STP root injection, evil twin | Yersinia, macchanger, aircrack-ng |
| 1 | Physical | Bits | Copper (Cat5e/6), fiber, wireless RF | Physical tapping, cable interception, RF jamming, optical splicing | Hardware taps, spectrum analyzers |

### Why Layer Matters for Security

**Attacks at Layer 7** are what most developers think about (XSS, SQLi), but they require understanding the application protocol. A WAF operates here.

**Attacks at Layer 6** include SSL stripping (downgrade HTTPS to HTTP), certificate spoofing, and deserialization exploits in encoded data. TLS inspection operates here.

**Attacks at Layer 5** include session fixation, NTLM relay (Responder), and SMB session replay. These exploit the session establishment logic.

**Attacks at Layer 4** (TCP/UDP) include SYN floods, RST injection, and port scanning. A stateful firewall tracks TCP connection state and can block half-open connections.

**Attacks at Layer 3** include IP spoofing, ICMP tunneling, and BGP/OSPF route injection. Routing and ACLs operate here.

**Attacks at Layer 2** are the most dangerous in internal networks because many organizations have weak Layer 2 controls. ARP poisoning, VLAN hopping, and STP manipulation are all Layer 2 attacks that can position an attacker for MITM without touching Layer 3 security controls.

**Attacks at Layer 1** are physical — wiretapping, optical splitters on fiber, RF jamming. Physical security controls (locked comms rooms, tamper-evident seals) operate here.

**ATT&CK Mapping**: Network sniffing (T1040), MITM (T1557), ARP cache poisoning (T1557.002), DNS hijacking (T1584.002), traffic signaling (T1205), network service discovery (T1046).

---

## TCP/IP Deep Dive

### IP (IPv4)

IPv4 is a 20-byte (minimum) header carrying every packet across routed networks. Every field matters to an attacker or defender.

#### IPv4 Header Fields

| Field | Size | Purpose | Security Relevance |
|---|---|---|---|
| Version | 4 bits | IP version (4 = IPv4, 6 = IPv6) | Version confusion attacks; IPv6 bypass of IPv4-only ACLs |
| IHL (Header Length) | 4 bits | Header length in 32-bit words (min=5, max=15) | Options parsing bugs; malformed IHL causes kernel crashes |
| DSCP/ECN | 8 bits | QoS marking / congestion notification | Covert channel in DSCP bits; ECN abuse |
| Total Length | 16 bits | Total datagram length including header | Fragmentation attacks; zero-length DoS |
| Identification | 16 bits | Fragment group ID (shared by all fragments) | OS fingerprinting; fragmentation evasion via ID prediction |
| Flags | 3 bits | Bit 1: DF (Don't Fragment), Bit 2: MF (More Fragments) | Fragmentation evasion; path MTU discovery |
| Fragment Offset | 13 bits | Position of fragment in original datagram (8-byte units) | Teardrop attack; IDS evasion via overlapping fragments |
| TTL | 8 bits | Hop limit (decremented each router; drop at 0) | OS fingerprinting; traceroute; TTL manipulation IDS evasion |
| Protocol | 8 bits | Upper layer: 6=TCP, 17=UDP, 1=ICMP, 47=GRE, 50=ESP | Protocol identification; unusual protocols = potential tunnel |
| Header Checksum | 16 bits | Covers header only (not payload) | Modified after NAT; routers recalculate; forgeable with scapy |
| Source IP | 32 bits | Sender address (not verified by IP layer itself) | Spoofing; reflection attacks; BCP38 |
| Destination IP | 32 bits | Recipient address | Destination-based routing; anycast |
| Options | Variable | Rarely used: source routing, timestamps, record route | Source routing abuse (disabled on modern gear); option overflow |

#### IP Fragmentation and Security

Fragmentation occurs when a packet exceeds the path MTU (typically 1500 bytes on Ethernet). The sending host (or router if DF=0) splits the packet into fragments, all sharing the same Identification field. The destination reassembles them using Identification + Fragment Offset + MF flag.

**Why fragmentation is a security concern:**
- **IDS evasion**: NIDS may not reassemble fragments before matching signatures. A payload can be split across fragments so no single fragment matches a signature.
- **Teardrop attack** (historical): Overlapping fragment offsets caused kernel reassembly code to crash on early Windows and Linux. Patched, but concept lives on in fuzzing.
- **Fragmentation + ACL evasion**: On some older gear, only the first fragment carries transport headers (port numbers). Subsequent fragments have only the Fragment Offset and can bypass port-based ACLs.
- **IPv6 fragmentation**: Only the source can fragment in IPv6 (no in-path fragmentation), reducing some evasion but introducing different reassembly behaviors.

Wireshark filter to catch fragmented traffic: `ip.flags.mf == 1 or ip.frag_offset > 0`

#### TTL Values by OS (Passive OS Fingerprinting)

The initial TTL set by an OS is predictable and useful for passive fingerprinting:

| OS | Default TTL | Notes |
|---|---|---|
| Windows (Vista+) | 128 | Subtract observed TTL from 128 to estimate hop count |
| Linux (kernel 2.4+) | 64 | Most common in cloud environments |
| Cisco IOS | 255 | Routers and network gear |
| macOS / BSD | 64 | Same as Linux |
| Solaris | 255 | Legacy UNIX systems |
| FreeBSD | 64 | Basis for pfSense, OPNsense |
| Android | 64 | Inherits Linux kernel default |

A packet with TTL=117 arriving at your host likely started at 128 (Windows) and traversed 11 hops. This is not definitive but useful as a passive signal alongside TCP options fingerprinting.

Tools: `p0f` (passive OS fingerprinting), `nmap -O` (active), Wireshark statistics.

#### Private and Special IP Ranges

| Range | CIDR | Purpose | Security Notes |
|---|---|---|---|
| Private (Class A) | 10.0.0.0/8 | Large internal networks | Seeing in routing tables = misconfiguration or leak |
| Private (Class B) | 172.16.0.0/12 | Medium internal networks | 172.16-31.x.x range |
| Private (Class C) | 192.168.0.0/16 | Small internal networks (home/SMB) | Most common home lab range |
| Loopback | 127.0.0.0/8 | Local host only (127.0.0.1 most common) | SSRF bypass: `http://127.0.0.1/admin` |
| Link-local (APIPA) | 169.254.0.0/16 | Auto-assigned when DHCP fails | 169.254.x.x = DHCP failure alert |
| Multicast | 224.0.0.0/4 | One-to-many delivery | OSPF (224.0.0.5/6), SSDP (239.255.255.250) |
| Limited Broadcast | 255.255.255.255/32 | All hosts on local subnet | Directed broadcast disabled on modern gear |
| Documentation | 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 | TEST-NET in RFCs | Should never appear in routing tables or packet captures |
| Shared Address Space | 100.64.0.0/10 | Carrier-grade NAT (RFC 6598) | Complicates attribution in abuse investigations |
| IPv6 Loopback | ::1/128 | IPv6 localhost | Same SSRF relevance as 127.0.0.1 |
| IPv6 Link-local | fe80::/10 | Auto-configured on all IPv6 interfaces | Used for NDP (replaces ARP in IPv6) |

---

### IPv4 Subnetting — Complete Reference

#### Subnet Mask Table (CIDR /8 to /32)

| CIDR | Subnet Mask | Total Addresses | Usable Hosts | Typical Use |
|---|---|---|---|---|
| /8 | 255.0.0.0 | 16,777,216 | 16,777,214 | Large enterprise (Class A); 10.0.0.0/8 |
| /9 | 255.128.0.0 | 8,388,608 | 8,388,606 | Half of Class A |
| /10 | 255.192.0.0 | 4,194,304 | 4,194,302 | 100.64.0.0/10 CGNAT |
| /11 | 255.224.0.0 | 2,097,152 | 2,097,150 | Large regional block |
| /12 | 255.240.0.0 | 1,048,576 | 1,048,574 | 172.16.0.0/12 private range |
| /13 | 255.248.0.0 | 524,288 | 524,286 | ISP allocation |
| /14 | 255.252.0.0 | 262,144 | 262,142 | ISP allocation |
| /15 | 255.254.0.0 | 131,072 | 131,070 | ISP allocation |
| /16 | 255.255.0.0 | 65,536 | 65,534 | Campus or data center; 192.168.0.0/16 |
| /17 | 255.255.128.0 | 32,768 | 32,766 | Half campus |
| /18 | 255.255.192.0 | 16,384 | 16,382 | District or zone |
| /19 | 255.255.224.0 | 8,192 | 8,190 | Large building |
| /20 | 255.255.240.0 | 4,096 | 4,094 | Medium enterprise zone |
| /21 | 255.255.248.0 | 2,048 | 2,046 | Building or large floor |
| /22 | 255.255.252.0 | 1,024 | 1,022 | Medium subnet; university VLAN |
| /23 | 255.255.254.0 | 512 | 510 | Medium subnet |
| /24 | 255.255.255.0 | 256 | 254 | Standard office subnet; most common |
| /25 | 255.255.255.128 | 128 | 126 | Split /24 in half |
| /26 | 255.255.255.192 | 64 | 62 | Small subnet; workgroup |
| /27 | 255.255.255.224 | 32 | 30 | Small segment |
| /28 | 255.255.255.240 | 16 | 14 | VLAN, small server group |
| /29 | 255.255.255.248 | 8 | 6 | Small server cluster |
| /30 | 255.255.255.252 | 4 | 2 | Point-to-point WAN link |
| /31 | 255.255.255.254 | 2 | 2 | P2P link (RFC 3021; no broadcast addr) |
| /32 | 255.255.255.255 | 1 | 1 | Host route, loopback, firewall rule |

Usable hosts = Total addresses - 2 (network address + broadcast address). Exception: /31 (RFC 3021) and /32 (host route — used in OSPF loopback advertisements and firewall rules).

#### Subnetting Math — Worked Example

**Given: 192.168.10.0/26**

Step 1 — Convert prefix to mask:
```
/26 = 26 bits set to 1
Binary: 11111111.11111111.11111111.11000000
Mask:   255      .255     .255     .192
```

Step 2 — Block size (the "magic number"):
```
Block size = 256 - last non-zero octet = 256 - 192 = 64
Subnets repeat every 64 addresses in the last octet: 0, 64, 128, 192
```

Step 3 — Calculate addresses for 192.168.10.0/26:
- **Network address**: 192.168.10.**0** (all host bits = 0)
- **First usable host**: 192.168.10.**1**
- **Last usable host**: 192.168.10.**62**
- **Broadcast address**: 192.168.10.**63** (all host bits = 1)
- **Total usable hosts**: 2^6 - 2 = **62**

Step 4 — Verify whether a host belongs to this subnet:
```
Does 192.168.10.45 belong to 192.168.10.0/26?
45 AND 192 (bitwise) = 0 → network = 192.168.10.0 → YES, it belongs.

Does 192.168.10.75 belong to 192.168.10.0/26?
75 AND 192 = 64 → network = 192.168.10.64 → NO, it's in 192.168.10.64/26.
```

**Quick mental formula:**
```
Host bits = 32 - prefix_length
Usable hosts = 2^(host_bits) - 2
/26 → 32 - 26 = 6 host bits → 2^6 - 2 = 62 usable
/28 → 32 - 28 = 4 host bits → 2^4 - 2 = 14 usable
/30 → 32 - 30 = 2 host bits → 2^2 - 2 = 2 usable (P2P link)
```

#### Subnetting for Security Practitioners

- **Micro-segmentation**: Use /28 or /29 subnets for server groups to limit blast radius of compromise.
- **Scanning scope**: Understanding subnets tells you how many IPs nmap will probe. A /16 = ~65,000 hosts; /24 = 254 hosts.
- **Longest-prefix-match in attacks**: OSPF/BGP route injection is more dangerous when you inject a more-specific route — it wins by longest-prefix-match rule. A hijacker advertising a /24 out of your /22 steals traffic for that /24.
- **CIDR in firewall rules**: A rule for `10.0.0.0/8` covers all RFC 1918 Class A addresses. Miscounting host bits creates over-permissive or broken rules.
- **RFC 1918 in captures**: Seeing RFC 1918 addresses where public IPs are expected = misconfiguration or spoofing. Seeing 169.254.x.x = DHCP failure — a configuration alert worth monitoring.

---

### TCP (Transmission Control Protocol)

TCP is a connection-oriented, reliable, ordered protocol. Understanding its internal mechanics is fundamental to understanding a huge class of attacks: scanning, SYN floods, session hijacking, RST injection, and firewall evasion.

#### TCP Header Fields

| Field | Size | Description | Security Relevance |
|---|---|---|---|
| Source Port | 16 bits | Ephemeral (1024-65535) or well-known port | Port hopping C2; source port 0 attacks |
| Destination Port | 16 bits | Service port (22 SSH, 80 HTTP, 443 HTTPS, 3389 RDP...) | Service identification; well-known port = firewall bypass |
| Sequence Number | 32 bits | Byte position of first byte in this segment (ISN = starting value) | Sequence prediction attack; session hijacking |
| Acknowledgment Number | 32 bits | Next byte expected from the other side | State tracking |
| Data Offset | 4 bits | Header length in 32-bit words (5 = 20 bytes minimum) | TCP options parsing; malformed offset = crash |
| Reserved | 3 bits | Must be zero per RFC | Covert channel if set |
| Flags | 9 bits | URG, ACK, PSH, RST, SYN, FIN + ECE, CWR, NS | Scan detection; firewall rules; evasion techniques |
| Window Size | 16 bits | Receive buffer space available (controls flow) | Fingerprinting (Win=65535 on Windows); window scale |
| Checksum | 16 bits | Covers pseudo-header + header + data | Data integrity; can be recomputed for forged packets |
| Urgent Pointer | 16 bits | Offset to urgent data when URG flag is set | URG rarely used legitimately; covert channel |
| Options | Variable | MSS, SACK, timestamps, window scaling, NOP | OS fingerprinting (p0f, nmap -O) |

#### TCP Flags — Security Reference

```
URG — Urgent data present (Urgent Pointer field is valid)
ACK — Acknowledgment number is valid (set after first SYN-ACK)
PSH — Push: deliver data to application immediately, don't buffer
RST — Reset: abort connection immediately, no graceful close
SYN — Synchronize: initiate connection, exchange Initial Sequence Numbers
FIN — Finish: no more data from sender, begin graceful close
```

**Attack relevance of flag combinations:**

| Scan / Attack Type | Flags Set | Behavior | Use Case |
|---|---|---|---|
| SYN scan (nmap -sS) | SYN only | RST on closed; no RST on open (stealth) | Port discovery without completing handshake |
| NULL scan | None | RFC: RST on closed; open ignores | Firewall evasion; Unix targets |
| FIN scan | FIN only | RST on closed; open ignores | Bypasses some stateless ACLs |
| XMAS scan | URG+PSH+FIN | Same as FIN scan | Named for "lit up like Christmas tree" |
| ACK scan | ACK only | Unfiltered returns RST; filtered drops/RST | Map firewall rules (stateful vs stateless) |
| RST injection | RST | Forged RST terminates TCP session | BGP session attacks; censorship (GFW) |
| SYN flood | SYN only (spoofed src) | Server allocates half-open state, exhausts table | DoS against TCP stack |

#### The 3-Way Handshake (with Sequence Numbers)

```
Client (192.168.1.100)            Server (192.168.1.1:443)
        |                                   |
        |---- SYN (seq=1000, ack=0) ------->|   Client picks random ISN = 1000
        |                                   |
        |<--- SYN-ACK (seq=5000, ack=1001) -|   Server picks ISN = 5000
        |                                   |   Server ACKs client ISN + 1
        |                                   |
        |---- ACK (seq=1001, ack=5001) ----->|   Client ACKs server ISN + 1
        |                                   |
        |========= ESTABLISHED =============|   Both sides have synced sequence numbers
```

**ISN (Initial Sequence Number)**: Should be cryptographically random per RFC 6528. Predictable ISNs (early implementations used simple counters) allowed **TCP session hijacking** — an attacker who can predict the next sequence number can inject data into an existing connection.

**SYN flood attack mechanics:**
```
Attacker (with spoofed IPs)         Server
  |---- SYN (src=1.1.1.1) --------->|  Server allocates state: SYN_RECEIVED
  |---- SYN (src=2.2.2.2) --------->|  Server allocates state: SYN_RECEIVED
  |---- SYN (src=3.3.3.3) --------->|  ... (SYN-ACK goes to spoofed IPs; no ACK)
  ... (thousands more) ...           |  Connection table fills up → LEGITIMATE CONNECTIONS DROPPED
```

**SYN cookies** (mitigation): Encode the connection state in the SYN-ACK sequence number using a hash. Only allocate state when the ACK arrives with the correct value. Enabled in Linux: `sysctl -w net.ipv4.tcp_syncookies=1`.

#### 4-Way Termination

```
Client                              Server
  |---- FIN (seq=A) --------------->|   Client done sending
  |<--- ACK (ack=A+1) --------------|   Server acknowledges (half-close)
  |                                 |   Server can still send data here
  |<--- FIN (seq=B) ----------------|   Server done sending
  |---- ACK (ack=B+1) ------------->|   Client acknowledges
  |                                 |
  Client enters TIME_WAIT           Server enters CLOSED
  (waits 2x MSL = 60-120s)
```

**TIME_WAIT** prevents old duplicate segments from being mistaken for new connections. A large number of TIME_WAIT connections is normal on busy servers. CLOSE_WAIT accumulation (many connections stuck in CLOSE_WAIT) indicates an application is not calling close() on sockets — potential resource leak or bug.

#### TCP States — Full Reference

| State | Where | Description | Attack/Defense Relevance |
|---|---|---|---|
| LISTEN | Server | Bound to port, waiting for connection | Service discovery; exposed service |
| SYN_SENT | Client | SYN sent, awaiting SYN-ACK | Port scan indicator on client |
| SYN_RECEIVED | Server | SYN-ACK sent, awaiting ACK | SYN flood victim state; high count = flood |
| ESTABLISHED | Both | Full connection active, data flowing | Normal traffic; hijacking target |
| FIN_WAIT_1 | Initiator | FIN sent, waiting for ACK or FIN | Graceful close initiated |
| FIN_WAIT_2 | Initiator | FIN ACKed, waiting for FIN from remote | Half-close state |
| TIME_WAIT | Initiator | Both FINs exchanged, waiting 2xMSL | Port reuse delay; large count = busy server |
| CLOSE_WAIT | Receiver | Received FIN, local hasn't closed | App bug: not calling close(); resource leak |
| LAST_ACK | Receiver | FIN sent after CLOSE_WAIT | Final close acknowledgment pending |
| CLOSED | Both | No connection exists | Default state |

Check TCP states on Linux: `ss -s` (summary) or `ss -tan` (all TCP with state)
Check on Windows: `netstat -ano | findstr TCP`

#### TCP Options and OS Fingerprinting

TCP options are negotiated in the SYN packet and reveal OS-specific defaults:

| Option | Code | Description | Fingerprinting Significance |
|---|---|---|---|
| MSS | 2 | Maximum Segment Size — negotiated max payload | Reveals MTU; Linux=1460, Windows=1460, VPN may differ |
| SACK Permitted | 4 | Selective ACK support | Most modern OS enable it |
| Timestamps | 8 | RTT measurement; PAWS against wrapped seqs | Enabled by most; reveals system uptime |
| Window Scale | 3 | Multiply window by 2^n for high-bandwidth | Scale factor reveals OS class |
| NOP | 1 | Padding to align options | Option order is OS-specific |

`p0f` uses the combination of MSS, window size, window scale, SACK, timestamps, TTL, and option order to passively identify OS without sending a single packet. This technique is used in network sensors and firewalls for behavioral classification.

---

### UDP (User Datagram Protocol)

UDP is connectionless — 8 bytes, no handshake, no state, no guaranteed delivery. This simplicity is both its strength (low latency) and why it creates distinct security challenges.

#### UDP Header Structure

```
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|   Source Port   | Destination Port|
+--------+--------+--------+--------+
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|                Data               |
+-----------------------------------+
```

Only 4 fields. Checksum is optional in IPv4 (zero = no checksum), mandatory in IPv6.

#### Why UDP Matters for Security

**Amplification/Reflection DDoS**: UDP's connectionless nature enables reflection attacks. An attacker spoofs the victim's source IP and sends a small request to a public server; the large response goes to the victim.

| Protocol | Port | Amplification Factor | Attack Name | Mitigation |
|---|---|---|---|---|
| DNS | 53 | 28-54x (ANY record) | DNS amplification | Disable open recursion; RRL |
| NTP | 123 | 556x (monlist command) | NTP amplification | Disable monlist (ntpdc -c monlist) |
| SSDP | 1900 | 30x | SSDP reflection | Block port 1900 at border |
| Memcached | 11211 | 10,000-51,000x | Memcached amplification | Never expose Memcached to internet |
| TFTP | 69 | Variable | TFTP amplification | Block at border |
| QUIC | 443/UDP | N/A | QUIC-based C2 | Inspect or block QUIC |

Mitigation for amplification: BCP38 (ingress filtering — drop packets with spoofed source IPs at ISP level), rate limiting, disable unnecessary UDP services on internet-facing hosts.

**Stateless = harder to filter precisely**: Without stateful inspection, UDP-based protocols are nearly impossible to filter precisely. A stateless ACL `permit udp any any eq 53` lets all UDP/53 pass both directions — including attacker probes. A stateful firewall tracks the outbound query and only permits the matching response.

**C2 over UDP**: QUIC (HTTP/3) runs over UDP/443 and is encrypted. Many NDR/proxy solutions struggle to inspect QUIC traffic. Attackers increasingly use QUIC or DNS-over-HTTPS to blend with legitimate encrypted traffic.

**UDP port scanning**: `nmap -sU` is slow because closed UDP ports return ICMP Port Unreachable (Type 3, Code 3), but firewalls often rate-limit ICMP, causing false "open|filtered" results. `nmap -sU --top-ports 100` is more practical for reconnaissance.

---

### ICMP (Internet Control Message Protocol)

ICMP carries network error and diagnostic messages. It operates at Layer 3 (inside IP packets with Protocol number 1) but is distinct from TCP/UDP.

#### ICMP Type/Code Reference

| Type | Code | Name | Security Relevance |
|---|---|---|---|
| 0 | 0 | Echo Reply | Ping response; host is alive |
| 3 | 0 | Dest Unreachable — Net Unreachable | Network black hole or routing failure |
| 3 | 1 | Dest Unreachable — Host Unreachable | Host down or wrong subnet mask |
| 3 | 3 | Dest Unreachable — Port Unreachable | UDP port closed; used in UDP scanning |
| 3 | 4 | Dest Unreachable — Fragmentation Needed | Path MTU discovery; DF bit set |
| 3 | 13 | Dest Unreachable — Communication Filtered | Firewall reject rule (polite block) |
| 5 | 0 | Redirect — Redirect for Network | Router redirect — route manipulation |
| 5 | 1 | Redirect — Redirect for Host | Attacker-forged redirect for MITM |
| 8 | 0 | Echo Request | Ping; host discovery (nmap -sn -PE) |
| 11 | 0 | Time Exceeded — TTL in Transit | Traceroute hop response |
| 11 | 1 | Time Exceeded — Frag Reassembly | Fragment reassembly timeout |
| 12 | 0 | Parameter Problem — Pointer | Malformed IP header |

#### ICMP in Attack Workflows

**Host discovery without TCP/UDP**: `nmap -sn -PE 10.0.0.0/24` sends ICMP Echo Requests. Many hosts respond even when TCP ports are filtered. Windows allows ICMP from the local subnet by default. Combine with ARP scan for more complete results.

**Traceroute mechanics explained**: Linux `traceroute` sends UDP probes (default) or ICMP (`-I` flag) with TTL starting at 1, incrementing each probe. When TTL reaches zero at a router, the router generates ICMP Time Exceeded (Type 11, Code 0) — the source IP of this reply reveals the router's identity. Windows `tracert` uses ICMP Echo Requests directly. `traceroute -T -p 443` sends TCP SYN probes to port 443, bypassing ICMP-blocking firewalls.

**ICMP tunneling (C2/exfiltration)**: ICMP Echo payload is arbitrary data up to ~65,000 bytes. Tools like `ptunnel`, `icmptunnel`, and `hans` embed TCP sessions inside ICMP Echo packets, traversing firewalls that allow ICMP but block TCP.

Detection signatures:
- Large ICMP payloads (normal ping = 32-64 bytes; tunneling = 1000+ bytes)
- High ICMP request/reply rate from a single host
- Non-sequential ICMP IDs or unusual IDs
- ICMP Echo where payload is not the standard pattern

**ICMP redirect attack**: Type 5 ICMP Redirect tells a host "use this router instead for that destination." Forged redirects from an attacker redirect victim traffic through the attacker for MITM. Modern Linux kernels ignore ICMP redirects by default (`net.ipv4.conf.all.accept_redirects = 0`). Check: `sysctl net.ipv4.conf.all.accept_redirects`.

**Smurf attack** (historical): Attacker sends ICMP Echo Request to subnet broadcast address with spoofed source = victim IP. Every host on the subnet replies to the victim — amplification DDoS. Mitigated by disabling directed broadcasts on routers (`no ip directed-broadcast` in Cisco IOS) and BCP38.

---

## Ethernet & Layer 2

Layer 2 is the most dangerous and least monitored layer in most enterprise networks. Attacks here can intercept traffic before it ever reaches Layer 3 controls.

### MAC Addresses

A MAC address is a 48-bit (6-byte) Layer 2 identifier, typically written as `AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF`.

**Structure:**
```
AA:BB:CC | DD:EE:FF
OUI (first 24 bits) | Device-specific (last 24 bits)

Bit 0 (LSB) of first byte:
  0 = Unicast address (sent to one destination)
  1 = Multicast / Broadcast (FF:FF:FF:FF:FF:FF = broadcast to all)

Bit 1 of first byte:
  0 = Globally unique (burned-in, OUI-assigned by IEEE)
  1 = Locally administered (randomized, virtual machine, privacy)
```

**OUI (Organizationally Unique Identifier) lookup**: The first 24 bits identify the NIC vendor. During incident response, OUI lookup helps identify device type:
```bash
# OUI lookup via API
curl -s https://api.macvendors.com/AA:BB:CC

# Via Wireshark's OUI database
wireshark -G manuf | grep -i "Apple"
```

**CAM table (Content Addressable Memory)**: A switch learns MAC→port mappings by observing source MACs of incoming frames. Default timeout is ~300 seconds. When a destination MAC is unknown, the switch **floods** the frame to all ports except the source — this "unknown unicast flooding" can expose traffic to other hosts on the segment.

**MAC flooding attack**: Fill the CAM table with bogus MAC addresses using tools like `macof` (dsniff) or `ettercap`. When the table is full, the switch degrades to hub behavior — flooding all frames to all ports. Attacker on any port sees all traffic. Mitigation: **Port Security** — configure `switchport port-security maximum 3` and `switchport port-security violation shutdown` to limit MACs per port.

**MAC randomization**: Modern iOS, Android, and Windows 11 randomize MAC addresses per SSID to prevent tracking. This complicates MAC-based network access control (NAC) and asset tracking. Enterprise impact: 802.1X with certificates (EAP-TLS) is not affected; MAB is.

---

### ARP (Address Resolution Protocol)

ARP resolves Layer 3 IPv4 addresses to Layer 2 MAC addresses. It operates at "Layer 2.5" — encapsulated in Ethernet frames (EtherType 0x0806), but logically bridges Layer 2 and Layer 3.

#### How ARP Works

```
Host A (192.168.1.100) wants to reach Host B (192.168.1.50):

Step 1 — ARP Request (broadcast):
  Ethernet: Src=AA:BB:CC:11:22:33  Dst=FF:FF:FF:FF:FF:FF
  ARP: "Who has 192.168.1.50? Tell 192.168.1.100"
  (Every host on the segment receives this)

Step 2 — ARP Reply (unicast):
  Ethernet: Src=DD:EE:FF:44:55:66  Dst=AA:BB:CC:11:22:33
  ARP: "192.168.1.50 is at DD:EE:FF:44:55:66"

Step 3 — Host A caches: 192.168.1.50 → DD:EE:FF:44:55:66
  Cache lifetime: Linux = 60s (reachable) → 30s probe; Windows = 45-65s
```

ARP cache inspection:
```bash
arp -a          # Windows and Linux — show ARP cache
ip neigh show   # Linux (preferred) — shows state (REACHABLE, STALE, etc.)
```

**Gratuitous ARP**: An unsolicited ARP reply where the sender announces its own IP-to-MAC mapping. Used legitimately by HSRP/VRRP failover (announce new MAC for VIP) and IP conflict detection. Attackers abuse gratuitous ARP to poison caches without waiting for a request.

#### ARP Poisoning (ARP Spoofing) Attack

ARP has **no authentication** — any host can send ARP replies claiming any IP-to-MAC mapping.

**Attack flow — MITM via ARP poisoning:**
```
Normal state:
  Victim      → Gateway    (direct path)

After ARP poison:
  Attacker tells Victim:  "192.168.1.1 (gateway) is at ATTACKER_MAC"
  Attacker tells Gateway: "192.168.1.100 (victim) is at ATTACKER_MAC"

Result: Victim → Attacker → Gateway (attacker reads/modifies all traffic)
```

```bash
# Step 1: Enable IP forwarding (so traffic still reaches destination)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Step 2: ARP poison both directions (dsniff package)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Poison victim's ARP cache
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Poison gateway's ARP cache

# Alternative: Bettercap (modern, all-in-one)
bettercap -iface eth0
# In bettercap console:
net.probe on         # Discover hosts
arp.spoof on         # Start ARP poisoning
net.sniff on         # Capture traffic
```

**Detection methods:**
- Duplicate IP in ARP table: `arp -a | sort` — same IP appearing with two different MACs
- `arpwatch` daemon: monitors and alerts on MAC-to-IP changes for known hosts
- Wireshark filter: `arp.duplicate-address-detected` — built-in detection
- DHCP snooping + Dynamic ARP Inspection (DAI) on managed switches — validates ARP against DHCP binding table, drops unauthorized ARP packets
- XDR/NDR behavioral correlation: rapid ARP table changes across multiple hosts

**ATT&CK**: T1557.002 — ARP Cache Poisoning

---

### VLANs (802.1Q)

VLANs logically segment a physical switch into multiple isolated broadcast domains. A switch port is configured as either **access** (one VLAN, untagged) or **trunk** (multiple VLANs, 802.1Q tagged).

#### 802.1Q Tag Structure

An 802.1Q tag is a 4-byte field inserted between the source MAC and the EtherType:
```
Original Ethernet frame:
| Dst MAC (6B) | Src MAC (6B) | EtherType | Payload |

802.1Q tagged frame:
| Dst MAC (6B) | Src MAC (6B) | 0x8100 | TCI (2B) | EtherType | Payload |
                                TPID    |PCP|D|VID 12b|
                                        3b  1b
```

- **TPID** (Tag Protocol ID): 0x8100 — marks this as an 802.1Q frame
- **PCP** (Priority Code Point): 3 bits, 802.1p QoS priority 0-7 (7=highest)
- **DEI** (Drop Eligible Indicator): 1 bit — drop this frame under congestion
- **VID** (VLAN ID): 12 bits, values 1-4094 (0 = untagged, 4095 = reserved)

#### Trunk and Access Ports

| Port Type | VLANs | Tagging | Used For |
|---|---|---|---|
| Access port | One VLAN | Untagged frames to/from device | End devices (PCs, printers) |
| Trunk port | Multiple VLANs | 802.1Q tagged (except native VLAN) | Switch-to-switch, switch-to-router |
| Native VLAN | Special | **Untagged** on trunk | Default VLAN 1 — security risk |

**Native VLAN security risk**: On a trunk port, native VLAN traffic is sent and received untagged. If two switches have different native VLAN configurations, frames can "slip" between VLANs. Best practice: change native VLAN to an unused VLAN and tag explicitly.

#### VLAN Hopping Attacks

**Attack 1: Switch Spoofing (DTP Negotiation)**

Dynamic Trunking Protocol (DTP) is a Cisco protocol that allows switches to auto-negotiate trunk links. An attacker on an access port sends DTP frames pretending to be a switch — if the port is in `dynamic desirable` or `dynamic auto` mode, it may become a trunk, granting access to all VLANs.

```bash
# Yersinia — DTP trunk negotiation attack
yersinia dtp -attack 1   # Send DTP frames to negotiate trunk port

# If successful: sniff traffic from any VLAN using 802.1Q tagging
```

Mitigation:
```
switchport mode access          ! Force access mode — no DTP negotiation
switchport nonegotiate          ! Explicitly disable DTP
```

**Attack 2: Double Tagging**

The attacker crafts a frame with two 802.1Q tags:
- **Outer tag**: Native VLAN (e.g., VLAN 1) — stripped by first switch
- **Inner tag**: Target VLAN (e.g., VLAN 100) — forwarded by second switch

```
Attacker sends: [Outer: VLAN1] [Inner: VLAN100] [Payload]
First switch: strips outer VLAN1 tag (native = no tag), forwards frame with VLAN100 tag
Second switch: sees VLAN100, delivers to VLAN100 hosts
```

**Limitation**: Double tagging is one-directional — attacker can send to target VLAN but cannot receive replies (target host's reply goes to VLAN100, not back to attacker's access port in VLAN1).

Mitigation:
```
switchport trunk native vlan 999          ! Change native VLAN to unused VLAN
vlan dot1q tag native                     ! Tag native VLAN explicitly (global)
switchport mode access                    ! Access ports cannot receive double-tagged frames
```

**ATT&CK**: T1599 — Network Boundary Bridging; T1599.001 — VLAN Hopping

---

### Spanning Tree Protocol (STP/RSTP)

STP (IEEE 802.1D) prevents Layer 2 broadcast loops by electing one switch as **root bridge** and blocking redundant paths. Without STP, a loop would cause a broadcast storm that saturates the network in seconds — a Layer 2 self-inflicted DDoS.

#### How STP Works

1. **Root Bridge Election**: All switches exchange BPDUs (Bridge Protocol Data Units). The switch with the lowest **Bridge ID** (2-byte priority + 6-byte MAC address) becomes root. Default priority: 32768.
2. **Root Port**: Each non-root switch picks the port with the lowest-cost path to root (port cost = 1/bandwidth).
3. **Designated Port**: Each network segment has exactly one designated port — the port closest to root on that segment.
4. **Blocked Ports**: All other ports — receive BPDUs but do not forward data frames.
5. **Convergence times**: STP (802.1D): ~30-50 seconds (Listening → Learning → Forwarding). RSTP (802.1w): ~1-6 seconds using proposal/agreement mechanism.

#### BPDU Key Fields

| Field | Purpose | Attack Relevance |
|---|---|---|
| Root Bridge ID | Who the sender believes is root bridge | Injected lower value = attacker becomes root |
| Root Path Cost | Total path cost from sender to root | Lower value = preferred path |
| Bridge ID | Sender's own priority + MAC | Attacker sets priority to 0 for root injection |
| Port ID | Port from which BPDU was sent | Port selection logic |
| Message Age | Age of root BPDU in seconds | Max age = 20s before stale BPDU discarded |

#### STP Attacks

**Root bridge injection (most dangerous)**:
Attacker sends BPDUs with Bridge Priority = 0 (lower than any legitimate switch). All switches re-elect attacker as new root bridge. Traffic paths shift to go through attacker's switch — all traffic passes through attacker → MITM.

```bash
yersinia stp -attack 4   # Send superior BPDUs to become root bridge
```

**BPDU flood**: Send thousands of BPDUs from many spoofed Bridge IDs → constant STP topology changes → constant reconvergence → network DoS (traffic interrupted for 30-50s with STP, 1-6s with RSTP).

**Mitigation:**
```
! BPDU Guard: shut port if BPDU received (for access/PortFast ports only)
spanning-tree portfast bpduguard default    ! Globally
spanning-tree bpduguard enable              ! Per-port

! Root Guard: ignore superior BPDUs (for distribution uplinks)
spanning-tree guard root                    ! On ports where root should NOT be

! PortFast: skip Listening/Learning for access ports (instant forwarding for PCs)
spanning-tree portfast                      ! Per-port on access ports only
```

**ATT&CK**: T1565 — Data Manipulation (STP manipulation enables traffic interception); Network DoS (BPDU flood).

---

## Routing

### Static vs Dynamic Routing

**Static routes**: Manually configured, zero overhead, no automatic convergence — if the path fails, traffic drops until an admin intervenes. Used for stub networks, default routes, and point-to-point WAN links.

```bash
# Cisco IOS static route syntax
ip route 10.0.0.0 255.0.0.0 192.168.1.1    # To reach 10/8, use next-hop 192.168.1.1
ip route 0.0.0.0 0.0.0.0 192.168.1.254     # Default route (quad-zero)

# Linux
ip route add 10.0.0.0/8 via 192.168.1.1
ip route add default via 192.168.1.254

# Windows
route add 10.0.0.0 mask 255.0.0.0 192.168.1.1
```

**Longest prefix match (LPM)**: The router always uses the most specific matching route:
```
Destination: 10.10.10.5
Routes: 10.0.0.0/8  →  next-hop A
        10.10.10.0/24  →  next-hop B   ← MORE SPECIFIC: wins

Security implication: Attackers exploit LPM by injecting more-specific routes to
intercept traffic. A hijacker advertising 10.10.10.0/24 from your 10.0.0.0/8
steals traffic for that /24 subnet.
```

---

### OSPF (Open Shortest Path First)

OSPF is a link-state Interior Gateway Protocol (IGP) using Dijkstra's Shortest Path First algorithm. It's the dominant enterprise and service provider routing protocol.

#### OSPF Key Concepts

- **Link-state**: Each router floods a complete map of its links (LSAs) to all routers in the area. Every router builds an identical topology database (LSDB) and runs SPF independently.
- **Area 0 (backbone area)**: All other areas must connect to Area 0. Reduces LSA flooding scope and prevents routing loops between areas.
- **Cost metric**: 10^8 / interface bandwidth. Gigabit = cost 1; Fast Ethernet = cost 10; Serial 64k = cost 1562.
- **DR/BDR election**: On broadcast segments (Ethernet), one Designated Router reduces flooding. Router with highest OSPF priority (default 1) wins; tie-break = highest Router ID (highest loopback IP or highest interface IP).

#### LSA Types

| Type | Name | Description | Scope |
|---|---|---|---|
| 1 | Router LSA | Describes router's own links | Single area |
| 2 | Network LSA | DR advertises multi-access segment | Single area |
| 3 | Summary LSA | ABR summarizes other areas | Between areas |
| 4 | ASBR Summary LSA | Locates an ASBR | Between areas |
| 5 | AS External LSA | External routes (BGP, static) | Entire OSPF domain |
| 7 | NSSA External LSA | External routes in NSSA areas | NSSA area only |

#### OSPF Adjacency State Machine

```
DOWN → INIT → 2-WAY → EXSTART → EXCHANGE → LOADING → FULL

DOWN:     No Hellos received from neighbor
INIT:     Hello received; neighbor doesn't list us yet
2-WAY:    Both routers see each other in Hello packets (bidirectional)
EXSTART:  Negotiate master/slave for DBD exchange (higher RID = master)
EXCHANGE: Exchange DBD (Database Description) packets — LSDB summaries
LOADING:  Send LSR (Link State Request) for missing LSAs; receive LSU
FULL:     LSDB synchronized; routing can begin
```

On broadcast networks, only DR/BDR pairs reach FULL state with all routers. DROther routers stay in 2-WAY with each other.

#### OSPF Security

**Authentication** (prevents rogue router injection):
```
! MD5 authentication per interface
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 SecurePassword123
 ip ospf authentication message-digest

! SHA-256 (OSPFv3 with IPsec, or IOS-XE 15.4+ OSPF auth)
key chain OSPF-KEYS
 key 1
  key-string SecurePassword123
  cryptographic-algorithm hmac-sha-256

router ospf 1
 area 0 authentication message-digest
```

**Attack — OSPF LSA injection**: An attacker on the network segment who can speak OSPF (no authentication enabled, or authentication cracked) injects Router LSAs or Summary LSAs to:
- Black-hole traffic (advertise a prefix with infinite cost or via a non-existent next-hop)
- Redirect traffic through attacker's path
- Cause routing table corruption and convergence instability

Tools: `loki` (OSPF attack framework), custom Scapy scripts.

**Detection**: Unexpected Router ID in OSPF neighbor table (`show ip ospf neighbor`), sudden route table changes, OSPF authentication failures in syslog (message `%OSPF-4-NOAUTH`).

---

### BGP (Border Gateway Protocol)

BGP is the routing protocol of the internet — a path vector EGP (Exterior Gateway Protocol) that routes between Autonomous Systems (ASes). The global internet routing table contains 900,000+ prefixes as of 2025.

#### BGP Fundamentals

- **AS (Autonomous System)**: A network under single administrative control, identified by ASN. 16-bit ASNs: 1-65535. 32-bit ASNs: up to 4,294,967,295. Private ASNs: 64512-65534 (16-bit), 4200000000-4294967294 (32-bit).
- **eBGP**: Between different ASes. Default TTL=1 (neighbor must be directly connected). Use EBGP multihop for non-adjacent peers.
- **iBGP**: Within the same AS. Full mesh required (or route reflectors / confederations to scale). iBGP does not change AS_PATH.
- **TCP port 179**: BGP sessions run over TCP. A BGP session is a long-lived TCP connection — RST injection can tear down the session (hence MD5/GTSM protection).
- **Message types**: OPEN (establish session), UPDATE (route advertisements/withdrawals), NOTIFICATION (error/teardown), KEEPALIVE (60s default; hold time 180s).
- **AS_PATH loop prevention**: When a router receives an UPDATE with its own ASN in AS_PATH, it discards it — prevents routing loops between ASes.

#### BGP Path Selection (Simplified, in Priority Order)

```
1. Highest Weight (Cisco-specific; local to router only)
2. Highest LOCAL_PREF (prefer internal over external)
3. Locally originated (network command, redistribute, or aggregate)
4. Shortest AS_PATH (fewest ASes to traverse)
5. Lowest ORIGIN type (IGP=0 < EGP=1 < Incomplete=2)
6. Lowest MED (Multi-Exit Discriminator — hint to upstream for preferred entry point)
7. eBGP over iBGP
8. Lowest IGP metric to BGP next hop
9. Oldest eBGP route (stability preference)
10. Lowest Router ID (tiebreaker)
```

#### BGP Hijacking — How and Why It Matters

**BGP hijacking**: An AS originates a BGP prefix they do not own, or a more-specific sub-prefix of someone else's block. Since BGP routers prefer more-specific (longer prefix) routes, a hijacker advertising a /24 out of someone's /22 attracts traffic destined for that /24.

**Notable incidents:**
- **Pakistan Telecom / YouTube (2008)**: PTCL advertised 208.65.153.0/24 (more specific than YouTube's /22). YouTube was unreachable globally for ~2 hours. Traffic was black-holed in Pakistan's network.
- **AWS Route 53 / MyEtherWallet (2018)**: Hijack of Amazon's DNS infrastructure IP block. DNS queries for MyEtherWallet redirected to attacker-controlled server. Cryptocurrency theft followed.
- **Rostelecom (2020)**: Russian ISP briefly originated routes for US banks, cloud providers, and government services. ~8,000 prefixes affected.

**RPKI (Resource Public Key Infrastructure)**: Cryptographic mechanism to validate route origins:
- **ROA (Route Origin Authorization)**: Signed certificate from the RIR binding a prefix (up to a max-length) to an authorized ASN
- **RPKI-valid**: Prefix matches a valid ROA
- **RPKI-invalid**: Prefix does NOT match any ROA → should be dropped at RPKI-validating routers
- **RPKI-unknown**: No ROA exists — treated as valid (not invalid) by most implementations

```bash
# Check RPKI validation state for an IP prefix
curl -s "https://api.bgpview.io/ip/8.8.8.8" | python3 -m json.tool | grep -A5 "rir_allocation"

# Check ROA validity for a prefix/ASN pair
curl -s "https://rpki-validator.ripe.net/api/v1/validity/15169/8.8.8.0/24"

# Check what AS is announcing an IP
curl -s "https://api.bgpview.io/ip/1.1.1.1" | python3 -m json.tool | grep -A3 "asn"
```

**BGP security controls:**
- **RPKI + ROV**: Drop RPKI-invalid routes at border — prevents most hijacking of prefixes with ROAs
- **Prefix filters**: Explicit allow-lists of expected prefixes from each peer (most effective; operationally complex)
- **max-prefix limits**: Automatically shut down a peer session if they send too many prefixes (fat finger protection)
- **GTSM (Generalized TTL Security Mechanism)**: BGP peers set TTL=255; peers expect to receive TTL≥254 — prevents RST injection from off-path attackers who can't set that TTL
- **MD5 TCP authentication**: Password-based TCP segment authentication (weaker than GTSM but widely deployed)
- **BGPsec**: Cryptographic path validation per AS hop — not widely deployed as of 2025

**ATT&CK**: T1584.002 — DNS Server; T1599 — Network Boundary Bridging (BGP hijack used to intercept traffic at internet scale).

---

### NAT (Network Address Translation)

NAT translates IP addresses (and ports) as traffic crosses a boundary, enabling private RFC 1918 addresses to communicate with the internet and supporting port-based load balancing.

#### NAT Types

**SNAT (Source NAT) / PAT (Port Address Translation) / Masquerade** — many-to-one:
The firewall maintains a NAT translation table keyed on (inside source IP:port, outside translated IP:port). Return traffic is un-NATed using this table.

```
Internal host:  192.168.1.100:54321  →  Web server: 93.184.216.34:443
NAT translates: 192.168.1.100:54321  →  203.0.113.1:12345   (public IP:translated port)
Return traffic: 93.184.216.34:443    →  203.0.113.1:12345   →  un-NATed  →  192.168.1.100:54321
```

**DNAT (Destination NAT) / Port Forwarding** — inbound to specific host:
```
Internet request: 203.0.113.1:443  →  Internal web server: 10.0.1.5:443
```

**Hairpin NAT / NAT loopback**: Internal host accesses public IP of a service hosted internally. Required when DNS returns public IP but the service is actually on the internal network.

#### NAT and Security Implications

**Common misconception — NAT is NOT a security boundary**: NAT provides implicit inbound blocking for unsolicited connections (no state table entry = drop), but:
- Port forwards expose internal hosts to the internet
- NAT does not filter malicious content — a NATed HTTPS connection can carry malware
- Carrier-grade NAT (CGN, RFC 6598, 100.64.0.0/10) complicates law enforcement attribution — multiple customers share one public IP
- NAT state table exhaustion is a valid DoS vector

**NAT traversal for legitimate protocols**: VoIP (SIP), WebRTC, some VPNs, and games need to establish connections through NAT. Methods:
- **STUN** (Session Traversal Utilities for NAT, RFC 5389): Client queries STUN server to discover its public IP:port mapping
- **TURN** (Traversal Using Relays around NAT, RFC 5766): Relay all traffic through a TURN server when STUN fails (symmetric NAT)
- **ICE** (Interactive Connectivity Establishment, RFC 8445): Framework that tries direct, STUN, then TURN in order

**Security relevance**: STUN servers are internet-facing and often weakly authenticated. STUN/TURN protocols have been abused for C2 traffic — attackers use WebRTC infrastructure (Twilio, Google TURN) to relay C2 traffic through otherwise-trusted connections.

---

## DNS (Domain Name System)

DNS is the phonebook of the internet, but it is also one of the most abused protocols in security — used for C2, data exfiltration, amplification attacks, and phishing infrastructure.

### How DNS Resolution Works

**Full resolution chain for `www.example.com`:**
```
Client application (Chrome, curl, malware)
  ↓ 1. Check local DNS cache (TTL-controlled)
  ↓ 2. Check /etc/hosts or C:\Windows\System32\drivers\etc\hosts
  ↓ 3. Query stub resolver (OS resolver)
    ↓ 4. Stub queries recursive resolver (8.8.8.8, 1.1.1.1, or corporate resolver)
      ↓ 5. Recursive resolver queries root nameservers (.) → "Ask .com TLD servers"
      ↓ 6. Recursive resolver queries .com TLD servers → "Ask example.com's NS"
      ↓ 7. Recursive resolver queries example.com authoritative NS → "93.184.216.34"
    ↓ 8. Recursive caches answer per TTL, returns to client
  ↓ 9. Stub caches answer per TTL
Client connects to 93.184.216.34
```

**TTL (Time to Live)**: Caching duration for DNS records. Low TTL (30-300 seconds) = fast propagation but more queries to authoritative servers. Attackers set very low TTLs (30-60s) before changing C2 infrastructure IP — "fast flux" to evade blocklists and takedowns.

### DNS Record Types — Security Reference

| Record | Purpose | Security Relevance |
|---|---|---|
| A | IPv4 address mapping | Primary C2 resolution; IoC is the IP |
| AAAA | IPv6 address mapping | IPv6 C2; bypasses IPv4-only filtering/logging |
| CNAME | Canonical name (alias) | Domain fronting; subdomain takeover |
| MX | Mail server for domain | Email security; validate with SPF/DKIM/DMARC |
| TXT | Arbitrary text data | SPF, DKIM, DMARC policies; DNS tunneling payload |
| NS | Authoritative nameserver | Zone transfer target; delegation hijacking |
| PTR | Reverse DNS (IP → hostname) | Footprinting; spam reputation scoring |
| SOA | Start of Authority | Zone admin info; serial number for AXFR tracking |
| SRV | Service discovery | `_kerberos._tcp.domain.com` → AD; `_sip._tcp` → VoIP |
| CAA | Certification Authority Authorization | Restrict which CAs can issue TLS certs for domain |
| DNSKEY | DNSSEC zone public key | DNSSEC chain of trust |
| DS | Delegation Signer | Hash of child zone's DNSKEY in parent zone |
| TLSA | TLS cert association (DANE) | Pin certificate to DNS; bypass CA trust store |

### DNS Queries — Essential Commands

```bash
# Basic queries
dig example.com A                       # IPv4 address
dig example.com AAAA                    # IPv6 address
dig example.com MX                      # Mail servers
dig example.com TXT                     # TXT records (SPF, DKIM, DMARC, verification)
dig example.com NS                      # Authoritative nameservers
dig example.com SOA                     # Start of Authority

# Query specific resolver
dig @8.8.8.8 example.com ANY            # All records via Google DNS
dig @1.1.1.1 example.com               # Cloudflare resolver

# Reverse DNS
dig -x 93.184.216.34                    # PTR lookup (reverse DNS)

# Zone transfer attempt (usually blocked; tests for misconfiguration)
dig example.com AXFR @ns1.example.com

# Trace full resolution chain from root
dig +trace example.com

# Quick output (IP only)
dig +short example.com

# Check DNSSEC validation
dig +dnssec example.com

# nslookup equivalents
nslookup -type=MX domain.com            # MX records
nslookup -type=TXT domain.com           # TXT records
nslookup domain.com 8.8.8.8            # Query specific resolver

# host command (simplest)
host domain.com                         # Forward lookup
host 8.8.8.8                            # Reverse lookup

# DNS subdomain brute force
nmap --script dns-brute domain.com
```

### DNS over HTTPS (DoH) and DNS over TLS (DoT)

Traditional DNS is unencrypted on UDP/53 — visible to any network observer with a tap or SPAN port.

| Protocol | Port | Encryption | Blue Team Concern |
|---|---|---|---|
| DNS (traditional) | UDP/53, TCP/53 | None | Fully visible; log all queries |
| DoT (DNS over TLS) | TCP/853 | TLS | Can block port 853; inspect at proxy |
| DoH (DNS over HTTPS) | TCP/443 | TLS/HTTPS | Blends with HTTPS; hard to block without breaking internet |

**Blue team challenge with DoH**: If an endpoint uses DoH to 8.8.8.8 or 1.1.1.1, your corporate DNS server logs nothing. Firefox and Chrome enable DoH by default in some configurations.

Solutions:
1. Block DoH provider IPs at perimeter (8.8.8.8:443, 1.1.1.1:443 for DNS purposes)
2. Force all DNS through a corporate resolver using DHCP option 6 and firewall block on outbound DNS
3. SSL/TLS inspection at proxy (decrypts DoH traffic)
4. EDR DNS telemetry (endpoint records all DNS resolutions at OS level, bypassing network filtering)

---

### DNS Security Attacks

#### DNS Amplification (Reflection DDoS)

UDP/53 enables reflection because the attacker spoofs the victim's IP as the source:
```
Attacker spoofs victim's IP → Open Resolver: DNS ANY query for isc.org (40 bytes)
Open Resolver → Victim's IP: Large DNSSEC-signed ANY response (4000+ bytes)
Amplification factor: ~100x
```

With thousands of open resolvers, attacker generates Gbps of traffic from Kbps of queries. Mitigation: BCP38 (ISP ingress filtering to drop spoofed packets), Response Rate Limiting (RRL) on authoritative nameservers, disable recursive queries on authoritative servers.

#### DNS Tunneling (C2 and Exfiltration)

DNS tunneling encodes data in DNS query labels and response payloads. Since UDP/53 passes through nearly every firewall, it is a reliable C2 and exfiltration channel.

**How it works:**
```
# Client encodes "execute: whoami" in DNS query label
Query: YWdlbnQ6d2hvYW1pCg.c2.attacker-c2.com → client's DNS resolver → attacker's NS
       (base32/base64 encoded command)

# Attacker's NS returns response encoded in TXT/NULL/CNAME record
Response: TXT "dXNlcjogcm9vdAo" → decoded: "user: root"
```

**Tools**: `iodine` (TCP-over-DNS VPN), `dnscat2` (encrypted bidirectional C2 over DNS), `dns2tcp`, `DNSExfiltrator`

**Detection indicators:**
- High query volume from a single host to a single parent domain
- Long, high-entropy subdomain labels (normal = human-readable; tunneling = base32/64 encoded)
- Queries for rare/uncommon record types (NULL, PRIVATE)
- Single parent domain receives many unique subdomains (bypasses caching — every query is unique)
- Large TXT responses from external domains
- NXDOMAIN rate — tunneling often generates many NXDOMAINs during setup

```python
# Shannon entropy calculation to detect encoded DNS labels
import math, collections

def entropy(s):
    freq = collections.Counter(s)
    return -sum((c/len(s))*math.log2(c/len(s)) for c in freq.values())

# Normal domain label: "www" or "mail" — entropy ~1.5-2.5
# Base32 encoded payload: "y3zk9x2b8m1n4p" — entropy ~4.0-4.5+
print(entropy("a7f3k9x2b8m1n4p"))   # ~3.9 — suspicious
print(entropy("www"))                 # ~1.58 — normal
```

**ATT&CK**: T1071.004 — Application Layer Protocol: DNS; T1048.003 — Exfiltration Over Alternative Protocol; T1568.002 — Domain Generation Algorithms

#### DNS Hijacking

Multiple paths to redirect DNS queries to attacker-controlled IPs:
- **Compromised recursive resolver**: Attacker gains admin access to a corporate DNS server, modifies responses for targeted domains
- **MITM on UDP/53**: ARP poisoning on the local segment + DNS response injection (Responder, dnsspoof, Ettercap)
- **Registrar compromise**: Attacker changes NS records at the domain registrar level — all resolution globally is affected
- **BGP hijack of DNS provider IPs**: Reroute traffic destined for 8.8.8.8 or 1.1.1.1 to attacker-controlled resolvers (BGP-level attack, ISP tier)

#### DNS Rebinding

**How it works**: Attacker registers a domain with a very short TTL (1 second). Initially it resolves to attacker's public IP (legitimate). After the victim's browser caches the response, the attacker changes the DNS record to point to an internal IP (e.g., 192.168.1.1). The browser, believing the IP is still associated with the same origin, makes requests to the internal network under the attacker's domain origin.

**Impact**: Browser-based SSRF — JavaScript can make requests to internal services (router admin pages, cloud metadata 169.254.169.254, internal APIs) using victim's credentials.

Mitigation: DNS rebinding protection in browsers/resolvers (reject private IPs in DNS responses for public domains), bind services to specific interfaces.

#### DNSSEC

DNSSEC adds cryptographic signatures to DNS records:
- **RRSIG**: Cryptographic signature covering an RRset (resource record set)
- **DNSKEY**: Zone's public signing key
- **DS (Delegation Signer)**: Hash of child zone's DNSKEY stored in parent zone (forms chain of trust)
- **NSEC/NSEC3**: Authenticated denial-of-existence (NSEC3 adds hashing to prevent zone enumeration via "walking")

DNSSEC validates that responses haven't been tampered with but does **not** encrypt queries (that's DoH/DoT). Implementation is complex and misconfiguration causes resolution failures — DNSSEC is a common source of outages when signing keys expire without renewal.

#### Subdomain Takeover

A CNAME record points to an external service (GitHub Pages, Heroku, Azure, S3) that has been deprovisioned. The subdomain is "dangling" — anyone can claim the service and host content under the victim's trusted domain.

```bash
# Step 1: Enumerate subdomains
amass enum -d victim.com
subfinder -d victim.com

# Step 2: Check for dangling CNAMEs
dig sub.victim.com CNAME
# Result: sub.victim.com. 300 IN CNAME someapp.github.io.
dig someapp.github.io     # If NXDOMAIN → claimable takeover!

# Step 3: Claim the external service
# (Create a GitHub Pages repo at "someapp", CloudFront distribution, etc.)
```

**Tools**: `subjack`, `nuclei -t http/takeovers/`, `dnsx`, `can-i-take-over-xyz` (GitHub resource)

**Impact**: Serve phishing pages under victim's trusted domain, bypass CSP (same-origin policy), steal session cookies (domain-scoped), obtain DV TLS certificate for `sub.victim.com` via ACME/Let's Encrypt HTTP-01 challenge.

---

## Switching & Network Devices

### Firewalls

#### Stateless Packet Filtering

Matches traffic against rules based on header fields only: source/destination IP, source/destination port, protocol. No connection state tracking.

```
Rule: permit tcp 10.0.0.0/8 any eq 443
Problem: Rule allows ANY TCP packet to port 443 — including unsolicited
         inbound packets. Cannot distinguish response from attack.
```

Used in: Router ACLs (Cisco IOS access-lists), `iptables -t raw`, network appliance ACLs.

**Limitation**: Stateless rules require symmetric permit for both directions or allow all return traffic — this is the weakness that stateful inspection solves.

#### Stateful Inspection

Tracks TCP connection state (and UDP "pseudo-state") in a state table. Only permits return traffic matching an established flow entry.

```
TCP state table entry created:
SYN →  [state: SYN_SENT]
SYN-ACK ← [state: ESTABLISHED]
Data ↔  [match established state → PERMIT]
Unsolicited packet: [no matching state → DROP]
```

**State table exhaustion attack**: SYN flood or UDP flood fills the state table → legitimate connections are dropped. Mitigation: per-source connection rate limits, SYN cookies on the firewall itself, asymmetric state tracking for UDP.

#### Next-Generation Firewall (NGFW)

Adds Layer 7 visibility via Deep Packet Inspection (DPI):

| NGFW Capability | How It Works | Security Value |
|---|---|---|
| Application ID | Behavioral fingerprinting, not just port | Block BitTorrent on port 443; identify shadow IT |
| User identity | AD/LDAP integration via LDAP bind or User-ID agent | Enforce per-user policies; log with username |
| SSL/TLS inspection | Decrypt, inspect, re-encrypt HTTPS | See inside encrypted C2, exfiltration in HTTPS |
| URL filtering | Category-based blocking (malware, P2P, gambling) | Reduce attack surface; block phishing categories |
| Inline IPS | Signature matching on decrypted application traffic | Block known exploits mid-session |
| DNS Security | Sinkhole/block malicious domains | Prevent C2 dial-out via DNS |

**Key architectural concept — Security Zones**: NGFWs group interfaces into trust zones (Trust, Untrust, DMZ, VPN, Management). Policies are zone-pair-based. Traffic between zones requires an explicit allow rule; implicit deny at end.

**Firewall evasion techniques:**

| Technique | Mechanism | Detection/Mitigation |
|---|---|---|
| Fragmentation | Split payload across fragments below signature threshold | Reassemble before inspection; defrag on firewall |
| Protocol tunneling | Encode attack traffic in DNS, ICMP, HTTP | Application ID + DPI; block tunneling tools |
| No SSL inspection | Encrypt C2/exfil in TLS | Deploy TLS inspection with endpoint trust root |
| Application mimicry | Cobalt Strike malleable C2 profiles mimic Teams/Slack | Behavioral anomaly on application traffic flows |
| IPv6 bypass | Use IPv6 where firewall has weaker ruleset | Apply equivalent rules to IPv6; block IPv6 if unused |
| Low-and-slow | Traffic rate below alerting thresholds | Longer time window correlation in SIEM |

---

### IDS/IPS

#### NIDS vs NIPS Comparison

| | NIDS | NIPS |
|---|---|---|
| Deployment | Passive (network tap or SPAN/mirror port) | Inline (all traffic must traverse device) |
| Response capability | Alert only; no traffic blocking | Block malicious traffic + alert |
| Performance impact | Minimal (copies only) | Direct — adds latency (typically 50-200μs) |
| Failure mode | Fails open (traffic bypasses; detection lost) | Configurable: fail-open or fail-closed |
| False positive impact | Missed alerts; analyst noise | Blocked legitimate traffic — business disruption |

#### Detection Methods

**Signature-based**: Pattern matching against known attack patterns. Fast, low false positive rate on known attacks, blind to zero-days.

```
# Example Suricata signature
alert tcp any any -> any 80 (
    msg:"ET WEB_SERVER SQL Injection Attempt UNION SELECT";
    content:"UNION"; nocase; http.uri;
    content:"SELECT"; nocase; http.uri;
    within:50;
    sid:1001;
    rev:1;
)
```

**Anomaly-based**: Statistical baseline of normal traffic; alerts on deviations. Can detect novel attacks and insider threats. High false positive rate during initial baseline establishment, new deployments, seasonal variation.

**Behavioral/ML-based**: Machine learning on flow features (bytes/s, packets/s, flag ratios, connection duration). Better for complex environments; requires substantial training data and ongoing tuning.

#### IDS/IPS Evasion Techniques

| Technique | How It Works | Detection Response |
|---|---|---|
| IP fragmentation | Split payload below signature reassembly threshold | Normalize/defrag before inspection |
| TTL manipulation | Craft TTL that reaches IDS but not target — IDS sees payload; target ignores | Normalize TTL to fixed value before inspection |
| Encryption (TLS) | IDS cannot match signatures in encrypted traffic | Deploy TLS inspection (NGFW decrypt-inspect-encrypt) |
| Slow scan | Rate below IDS packets-per-second threshold | Extend correlation window; track partial scans |
| Polymorphism | Vary encoding (XOR key, base64 variant, chunked encoding) | Normalize encodings; heuristic content rules |
| Protocol violations | Exploit parser differences (IDS parses differently than target host) | Strict protocol normalization |
| Decoy traffic | Flood with benign-looking noise alongside real attack | Prioritized alert scoring; anomaly correlation |

Testing tools: `fragroute` (fragmentation), `scapy` (custom malformed packets), `nmap --data-length` (pad packets), Whisker (web evasion), `metasploit` evasion modules.

---

### Network Access Control (NAC)

NAC enforces policy before devices access the network — validating identity, device posture (patch level, AV status, OS version), and assigning appropriate network access.

#### 802.1X — Port-Based Network Access Control

802.1X is the standard for authentication before network access. The switch or AP enforces access, but does not authenticate — it relays to a RADIUS server using RADIUS protocol (UDP 1812/1813).

```
Supplicant (PC)  ←[EAP over LAN (EAPOL)]→  Authenticator (Switch/AP)  ←[RADIUS]→  Auth Server (FreeRADIUS, Cisco ISE, NPS)
```

**Sequence of events:**
1. Device connects to switch port
2. Switch sends EAP-Request/Identity to device
3. Device responds with identity (username or MAC)
4. Switch relays to RADIUS server as RADIUS Access-Request
5. RADIUS challenges/verifies credentials (varies by EAP method)
6. RADIUS sends Access-Accept (open port) or Access-Reject (keep port in limited VLAN)
7. Switch moves port to authorized VLAN

**EAP Methods Comparison:**

| Method | Credential | Server Cert Required | Client Cert Required | Security Level |
|---|---|---|---|---|
| EAP-TLS | Client certificate | Yes (mutual TLS) | Yes | Strongest — no password attack surface |
| PEAP-MSCHAPv2 | Username + password | Yes (TLS tunnel) | No | Common; MSCHAPv2 weak if server cert not validated |
| EAP-TTLS | Flexible inner method | Yes (TLS tunnel) | No | More flexible than PEAP |
| EAP-FAST | PAC (credential) | No (PAC-based) | No | Cisco; easier to deploy; weaker |

**PEAP-MSCHAPv2 attack — Evil twin RADIUS**:
If clients do not validate the RADIUS server's TLS certificate (common misconfiguration), an attacker can deploy a rogue AP + fake RADIUS server (hostapd-WPE, eaphammer) to capture the MSCHAPv2 challenge/response hash:

```bash
# Deploy rogue AP with hostapd-WPE (RADIUS impersonation)
eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "CorpWiFi" --creds

# Captured hash format: username:NTLMv2-hash
# Crack offline with hashcat
hashcat -m 5600 captured_ntlmv2.hash /usr/share/wordlists/rockyou.txt
```

**MAB (MAC Authentication Bypass)**: For devices without 802.1X support (IoT, printers, legacy), the switch uses the device's MAC address as authentication credential. Since MACs are unencrypted and trivially spoofable with `macchanger`, MAB provides minimal security but is operationally necessary for legacy device onboarding.

**NAC vendors**: Cisco ISE (most feature-rich), Aruba ClearPass, Forescout eyeSight/eyeControl (agentless), Portnox Cloud.

---

## Wireless Networking — Security Fundamentals

### 802.11 Standards Overview

| Standard | Marketing Name | Frequency | Max Theoretical Speed | Security Notes |
|---|---|---|---|---|
| 802.11b | WiFi 1 | 2.4 GHz | 11 Mbps | WEP era; fully insecure |
| 802.11a | WiFi 2 | 5 GHz | 54 Mbps | Early 5GHz; WPA era |
| 802.11g | WiFi 3 | 2.4 GHz | 54 Mbps | WPA/WPA2 era |
| 802.11n | WiFi 4 | 2.4/5 GHz | 600 Mbps | WPA2 dominant |
| 802.11ac | WiFi 5 | 5 GHz | ~3.5 Gbps | WPA2/WPA3 |
| 802.11ax | WiFi 6/6E | 2.4/5/6 GHz | ~9.6 Gbps | WPA3 required for 6 GHz |

**2.4 GHz vs 5 GHz security relevance**: 2.4 GHz has longer range (penetrates walls) and only 3 non-overlapping channels (1, 6, 11) — making it easier for attackers to reach more clients with an evil twin and creating congestion for jamming. 5 GHz has shorter range but more non-overlapping channels (up to 24 in some regions) and higher throughput.

### WiFi Association Process

```
Client                                    Access Point
  |                                            |
  |--- Probe Request (broadcast) ------------>|  "Any AP with SSID CorpWiFi?"
  |<-- Probe Response ------------------------|  AP sends capabilities, RSSI info
  |                                            |
  |--- Open System Authentication ----------->|  (Shared Key was WEP — do not use)
  |<-- Authentication ACK --------------------|
  |                                            |
  |--- Association Request ------------------>|  Client specifies supported rates, cipher
  |<-- Association Response ------------------|  AP assigns Association ID (AID)
  |                                            |
  |<--- DHCP exchange ----------------------->|  Get IP address
  |<--- 802.1X (if WPA2-Enterprise) -------->|  Authenticate via RADIUS
  |<--- 4-Way Handshake (WPA2) ------------->|  Derive session keys
  |                                            |
  |============ Data traffic ================|
```

### WPA2-Personal (PSK) — Cryptographic Details

WPA2-PSK does not use the passphrase directly for encryption. The key derivation chain:

```
Step 1: PMK derivation
Passphrase + SSID → PBKDF2-SHA1 (4096 iterations) → PMK (256-bit Pairwise Master Key)

Step 2: PTK derivation (4-Way Handshake)
PMK + ANonce (AP random) + SNonce (Client random) + AP MAC + Client MAC
→ PRF-512 → PTK (512-bit Pairwise Transient Key)

Step 3: PTK split
PTK = KCK (128-bit, MIC calculation)
    + KEK (128-bit, GTK encryption)
    + TK  (128-bit, data encryption — used for AES-CCMP)
    + 2x MIC keys (64-bit each)

Step 4: GTK delivery
AP → Client: GTK (Group Temporal Key for broadcast/multicast) encrypted with KEK
```

**Why this matters for attacks:**
- The PMK is deterministic given passphrase + SSID — offline dictionary attack is possible if you capture the 4-way handshake
- Each session derives a fresh PTK (ANonce and SNonce are random per session)
- **PMKID attack (clientless)**: The PMKID (HMAC-SHA1 of PMK + AP MAC + Client MAC) is transmitted in the first EAPOL frame — captured without needing a client to authenticate, enabling offline cracking

```bash
# Capture PMKID (no client deauth needed)
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convert to hashcat format
hcxpcapngtool -o hash.hc22000 capture.pcapng

# Crack with hashcat (mode 22000 = PMKID + EAPOL combined)
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.hc22000 -a 3 '?l?l?l?l?l?l?l?l'  # 8-char lowercase brute force
```

### WPA3-Personal — Security Improvements

WPA3-Personal replaces PSK with **SAE (Simultaneous Authentication of Equals)**, based on a variant of Diffie-Hellman (Dragonfly key exchange):

| Feature | WPA2-PSK | WPA3-SAE |
|---|---|---|
| Key derivation | PMK from passphrase+SSID (static) | Fresh PMK per session (ephemeral) |
| Forward secrecy | No — past sessions decryptable with passphrase | Yes — each session has unique PMK |
| Offline dictionary attack | Yes — capture handshake + crack | No — requires online interaction per guess |
| Equivalent security | Depends entirely on passphrase complexity | 128-bit equivalent even with weak passphrase |

**Dragonblood (2019 vulnerabilities)**: Side-channel attacks (timing, cache) against some WPA3 SAE implementations allowed partial key recovery. Patched in updated firmware/OS implementations.

### WPA2-Enterprise (802.1X + RADIUS)

Each user has individual credentials. Security depends on:
- Server certificate validation by clients (prevent evil twin RADIUS — see PEAP attack above)
- Strong EAP method (EAP-TLS >> PEAP-MSCHAPv2)
- Rogue AP detection via WIDS/WIPS (Wireless Intrusion Detection/Prevention System)

### Wireless Security Testing Commands

```bash
# Put wireless NIC in monitor mode
airmon-ng start wlan0         # Creates wlan0mon; kills interfering processes
iwconfig wlan0 mode monitor   # Alternative method

# Survey networks
airodump-ng wlan0mon          # Channel-hopping survey (see all networks)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon  # Target specific AP

# Deauthentication to capture 4-way handshake
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon  # Send 5 deauth frames

# Evil twin / hostapd rogue AP for credential capture
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf     # WPA2-Enterprise cred capture

# Crack captured handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Modern approach: PMKID + hashcat
hcxdumptool -i wlan0mon -o capture.pcapng
hcxpcapngtool -o hash.hc22000 capture.pcapng
hashcat -m 22000 hash.hc22000 rockyou.txt
```

**ATT&CK**: T1465 — Rogue Wi-Fi Access Points; T1040 — Network Sniffing; T1557 — Adversary-in-the-Middle

---

## Network Troubleshooting Commands — Security Context

Every command below has security relevance beyond basic troubleshooting. Know what each reveals and why an attacker or defender would run it.

```bash
# ============================================================
# LAYER 3 CONNECTIVITY
# ============================================================

# ICMP echo test — confirms L3 reachability and ICMP policy
ping -c 4 8.8.8.8
ping -c 4 -s 1472 8.8.8.8     # Test MTU: 1472+28 IP/ICMP header = 1500 byte frame

# Path discovery — reveals routing hops and intermediate router IPs (network footprinting)
traceroute -n 8.8.8.8          # Linux: UDP probes by default, -n skips reverse DNS
tracert -d 8.8.8.8             # Windows: ICMP probes, -d skips DNS resolution
traceroute -T -p 443 8.8.8.8   # TCP SYN traceroute on port 443 (bypass ICMP-blocking firewalls)
traceroute -I 8.8.8.8          # Linux ICMP mode (same as Windows tracert)

# Path MTU discovery
ping -M do -s 1472 gateway_ip  # Linux: DF-bit forced — find where fragmentation occurs
pathping 8.8.8.8               # Windows: combines ping + tracert with packet loss statistics

# ============================================================
# DNS QUERIES
# ============================================================

nslookup -type=MX domain.com               # MX records (identify mail servers)
dig domain.com ANY @8.8.8.8               # All records via Google DNS resolver
dig -x 8.8.8.8                            # Reverse DNS (PTR lookup)
dig +trace domain.com                     # Full resolution trace from root
dig domain.com AXFR @ns1.domain.com       # Zone transfer attempt (tests for misconfiguration)
host domain.com                           # Simple readable forward lookup
dig domain.com TXT | grep -i spf          # Extract SPF record
dig domain.com TXT | grep -i dmarc        # Extract DMARC policy
nmap --script dns-brute domain.com        # DNS subdomain brute force

# ============================================================
# NETWORK STATE — CRITICAL FOR INCIDENT RESPONSE
# ============================================================

# Windows: all connections with PIDs — identify what process owns suspicious connection
netstat -ano
netstat -ano | findstr ESTABLISHED        # Active connections only
netstat -ano | findstr :443               # Connections to/from specific port
netstat -ano | findstr LISTEN             # Listening services

# Linux: ss (preferred over legacy netstat)
ss -tlnp                                  # TCP, listening, numeric, with process names
ss -tunap                                 # TCP+UDP, all states, with process
ss -o state established '( dport = :443 or sport = :443 )'  # Established HTTPS connections
ss -s                                     # Connection state summary

# Routing table — where will traffic be sent?
netstat -rn                               # Windows + Linux legacy
ip route show                             # Linux (preferred)
ip route get 8.8.8.8                      # Exactly which route would be used for 8.8.8.8
route print                               # Windows: full routing table

# ARP cache — who is on the local segment?
arp -a                                    # Windows + Linux
ip neigh show                             # Linux (preferred): shows ARP/NDP state
ip neigh show | grep -v REACHABLE         # Find STALE, INCOMPLETE, FAILED entries

# Interface information
ip addr show                              # Linux: interface IPs, MACs, state
ip link show                              # Linux: interface status, MTU, flags
ifconfig                                  # Legacy Linux / macOS
ipconfig /all                             # Windows: full interface details including DHCP info
ip -s link                                # Linux: interface statistics (errors, drops, collisions)

# ============================================================
# PACKET CAPTURE — FOUNDATIONAL INVESTIGATIVE TOOL
# ============================================================

# Basic capture — first step in any network investigation
tcpdump -i eth0 -n -c 100

# Targeted captures by host, port, protocol
tcpdump -i eth0 'tcp port 443 and host 1.2.3.4'   # Specific host+port combination
tcpdump -i eth0 'not port 22'                      # Exclude SSH management noise
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'    # SYN packets only (scanning/handshakes)
tcpdump -i eth0 arp                                # ARP traffic (detect ARP poisoning)
tcpdump -i eth0 icmp                               # ICMP traffic (detect ICMP tunneling)
tcpdump -i eth0 'udp port 53'                      # DNS queries

# Save to file for Wireshark analysis
tcpdump -w /tmp/capture.pcap -i eth0              # Write to file
tcpdump -G 3600 -W 24 -w /tmp/cap_%Y%m%d_%H.pcap  # Rotate hourly, keep 24 files

# Wireshark display filters (more expressive than capture filters)
# tcp.flags.syn==1 && tcp.flags.ack==0    → SYN packets (scan detection / handshake start)
# arp.duplicate-address-detected          → ARP poisoning indicator
# dns.qry.name contains "."              → Abnormally long DNS labels (potential tunneling)
# http.request.method == "POST"           → HTTP POST requests (data submission / exfil)
# tls.handshake.type == 1                → TLS ClientHello (new TLS connections — watch SNI)
# ip.ttl < 5                             → Very low TTL (traceroute or TTL manipulation)
# icmp.data_len > 100                    → Large ICMP payload (potential ICMP tunnel)

# ============================================================
# PORT SCANNING AND SERVICE DISCOVERY
# ============================================================

nmap -sS -p 1-65535 target              # SYN (stealth) scan — all 65535 ports
nmap -sV -sC -p 22,80,443,8080 target   # Version detection + default scripts on common ports
nmap -sU -p 53,161,500,4500 target      # UDP scan: DNS, SNMP, IKE/IPsec ports
nmap -O target                          # OS fingerprinting via TTL + TCP options
nmap -A -T4 target                      # Aggressive: OS + version + scripts + traceroute
nmap -sn 10.0.0.0/24                   # Ping sweep (host discovery without port scan)
nmap --script vuln target              # Run vulnerability NSE scripts
nmap --script banner -sS target        # Grab service banners

# Masscan — for large ranges where nmap -sS is too slow
masscan -p1-65535 10.0.0.0/16 --rate=1000 -oG masscan_out.txt
masscan -p80,443,8080,8443 10.0.0.0/8 --rate=10000

# ============================================================
# FIREWALL RULES
# ============================================================

# Linux
iptables -L -n -v --line-numbers        # All rules with packet/byte counts and line numbers
iptables -t nat -L -n -v               # NAT table rules (SNAT, DNAT, MASQUERADE)
ip6tables -L -n -v                     # IPv6 rules — often neglected!
nft list ruleset                        # nftables (modern replacement for iptables on Linux)
ufw status verbose                      # Ubuntu UFW (Uncomplicated Firewall) rules
firewall-cmd --list-all                 # firewalld (RHEL/CentOS/Fedora) active rules

# Windows
netsh advfirewall show allprofiles     # Firewall state (on/off) for all profiles
netsh advfirewall firewall show rule name=all  # All configured rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select DisplayName,Action,Direction

# ============================================================
# VPN AND TUNNEL INSPECTION
# ============================================================

ip tunnel show                          # All active Linux tunnels (GRE, IPIP, etc.)
ip -d link show type gre               # GRE tunnels specifically
ip -d link show type vxlan             # VXLAN overlays (used in SDN/container networking)
ss -tlnp | grep -E '1194|4500|500'    # OpenVPN (1194) / IPsec (500/4500) ports listening
wg show                                # WireGuard tunnel status, peers, handshake times

# ============================================================
# COMMON SECURITY INVESTIGATION COMBINATIONS
# ============================================================

# Find process owning a suspicious connection (Linux)
ss -tunap | grep ESTABLISHED | grep ':443'   # See process name + PID
ls -la /proc/$(ss -tunap | grep ':443' | awk '{print $7}' | cut -d= -f2)/exe  # Binary path

# Check for unusual listening ports (compare against known-good baseline)
ss -tlnp | awk '{print $4}' | sort | uniq -c | sort -rn

# Watch for new connections in real time
watch -n 1 'ss -tn state established | wc -l'

# DNS cache inspection (Windows — look for malicious cached entries)
ipconfig /displaydns | grep -A2 "attacker"

# Check for hosts file manipulation (persistence/redirect technique)
# Linux
cat /etc/hosts
# Windows
type C:\Windows\System32\drivers\etc\hosts
```

---

## Network Security Architecture

### Defense in Depth — Layered Model

```
                        INTERNET
                            |
    ┌───────────────────────────────────────────────────┐
    │      DDoS Scrubbing / Upstream Provider           │
    │   Volumetric mitigation (Cloudflare, Akamai)      │
    └───────────────────────────────────────────────────┘
                            |
    ┌───────────────────────────────────────────────────┐
    │                   Edge Router                     │
    │  BGP filters · RPKI · BCP38 · GTSM · prefix lists │
    └───────────────────────────────────────────────────┘
                            |
    ┌───────────────────────────────────────────────────┐
    │            Perimeter NGFW / IPS                   │
    │  Stateful · DPI · SSL inspect · URL filter · IPS  │
    └───────────────────────────────────────────────────┘
                       |          |
              ┌────────┴──┐   ┌──┴────────┐
              │    DMZ    │   │  VPN Zone  │
              │  Web/API  │   │ Remote     │
              │  servers  │   │ workers    │
              │  WAF      │   │ (ZTNA)     │
              └────────┬──┘   └──┬────────┘
                       │          │
    ┌───────────────────────────────────────────────────┐
    │                Internal Firewall                  │
    │  Strict DMZ→Core rules · micro-segmentation       │
    └───────────────────────────────────────────────────┘
                            |
    ┌───────────────────────────────────────────────────┐
    │                  Core Network                     │
    │    AD/LDAP  |  DNS  |  NTP  |  PKI               │
    │    (Critical services — isolated /28 subnets)     │
    └───────────────────────────────────────────────────┘
            |                |                |
    ┌───────┴──────┐  ┌──────┴──────┐  ┌─────┴──────┐
    │  Workstation │  │   Server    │  │   IoT/OT   │
    │  Segment     │  │   Segment   │  │  (isolated)│
    │  NAC/802.1X  │  │  App + DB   │  │  no outbound│
    └──────────────┘  └─────────────┘  └────────────┘
```

### Traffic Flow and Security Controls

**North-South traffic** (crossing the perimeter boundary — client ↔ internet):
- Inspected at perimeter NGFW
- WAF for inbound web traffic (OWASP Top 10)
- SSL/TLS inspection for HTTPS traffic
- Proxy (forward proxy) for outbound browsing — URL categorization, malware inspection
- DLP at egress — detect data exfiltration patterns in outbound traffic

**East-West traffic** (internal server-to-server — lateral movement path):
- Often underinspected — switches forward without inspection
- Lateral movement: compromise endpoint → pivot to internal servers
- Controls:
  - Host-based firewall (Windows Defender Firewall, iptables) — whitelist required flows
  - Microsegmentation (VMware NSX, Illumio, Guardicore) — overlay policy enforcement
  - VLAN isolation — separate broadcast domains per function
  - Internal NDR/IDS sensors on core switch SPAN ports
  - EDR — detect process-level lateral movement (PsExec, WMI, RDP)

**Zero Trust overlay principle:**
- Every connection is authenticated and authorized regardless of originating segment
- "Never trust, always verify" — network location grants no implicit access
- Implementation: identity-aware proxy (BeyondCorp model), ZTNA (Zscaler, Cloudflare Access, Palo Alto Prisma Access)

### Segmentation Principles

1. **Define trust zones by risk and data sensitivity**: Internet, DMZ, workstation, server, OT/ICS, management, partner/guest
2. **Build a communication matrix**: Document which zone talks to which, which protocols, which ports. If it's not documented, it should be denied.
3. **Default-deny between zones**: Every inter-zone rule is an explicit permit with business justification
4. **Management plane isolation**: Out-of-band management network for network devices (switches, firewalls, routers) — separate from data plane; only accessible from dedicated jump hosts
5. **Blast radius minimization**: A compromised IoT device on a dedicated /28 cannot reach domain controllers. A compromised user workstation should not be able to reach HR database servers.
6. **Segment by function, not just subnet**: PCI-scoped assets in dedicated VLAN/segment; privilege workstations for admin use only

### Key Network Security Controls Summary

| Control | Protects Against | OSI Layer |
|---|---|---|
| VLAN segmentation | Broadcast domain isolation, lateral movement | L2 |
| Port Security (MAC limiting) | MAC flooding (CAM table overflow) | L2 |
| Dynamic ARP Inspection (DAI) | ARP poisoning / ARP spoofing | L2 |
| BPDU Guard / Root Guard | STP root injection, BPDU flood | L2 |
| 802.1X NAC + EAP-TLS | Unauthorized device network access | L2/L3 |
| Stateful inspection firewall | Unauthorized inbound connections | L3/L4 |
| NGFW + inline IPS | Application-layer attacks, known exploits | L7 |
| SSL/TLS inspection | Encrypted C2, exfiltration inside HTTPS | L6/L7 |
| WAF | OWASP Top 10, web application attacks | L7 |
| RPKI + BGP prefix filters | BGP hijacking, route origin spoofing | L3 (routing) |
| DNSSEC + DNS security filtering | DNS hijacking, DNS-based C2 | L7 (DNS) |
| NDR / Network flow monitoring | Anomaly detection, lateral movement | L3-L7 |
| Microsegmentation | East-West lateral movement | L3-L7 |
| DDoS scrubbing | Volumetric and protocol-based attacks | L3/L4 |
| BCP38 ingress filtering | Spoofed source IP packets | L3 |

---

## ATT&CK Technique Quick Reference

| ATT&CK ID | Technique | Network Mechanism | Key Protocols / Layer |
|---|---|---|---|
| T1040 | Network Sniffing | Passive capture on shared segment or SPAN port | All layers |
| T1046 | Network Service Discovery | Port and service scanning | TCP/UDP — L4 |
| T1048.003 | Exfiltration Over Alternative Protocol | DNS tunneling, ICMP tunnel, HTTP C2 | DNS (L7), ICMP (L3) |
| T1071.001 | C2 via Web Protocols | HTTP/HTTPS C2 (Cobalt Strike, Metasploit) | HTTP/HTTPS — L7 |
| T1071.004 | C2 via DNS | DNS TXT/NULL record tunneling, DGA | DNS — L7 |
| T1090 | Proxy | SOCKS5 proxy, HTTP tunneling, Tor | L4/L7 |
| T1095 | Non-Standard Port | C2 on non-standard port (e.g., HTTPS on 8443) | TCP/UDP — L4 |
| T1557 | Adversary-in-the-Middle | ARP poisoning, DHCP spoofing, rogue AP | L2/L3 |
| T1557.002 | ARP Cache Poisoning | Gratuitous ARP, arpspoof | L2 |
| T1562.004 | Disable/Modify Firewall | `iptables -F`, Windows FW disable via GPO | L3/L4 |
| T1563 | Remote Service Session Hijacking | TCP sequence number injection | TCP — L4 |
| T1568.001 | Fast Flux DNS | Rapid IP rotation via low-TTL DNS | DNS — L7 |
| T1568.002 | Domain Generation Algorithms | Algorithmic C2 domain generation | DNS — L7 |
| T1572 | Protocol Tunneling | ICMP tunnel (ptunnel), DNS tunnel (iodine) | ICMP L3, DNS L7 |
| T1590 | Gather Victim Network Info | WHOIS, BGP routing table, DNS enumeration | Multiple |
| T1599 | Network Boundary Bridging | VLAN hopping, BGP route injection | L2/L3 |
| T1599.001 | VLAN Hopping | DTP negotiation, double tagging | L2 |
| T1205 | Traffic Signaling | Port knocking for firewall bypass | L4 |
| T1499 | Endpoint Denial of Service | SYN flood, UDP amplification, ICMP flood | L3/L4 |

---

*Reference built for cybersecurity practitioners. Depth over brevity — understanding the mechanism is what enables both offense and defense.*
