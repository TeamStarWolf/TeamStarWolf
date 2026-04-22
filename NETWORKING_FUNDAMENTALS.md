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

---

## The OSI Model — Security Perspective

The OSI model is not just an academic framework. Each layer has a distinct attack surface and a set of tools used to exploit or defend it. Understanding which layer an attack operates at tells you what visibility you need and which controls can stop it.

| Layer | Name | PDU | Protocols | Attack Surface | Key Tools |
|---|---|---|---|---|---|
| 7 | Application | Data | HTTP, DNS, SMTP, SSH, HTTPS, LDAP, Kerberos | XSS, SQLi, command injection, protocol abuse | Burp Suite, Wireshark, curl |
| 6 | Presentation | Data | SSL/TLS, encoding (Base64, gzip) | SSL stripping, certificate attacks, encoding abuse | testssl.sh, sslscan, sslyze |
| 5 | Session | Data | NetBIOS, SMB sessions, RPC, SQL sessions | Session hijacking, token stealing, replay attacks | Responder, Wireshark, Impacket |
| 4 | Transport | Segment / Datagram | TCP, UDP | SYN flood, port scanning, fragmentation attacks, session hijacking | nmap, hping3, scapy, tcpdump |
| 3 | Network | Packet | IP, ICMP, ARP (Layer 2.5), routing protocols | IP spoofing, ICMP tunneling, route injection, ARP poisoning | arpspoof, scapy, traceroute |
| 2 | Data Link | Frame | Ethernet, 802.11, 802.1Q (VLAN), STP | MAC flooding, VLAN hopping, STP root injection, evil twin | Yersinia, macchanger, aircrack-ng |
| 1 | Physical | Bits | Copper, fiber, wireless RF | Physical tapping, cable interception, RF jamming | Hardware taps, spectrum analyzers |

### Why Layer Matters for Security

**Attacks at Layer 7** are what most developers think about (XSS, SQLi), but they require understanding the application protocol. A WAF operates here.

**Attacks at Layer 4** (TCP) include SYN floods and scanning. A stateful firewall tracks TCP connection state and can block half-open connections.

**Attacks at Layer 3** include IP spoofing and ICMP tunneling. Routing and ACLs operate here.

**Attacks at Layer 2** are the most dangerous in internal networks because many organizations have weak Layer 2 controls. ARP poisoning, VLAN hopping, and STP manipulation are all Layer 2 attacks that can position an attacker for MITM without touching Layer 3 security controls.

**ATT&CK Mapping**: Network sniffing (T1040), MITM (T1557), ARP cache poisoning (T1557.002), DNS hijacking (T1584.002), traffic signaling (T1205).

---

## TCP/IP Deep Dive

### IP (IPv4)

IPv4 is a 20-byte (minimum) header carrying every packet across routed networks. Every field matters to an attacker or defender.

#### IPv4 Header Fields

| Field | Size | Purpose | Security Relevance |
|---|---|---|---|
| Version | 4 bits | IP version (4 = IPv4) | Version confusion attacks |
| IHL | 4 bits | Header length in 32-bit words | Options parsing bugs |
| DSCP/ECN | 8 bits | QoS marking / congestion notification | Covert channel in DSCP bits |
| Total Length | 16 bits | Total datagram length | Fragmentation attacks |
| Identification | 16 bits | Fragment group ID | OS fingerprinting, fragmentation evasion |
| Flags | 3 bits | DF (Don't Fragment), MF (More Fragments) | Fragmentation evasion, path MTU discovery |
| Fragment Offset | 13 bits | Position of fragment in original datagram | Teardrop attack, IDS evasion |
| TTL | 8 bits | Hop limit (decremented each router) | OS fingerprinting, traceroute |
| Protocol | 8 bits | Upper layer protocol (6=TCP, 17=UDP, 1=ICMP) | Protocol identification |
| Header Checksum | 16 bits | Covers header only (not payload) | Modified after NAT — routers recalculate |
| Source IP | 32 bits | Sender address | Spoofing, BCP38 |
| Destination IP | 32 bits | Recipient address | Destination-based routing |
| Options | Variable | Rarely used; source routing, timestamps | Source routing abuse (disabled on modern gear) |

#### IP Fragmentation and Security

Fragmentation occurs when a packet exceeds the path MTU (typically 1500 bytes on Ethernet). The sending host (or router if DF=0) splits the packet into fragments, all sharing the same Identification field. The destination reassembles them using Identification + Fragment Offset + MF flag.

**Why fragmentation is a security concern:**
- **IDS evasion**: NIDS may not reassemble fragments before matching signatures. A payload can be split across fragments so no single fragment matches a signature.
- **Teardrop attack** (historical): Overlapping fragment offsets caused kernel reassembly code to crash on early Windows and Linux. Patched, but concept lives on in fuzzing.
- **Fragmentation + ACL evasion**: On some older gear, only the first fragment carries transport headers (port numbers). Subsequent fragments have only the Fragment Offset and can bypass port-based ACLs.
- **IPv6 fragmentation**: Only the source can fragment in IPv6 (no in-path fragmentation), reducing some evasion but introducing different reassembly behaviors.

Wireshark filter to catch fragmented traffic: `ip.flags.mf == 1 or ip.frag_offset > 0`

#### TTL Values by OS (OS Fingerprinting)

The initial TTL set by an OS is predictable and useful for passive fingerprinting:

| OS | Default TTL |
|---|---|
| Windows (Vista+) | 128 |
| Linux (kernel 2.4+) | 64 |
| Cisco IOS | 255 |
| macOS / BSD | 64 |
| Solaris | 255 |
| FreeBSD | 64 |

A packet with TTL=117 arriving at your host likely started at 128 (Windows) and traversed 11 hops. This is not definitive but useful as a passive signal alongside TCP options fingerprinting.

Tools: `p0f` (passive OS fingerprinting), `nmap -O` (active), Wireshark statistics.

#### Private and Special IP Ranges

| Range | CIDR | Purpose |
|---|---|---|
| Private (Class A) | 10.0.0.0/8 | Large internal networks |
| Private (Class B) | 172.16.0.0/12 | Medium internal networks |
| Private (Class C) | 192.168.0.0/16 | Small internal networks (home/SMB) |
| Loopback | 127.0.0.0/8 | Local host only (127.0.0.1 most common) |
| Link-local (APIPA) | 169.254.0.0/16 | Auto-assigned when DHCP fails |
| Multicast | 224.0.0.0/4 | One-to-many delivery |
| Broadcast | 255.255.255.255/32 | All hosts on local subnet |
| Documentation | 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 | TEST-NET in RFCs; should never appear in routing tables |
| Shared Address Space | 100.64.0.0/10 | Carrier-grade NAT (RFC 6598) |

Security note: Seeing RFC 1918 addresses in traffic that should be public is a sign of misconfiguration or spoofing. Seeing 169.254.x.x typically means DHCP failure — a configuration alert you want to monitor.

---

### IPv4 Subnetting — Complete Reference

#### Subnet Mask Table

| CIDR | Subnet Mask | Total Addresses | Usable Hosts | Typical Use |
|---|---|---|---|---|
| /8 | 255.0.0.0 | 16,777,216 | 16,777,214 | Large enterprise Class A |
| /12 | 255.240.0.0 | 1,048,576 | 1,048,574 | 172.16.0.0/12 private range |
| /16 | 255.255.0.0 | 65,536 | 65,534 | Campus or data center |
| /20 | 255.255.240.0 | 4,096 | 4,094 | Large subnet |
| /22 | 255.255.252.0 | 1,024 | 1,022 | Medium subnet |
| /23 | 255.255.254.0 | 512 | 510 | Medium subnet |
| /24 | 255.255.255.0 | 256 | 254 | Standard office subnet |
| /25 | 255.255.255.128 | 128 | 126 | Split /24 |
| /26 | 255.255.255.192 | 64 | 62 | Small subnet |
| /27 | 255.255.255.224 | 32 | 30 | Small segment |
| /28 | 255.255.255.240 | 16 | 14 | VLAN, server group |
| /29 | 255.255.255.248 | 8 | 6 | Small server cluster |
| /30 | 255.255.255.252 | 4 | 2 | Point-to-point link |
| /31 | 255.255.255.254 | 2 | 2 | P2P (RFC 3021, no broadcast) |
| /32 | 255.255.255.255 | 1 | 1 | Host route, loopback |

Usable hosts = Total addresses - 2 (network address + broadcast address). Exception: /31 and /32 per RFC 3021.

#### Subnetting Math — Worked Example

**Given: 192.168.10.0/26**

Step 1 — Subnet mask:  
/26 = 11111111.11111111.11111111.**11**000000 = 255.255.255.192

Step 2 — Block size:  
256 - 192 = **64** (the block repeats every 64 addresses)

Step 3 — Subnet boundaries in the last octet:  
0, 64, 128, 192

Step 4 — For 192.168.10.0/26:
- **Network address**: 192.168.10.0 (all host bits = 0)
- **First usable host**: 192.168.10.1
- **Last usable host**: 192.168.10.62
- **Broadcast address**: 192.168.10.63 (all host bits = 1)
- **Total usable hosts**: 62

Step 5 — Verify a host belongs to this subnet:  
Does 192.168.10.45 belong to 192.168.10.0/26?  
`45 AND 192 = 0` → network = 192.168.10.0 → Yes, it belongs.

**Quick mental method for CIDR to usable hosts:**  
Host bits = 32 - prefix. Usable = 2^(host bits) - 2.  
/26 → 6 host bits → 2^6 - 2 = 62 usable.

#### Subnetting for Security

- **Micro-segmentation**: Use /28 or /29 subnets for server groups to limit blast radius of compromise.
- **Scanning scope**: Understanding subnets tells you how many IPs nmap will probe. /16 = ~65,000 hosts.
- **Routing security**: OSPF/BGP route injection is more dangerous if you inject a more-specific route (longer prefix) — it wins over shorter prefixes by longest-prefix-match rule.
- **CIDR notation in firewall rules**: A rule for 10.0.0.0/8 covers all RFC 1918 Class A addresses. Miscounting host bits creates over-permissive or broken rules.

---

### TCP (Transmission Control Protocol)

TCP is a connection-oriented, reliable, ordered protocol. Understanding its internal mechanics is fundamental to understanding a huge class of attacks: scanning, SYN floods, session hijacking, RST injection, and firewall evasion.

#### TCP Header Fields

| Field | Size | Description | Security Relevance |
|---|---|---|---|
| Source Port | 16 bits | Ephemeral (1024-65535) or well-known port | Port hopping C2, source port 0 attacks |
| Destination Port | 16 bits | Service port (22 SSH, 80 HTTP, 443 HTTPS...) | Service identification |
| Sequence Number | 32 bits | Byte position of first byte in this segment | Sequence prediction, session hijacking |
| Acknowledgment Number | 32 bits | Next byte expected from sender | State tracking |
| Data Offset | 4 bits | Header length in 32-bit words (5 = 20 bytes) | Options parsing |
| Reserved | 3 bits | Must be zero | Covert channel if set |
| Flags | 9 bits | URG, ACK, PSH, RST, SYN, FIN + ECE, CWR, NS | Scan detection, firewall rules, evasion |
| Window Size | 16 bits | Receive buffer space available | Flow control, fingerprinting (TCP window = 65535 on some OS) |
| Checksum | 16 bits | Covers pseudo-header + header + data | Data integrity |
| Urgent Pointer | 16 bits | Offset to urgent data when URG set | URG flag rarely used legitimately |
| Options | Variable | MSS, SACK, timestamps, window scaling, NOP | OS fingerprinting, p0f, nmap |

#### TCP Flags in Detail

```
URG — Urgent data present (Urgent Pointer is valid)
ACK — Acknowledgment number is valid
PSH — Push: deliver data to application immediately, don't buffer
RST — Reset: abort connection immediately
SYN — Synchronize: initiate connection, exchange ISNs
FIN — Finish: no more data from sender, begin graceful close
```

**Attack relevance:**
- **NULL scan** (no flags set): Closed ports send RST; open ports ignore
- **FIN scan**: Closed ports send RST; RFC-compliant open ports ignore
- **XMAS scan** (URG+PSH+FIN): Same logic as FIN scan
- **RST injection**: Forge RST with correct sequence number → terminate a session (used in censorship, BGP session attacks)
- **ACK scan**: Firewalls that pass established connections (ACK set) — used to map firewall rules

#### The 3-Way Handshake

```
Client                    Server
  |                          |
  |------ SYN (ISN=1000) --->|  Client picks random ISN
  |                          |
  |<-- SYN-ACK (ISN=5000) --|  Server ACKs client ISN+1, sends own ISN
  |      ACK=1001            |
  |                          |
  |------- ACK=5001 -------->|  Client ACKs server ISN+1
  |                          |  Connection ESTABLISHED
```

**ISN (Initial Sequence Number)**: Should be cryptographically random per RFC 6528. Predictable ISNs allowed session hijacking on early TCP stacks. Sequence number space is 32-bit (wraps at ~4 billion).

**SYN flood attack**: Attacker sends thousands of SYN packets with spoofed source IPs. Server allocates state for each SYN (half-open connection in SYN_RECEIVED), fills connection table, legitimate connections are rejected. Mitigation: **SYN cookies** — encode state in ISN rather than allocating per connection; only validate when ACK arrives.

**Security detection**: High rate of SYN packets without completing handshake = SYN flood indicator. Threshold alert: >1000 half-open connections in 10s.

#### 4-Way Termination

```
Client                    Server
  |---- FIN (seq=A) -------->|  Client done sending
  |<--- ACK (ack=A+1) -------|  Server acknowledges
  |<--- FIN (seq=B) ---------|  Server done sending
  |---- ACK (ack=B+1) ------>|  Client acknowledges
  |                           |
  |  Client enters TIME_WAIT  |  (waits 2x MSL = ~60-120s)
```

TIME_WAIT prevents old duplicate segments from being mistaken for new connections.

#### TCP States

| State | Description | Attack Relevance |
|---|---|---|
| LISTEN | Server waiting for connection | Service discovery |
| SYN_SENT | Client sent SYN, waiting for SYN-ACK | Port scan |
| SYN_RECEIVED | Server sent SYN-ACK, waiting for ACK | SYN flood victim state |
| ESTABLISHED | Full connection active | Normal traffic |
| FIN_WAIT_1 | Sent FIN, waiting for ACK or FIN | Graceful close initiated |
| FIN_WAIT_2 | FIN ACKed, waiting for FIN from remote | Half-close state |
| TIME_WAIT | Both FINs exchanged, waiting 2xMSL | Port reuse timing |
| CLOSE_WAIT | Remote sent FIN, local hasn't closed yet | Application not closing sockets |
| LAST_ACK | Sent FIN after CLOSE_WAIT, waiting for final ACK | |
| CLOSED | No connection | |

**CLOSE_WAIT accumulation**: If `ss -s` shows many CLOSE_WAIT connections, an application is failing to close sockets — potential resource exhaustion or connection leak.

#### TCP Options and OS Fingerprinting

TCP options are sent in the SYN packet and reveal OS fingerprint details:

| Option | Code | Description |
|---|---|---|
| MSS | 2 | Maximum Segment Size — negotiated MTU minus headers |
| SACK Permitted | 4 | Selective ACK — retransmit only lost segments |
| Timestamps | 8 | RTT measurement; also used for PAWS (Protect Against Wrapped Seq) |
| Window Scale | 3 | Multiply window size by 2^n for high-bandwidth links |
| NOP | 1 | Padding |

`p0f` uses the combination of MSS, window size, window scale, SACK, timestamps, and TTL to identify OS passively. `nmap -O` does it actively with probes.

---

### UDP (User Datagram Protocol)

UDP is connectionless — 8 bytes, no handshake, no state, no guaranteed delivery. This simplicity is both its strength (low latency) and why it creates distinct security challenges.

#### UDP Header

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

Only 4 fields. Checksum is optional in IPv4 (zero = unchecked), mandatory in IPv6.

#### Why UDP Matters for Security

**Amplification attacks**: UDP's connectionless nature enables reflection attacks. An attacker spoofs the victim's source IP and sends a small request to a public server; the large response goes to the victim.

| Protocol | Port | Amplification Factor | Attack Name |
|---|---|---|---|
| DNS | 53 | 28-54x (ANY record) | DNS amplification |
| NTP | 123 | 556x (monlist command) | NTP amplification |
| SSDP | 1900 | 30x | SSDP reflection |
| Memcached | 11211 | 10,000-51,000x | Memcached amplification |
| TFTP | 69 | Variable | TFTP amplification |

Mitigation: BCP38 (ingress filtering — drop packets with spoofed source IPs at ISP level), rate limiting, disable unnecessary UDP services.

**Stateless = harder to filter**: A stateless firewall with `permit udp any any eq 53` lets all UDP/53 pass both directions. A stateful firewall tracks the outbound query and only permits the matching response. Without stateful inspection, UDP-based protocols are nearly impossible to filter precisely.

**C2 over UDP**: QUIC (HTTP/3) runs over UDP and is encrypted. Many NDR/proxy solutions struggle to inspect QUIC traffic. Attackers increasingly use QUIC or DNS-over-HTTPS to blend with legitimate traffic.

**UDP port scanning**: Nmap `-sU` is slow because closed UDP ports return ICMP port unreachable (Type 3, Code 3), but firewalls often rate-limit ICMP, causing false "open|filtered" results.

---

### ICMP (Internet Control Message Protocol)

ICMP carries network error and diagnostic messages. It operates at Layer 3 (inside IP packets, Protocol 1) but is distinct from TCP/UDP.

#### Common ICMP Type/Code Pairs

| Type | Code | Name | Security Relevance |
|---|---|---|---|
| 0 | 0 | Echo Reply | Ping response; host discovery |
| 3 | 0 | Dest Unreachable — Net | Network not reachable; route black hole |
| 3 | 1 | Dest Unreachable — Host | Host down or filtered |
| 3 | 3 | Dest Unreachable — Port | UDP port closed; used in UDP port scanning |
| 3 | 13 | Dest Unreachable — Filtered | Firewall reject rule (polite RST equivalent) |
| 5 | 0 | Redirect — Network | Router redirect (route manipulation attack) |
| 5 | 1 | Redirect — Host | Router redirect |
| 8 | 0 | Echo Request | Ping; host discovery (nmap -sn) |
| 11 | 0 | Time Exceeded — TTL | Traceroute response from intermediate routers |
| 11 | 1 | Time Exceeded — Frag | Fragment reassembly timeout |
| 12 | 0 | Parameter Problem | Malformed IP header |

#### ICMP in Attack Workflows

**Host discovery**: `nmap -sn -PE 10.0.0.0/24` sends ICMP Echo Requests. Many hosts respond even when TCP ports are filtered. On Windows, ICMP is allowed by default from the local subnet.

**Traceroute mechanics**: Linux traceroute sends UDP probes with incrementing TTL (1, 2, 3...). When TTL reaches zero at a router, the router sends ICMP Time Exceeded (Type 11) back. Windows tracert uses ICMP Echo Requests. The source IP of the ICMP reply reveals each hop.

**ICMP tunneling**: ICMP Echo payload is arbitrary data (up to ~65,000 bytes). Tools like `ptunnel` and `icmptunnel` embed TCP sessions inside ICMP Echo packets, bypassing firewalls that only allow ICMP. Detection: large ICMP payloads (normal ping = 32-64 bytes), high ICMP request/reply rate, non-sequential ICMP IDs.

**ICMP redirect attack**: Type 5 ICMP Redirect tells a host "use this router instead for that destination." Attacker sends forged redirects → victim sends traffic through attacker's machine. Modern OS kernels ignore ICMP redirects by default (`net.ipv4.conf.all.accept_redirects = 0` in Linux).

**Smurf attack** (historical): Attacker sends ICMP Echo Request to subnet broadcast address with spoofed source = victim IP. Every host replies to victim → amplification DDoS. Mitigated by disabling directed broadcast on routers (`no ip directed-broadcast` in Cisco IOS).

---

## Ethernet & Layer 2

Layer 2 is the most dangerous and least monitored layer in most enterprise networks. Attacks here can intercept traffic before it ever reaches Layer 3 controls.

### MAC Addresses

A MAC address is a 48-bit (6-byte) Layer 2 identifier, typically written as `AA:BB:CC:DD:EE:FF`.

**Structure:**
```
AA:BB:CC | DD:EE:FF
OUI (first 24 bits) | NIC-specific (last 24 bits)

Bit 0 of first byte:
  0 = Unicast
  1 = Multicast / Broadcast (FF:FF:FF:FF:FF:FF = broadcast)

Bit 1 of first byte:
  0 = Globally unique (burned-in, OUI-assigned)
  1 = Locally administered (randomized, virtual)
```

**OUI lookup**: The first 24 bits identify the vendor. Apple, Intel, Cisco MACs are recognizable.
```bash
curl -s https://api.macvendors.com/AA:BB:CC
```

**CAM table (Content Addressable Memory)**: A switch learns MAC→port mappings by observing source MACs of incoming frames. Entries expire after ~300 seconds of inactivity. When a destination MAC is unknown, the switch **floods** the frame to all ports (except the source) — this is "unknown unicast flooding."

**MAC flooding attack**: Fill the CAM table with bogus MAC addresses (e.g., `macof` / `ettercap`). When the table is full, the switch floods all frames to all ports — the attacker on any port sees all traffic (switch becomes a hub). Mitigation: **Port Security** — limit MAC addresses per port, shut down on violation.

**MAC randomization**: Modern iOS, Android, and Windows 11 randomize MAC addresses per SSID to prevent tracking. Impact on NAC: MAC-based ACLs and 802.1X MAB bypass become less reliable as a tracking mechanism but are still used in enterprise onboarding.

---

### ARP (Address Resolution Protocol)

ARP resolves Layer 3 IPv4 addresses to Layer 2 MAC addresses. It operates at Layer 2.5 — encapsulated in Ethernet frames (EtherType 0x0806), but logically bridges Layer 2 and Layer 3.

#### How ARP Works

```
Host A (192.168.1.100) wants to reach 192.168.1.1 (gateway):

1. ARP Request (broadcast):
   Src MAC: AA:BB:CC:11:22:33
   Dst MAC: FF:FF:FF:FF:FF:FF  ← broadcast
   "Who has 192.168.1.1? Tell 192.168.1.100"

2. ARP Reply (unicast):
   Src MAC: DD:EE:FF:44:55:66
   Dst MAC: AA:BB:CC:11:22:33
   "192.168.1.1 is at DD:EE:FF:44:55:66"

3. Host A caches: 192.168.1.1 → DD:EE:FF:44:55:66
   Cache entry expires in 60–300s (OS-dependent)
```

ARP cache inspection:
```bash
arp -a          # Windows and Linux
ip neigh show   # Linux (preferred)
```

#### ARP Poisoning (ARP Spoofing)

ARP has **no authentication**. Any host can send ARP replies claiming any IP-to-MAC mapping. A **gratuitous ARP** is an unsolicited ARP reply (used legitimately for HSRP/VRRP failover and IP conflict detection).

**Attack flow (MITM via ARP poisoning)**:
```
Attacker tells Victim: "192.168.1.1 (gateway) is at MY MAC"
Attacker tells Gateway: "192.168.1.100 (victim) is at MY MAC"
→ All traffic flows: Victim → Attacker → Gateway (attacker can read/modify)
```

```bash
# Using arpspoof (dsniff package)
echo 1 > /proc/sys/net/ipv4/ip_forward   # Enable forwarding so traffic still flows
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Poison victim
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Poison gateway

# Using Bettercap
bettercap -iface eth0
net.probe on
arp.spoof on
```

**Detection**:
- Duplicate IP entries in ARP table: `arp -a | sort` — same IP, two MACs
- `arpwatch` daemon: alerts on MAC changes for known IPs
- XDR/NDR: correlation of ARP traffic patterns
- Wireshark: `arp.duplicate-address-detected` display filter
- DHCP snooping + Dynamic ARP Inspection (DAI) on managed switches — drops ARP packets that don't match the DHCP binding table

**ATT&CK**: T1557.002 — ARP Cache Poisoning

---

### VLANs (802.1Q)

VLANs logically segment a physical switch into multiple isolated broadcast domains. A switch port is configured as either **access** (one VLAN, untagged) or **trunk** (multiple VLANs, 802.1Q tagged).

#### 802.1Q Tag Structure

An 802.1Q tag is inserted between the source MAC and EtherType field:
```
+--------+--------+--------+--------+--------+--------+
| Dst MAC (6B) | Src MAC (6B) | 0x8100 | Tag | EtherType | Payload |
                                TPID  |PCP|D|  VID  |
                                      3b  1b  12b
```

- **TPID**: 0x8100 — identifies 802.1Q frame
- **PCP** (Priority Code Point): 3 bits, 802.1p QoS priority (0-7)
- **DEI** (Drop Eligible Indicator): 1 bit
- **VID** (VLAN ID): 12 bits, values 0-4095 (0 and 4095 reserved; 1 is default)

#### Trunk and Access Ports

- **Access port**: Assigned to one VLAN. Switch adds the VLAN tag internally but sends frames **untagged** to the device. End devices (PCs) don't need to understand VLANs.
- **Trunk port**: Carries multiple VLANs. Frames are **tagged** with their VLAN ID. Used between switches and between switches and routers.
- **Native VLAN**: On a trunk port, one VLAN's traffic is sent **untagged** (default: VLAN 1). This is a security risk.

#### VLAN Hopping Attacks

**Attack 1: Switch spoofing (DTP negotiation)**

Dynamic Trunking Protocol (DTP) allows switches to automatically negotiate trunk ports. An attacker on an access port sends DTP packets pretending to be a switch.

```bash
# Yersinia tool
yersinia dtp -attack 1   # Negotiate trunk

# If successful, attacker gets access to all VLANs
```

Mitigation:
```
switchport mode access          ! Disable DTP negotiation
switchport nonegotiate          ! Disable DTP explicitly
```

**Attack 2: Double tagging**

The attacker's frame has TWO 802.1Q tags:
- Outer tag = Native VLAN (e.g., VLAN 1)
- Inner tag = Target VLAN (e.g., VLAN 100)

The first switch strips the outer tag (native VLAN is untagged) and forwards the frame with the inner tag still intact. The second switch sees VLAN 100 and delivers the frame there.

**Limitation**: Double tagging is one-way only (attacker cannot receive replies from the target VLAN).

Mitigation:
```
! Change native VLAN to an unused VLAN (not VLAN 1)
switchport trunk native vlan 999

! Tag the native VLAN explicitly
vlan dot1q tag native

! Or simply disable trunk on access ports
```

**ATT&CK**: T1599 — Network Boundary Bridging; T1599.001 — VLAN Hopping

---

### Spanning Tree Protocol (STP/RSTP)

STP (IEEE 802.1D) prevents Layer 2 broadcast loops by electing one switch as **root bridge** and blocking redundant paths. Without STP, a loop would cause a broadcast storm that saturates the network in seconds.

#### How STP Works

1. **Root Bridge Election**: All switches exchange BPDUs (Bridge Protocol Data Units). The switch with the lowest **Bridge ID** (priority + MAC address) becomes root. Default priority: 32768.
2. **Root Port Selection**: Each non-root switch picks the port with lowest cost to root bridge.
3. **Designated Port**: Each network segment has one designated port (best path to root).
4. **Blocked Ports**: All others — forward BPDU only, not data frames.
5. **Port states**: Blocking → Listening → Learning → Forwarding (convergence ~30-50s for STP; RSTP is much faster, ~1-6s).

#### BPDU Structure (Key Fields)

| Field | Purpose |
|---|---|
| Root Bridge ID | Who the sender thinks is root |
| Root Path Cost | Cost from sender to root |
| Bridge ID | Sender's own Bridge ID |
| Port ID | Which port the BPDU came from |
| Message Age | How many hops from root |

#### STP Attacks

**Root bridge injection**: Attacker sends BPDUs with Bridge Priority = 0 (lower than any legitimate switch). Switches re-elect attacker as root bridge. All traffic passes through attacker's path → MITM.

```bash
yersinia stp -attack 4   # Send STP config BPDUs to become root
```

**BPDU flood**: Send thousands of BPDUs → constant STP reconvergence → DoS (traffic interrupted while STP reconverges).

**Mitigation**:
```
! BPDU Guard: shutdown port if a BPDU is received (for access ports)
spanning-tree bpduguard enable   ! Per-port
spanning-tree portfast bpduguard default   ! Global (all PortFast ports)

! Root Guard: ignore superior BPDUs (for distribution/uplink ports)
spanning-tree guard root

! PortFast: skip Listening/Learning for access ports (connect PCs faster)
spanning-tree portfast
```

**ATT&CK**: T1563 — Remote Service Session Hijacking (STP manipulation enables MITM); Network DoS (BPDU flood).

---

## Routing

### Static vs Dynamic Routing

**Static routes**: Manually configured, zero overhead, no convergence — if the path fails, traffic drops. Used for stub networks, default routes, and point-to-point links.

```bash
# Cisco IOS
ip route 10.0.0.0 255.0.0.0 192.168.1.1    # To reach 10/8, use next-hop 192.168.1.1
ip route 0.0.0.0 0.0.0.0 192.168.1.254     # Default route

# Linux
ip route add 10.0.0.0/8 via 192.168.1.1
ip route add default via 192.168.1.254
```

**Longest prefix match**: The router uses the most specific matching route. A route for 10.10.10.0/24 wins over 10.0.0.0/8 for a destination of 10.10.10.5. Attackers exploit this by injecting more-specific routes to steal traffic.

---

### OSPF (Open Shortest Path First)

OSPF is a link-state Interior Gateway Protocol (IGP) using Dijkstra's Shortest Path First algorithm. It's the most common enterprise routing protocol.

#### OSPF Key Concepts

- **Area 0 (backbone)**: All other areas must connect to Area 0. Reduces LSA flooding scope.
- **LSA types**: Routers flood Link State Advertisements describing their connections.
  - Type 1 (Router LSA): Intra-area, describes router's links
  - Type 2 (Network LSA): Generated by Designated Router (DR) for multi-access segments
  - Type 3 (Summary LSA): Inter-area summary routes from ABR
  - Type 5 (AS External LSA): Routes redistributed from other protocols (eBGP, static)
- **DR/BDR election**: On broadcast segments (Ethernet), one router is Designated Router to reduce flooding. Router with highest OSPF priority wins (default: 1); tie-break = highest Router ID.
- **Metrics**: Cost = 10^8 / interface bandwidth. Gigabit = cost 1; Fast Ethernet = cost 10.

#### OSPF Adjacency States

```
Down → Init → 2-Way → ExStart → Exchange → Loading → Full
```

- **2-Way**: Both routers see each other in Hello packets (bidirectional communication confirmed)
- **ExStart**: Negotiate master/slave for database exchange (higher Router ID = master)
- **Exchange**: Exchange DBD (Database Description) packets — summary of LSDB
- **Loading**: Request missing LSAs (LSR/LSU/LSAck)
- **Full**: Synchronized — routing can begin

#### OSPF Security

**Authentication** (prevent rogue router injection):
```
! MD5 authentication (prefer SHA in modern deployments)
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 SecurePassword
 ip ospf authentication message-digest

! SHA-256 (OSPFv3 + IPsec, or IOS-XE OSPF authentication)
router ospf 1
 area 0 authentication message-digest
```

**Attack — OSPF LSA injection**: If an attacker can speak OSPF (no authentication, or authentication cracked), they inject LSAs claiming to be a router. This can black-hole traffic, redirect traffic through the attacker, or cause route table corruption. Tools: `loki` (OSPF attack framework), scapy.

**Detection**: Unexpected Router ID in OSPF neighbor table, route table changes, OSPF authentication failures in syslog.

---

### BGP (Border Gateway Protocol)

BGP is the routing protocol of the internet — a path vector protocol that routes between Autonomous Systems (ASes). The global internet routing table has ~900,000+ prefixes.

#### BGP Fundamentals

- **AS (Autonomous System)**: A network under a single administrative control, identified by AS Number (ASN). ASNs are 16-bit (1-65535) or 32-bit (1-4294967295). Private: 64512-65534.
- **eBGP**: BGP between different ASes. TTL=1 by default (neighbor must be directly connected, unless EBGP multihop).
- **iBGP**: BGP within the same AS. Full mesh required or use route reflectors.
- **TCP port 179**: BGP sessions run over TCP. Full 3-way handshake, then BGP OPEN message.
- **BGP session types**: OPEN, UPDATE (route advertisements), NOTIFICATION (errors, teardown), KEEPALIVE (60s default, hold time 180s).

#### BGP Path Selection (simplified, in order)

1. Highest Weight (Cisco-specific, local only)
2. Highest LOCAL_PREF (prefer internal routes)
3. Locally originated (network command or redistribute)
4. Shortest AS_PATH
5. Lowest ORIGIN (IGP < EGP < Incomplete)
6. Lowest MED (Multi-Exit Discriminator)
7. eBGP over iBGP
8. Lowest IGP metric to next hop
9. Oldest eBGP route (tiebreaker)
10. Lowest Router ID

#### BGP Security and Hijacking

**BGP hijacking**: An AS originates a BGP prefix they don't own (or a more specific sub-prefix of someone else's prefix). Since BGP selects more-specific routes (longer prefix), the hijacker's announcement attracts traffic.

**Notable BGP hijack incidents:**
- **Pakistan Telecom / YouTube (2008)**: PTCL advertised 208.65.153.0/24 (more specific than YouTube's /22) → YouTube unreachable globally for ~2 hours
- **AWS / MyEtherWallet (2018)**: Hijack of Amazon's DNS IP block → DNS traffic redirected → cryptocurrency wallet theft
- **Rostelecom (2020)**: Russian ISP briefly hijacked routes for major US banks, cloud providers, and government services

**RPKI (Resource Public Key Infrastructure)**: Cryptographic validation that an AS is authorized to originate a prefix.
- **ROA (Route Origin Authorization)**: Signed certificate binding a prefix to an ASN
- **RPKI-valid route**: Prefix matches a ROA
- **RPKI-invalid route**: Prefix does NOT match ROA → should be dropped

```bash
# Check RPKI status for an IP
curl -s "https://api.bgpview.io/ip/8.8.8.8" | python3 -m json.tool | grep -A5 "rir_allocation"

# Check ROA for a prefix
curl -s "https://rpki-validator.ripe.net/api/v1/validity/15169/8.8.8.0/24"
```

**BGP security controls:**
- **RPKI + ROV (Route Origin Validation)**: Drop RPKI-invalid routes at border routers
- **Prefix filters**: Explicit allow-lists of expected prefixes from each peer
- **BGP communities**: Tag routes to influence propagation; don't rely on for security
- **max-prefix limits**: Shutdown session if peer sends too many prefixes (fat finger protection)
- **MD5 TCP authentication**: Prevents spoofed TCP RST attacks on BGP sessions (TTL security / GTSM is better)
- **BGPsec**: Cryptographic path validation (not widely deployed as of 2025)

**ATT&CK**: T1584.002 — DNS Server; T1599 — Network Boundary Bridging (BGP hijack used to intercept traffic at scale).

---

### NAT (Network Address Translation)

NAT translates IP addresses (and ports) as traffic crosses a boundary, enabling private addresses to reach the internet and allowing port-based load balancing.

#### NAT Types

**SNAT (Source NAT) / PAT (Port Address Translation) / Masquerade**:
Many internal IPs share one public IP. The firewall maintains a NAT translation table (source IP:port → public IP:translated port). Return traffic is un-translated using the table.

```
Internal: 192.168.1.100:54321 → Internet: 1.2.3.4:80
NAT translates: 192.168.1.100:54321 → 203.0.113.1:12345
Return: 1.2.3.4:80 → 203.0.113.1:12345 → un-NATed → 192.168.1.100:54321
```

**DNAT (Destination NAT) / Port Forwarding**:
Inbound traffic to a public IP:port is forwarded to an internal host. Used for self-hosted services and load balancers.

```
Internet: 203.0.113.1:443 → DMZ server: 10.0.1.5:443
```

#### NAT and Security

**Common misconception**: NAT is NOT a firewall. It provides implicit inbound blocking for outbound-initiated sessions, but:
- Port forwards expose internal hosts
- NAT does not filter malicious content — a NATed connection can carry malware
- Carrier-grade NAT (CGN, RFC 6598, 100.64.0.0/10) complicates attribution

**NAT traversal**: Protocols like SIP (VoIP), WebRTC, and some VPNs need to traverse NAT. Methods:
- **STUN** (Session Traversal Utilities for NAT): Discover public IP:port mapping
- **TURN** (Traversal Using Relays around NAT): Relay traffic through a TURN server when STUN fails
- **ICE** (Interactive Connectivity Establishment): Framework that tries direct, STUN, and TURN in order

Security relevance: STUN/TURN servers can be abused for C2 traffic traversal. VoIP STUN servers are often internet-facing and weakly authenticated.

---

## DNS (Domain Name System)

DNS is the phone book of the internet, but also one of the most abused protocols in security — used for C2, data exfiltration, amplification attacks, and phishing infrastructure.

### How DNS Works

**Resolution chain for `www.example.com`:**
```
Browser (stub resolver)
  ↓ 1. Check local cache / hosts file
  ↓ 2. Query recursive resolver (e.g., 8.8.8.8 or ISP resolver)
    ↓ 3. Recursive resolver queries root nameservers (.) → "ask .com TLD"
    ↓ 4. Recursive resolver queries .com TLD servers → "ask example.com NS"
    ↓ 5. Recursive resolver queries example.com authoritative NS → "93.184.216.34"
  ↓ 6. Recursive resolver returns answer, caches it per TTL
Browser connects to 93.184.216.34
```

**TTL (Time to Live)**: Controls caching duration. Low TTL (60-300s) = faster updates but more queries. Attackers lower TTL before changing C2 IP ("fast flux") to evade blocklists.

#### DNS Record Types

| Record | Purpose | Security Relevance |
|---|---|---|
| A | IPv4 address mapping | C2 infrastructure; IoC is the IP |
| AAAA | IPv6 address mapping | IPv6 C2, bypasses IPv4-only filtering |
| CNAME | Canonical name (alias) | Domain fronting, subdomain takeover |
| MX | Mail server | Email security; validate with SPF/DKIM/DMARC |
| TXT | Arbitrary text | SPF, DKIM, DMARC, domain verification, DNS tunneling payload |
| NS | Authoritative nameserver | Zone transfer target, delegation hijacking |
| PTR | Reverse DNS (IP → hostname) | Footprinting, spam reputation |
| SOA | Start of Authority | Zone admin info, serial number for AXFR |
| SRV | Service discovery | `_kerberos._tcp.domain.com` → AD, VoIP |
| CAA | Certification Authority Authorization | Restrict which CAs can issue certs for domain |
| DNSKEY | DNSSEC public key | DNSSEC validation |
| DS | Delegation Signer | DNSSEC chain of trust |
| TLSA | TLS cert association (DANE) | Pin cert to DNS, bypass CA system |

#### DNS Queries with dig

```bash
dig example.com A                      # A record
dig example.com MX                     # MX records
dig example.com TXT                    # TXT records (SPF, DKIM)
dig @8.8.8.8 example.com ANY          # All records, specific resolver
dig -x 93.184.216.34                   # Reverse DNS (PTR lookup)
dig example.com AXFR @ns1.example.com  # Zone transfer (often blocked)
dig +trace example.com                 # Trace full resolution chain
dig +short example.com                 # Output IP only
```

#### DNS over HTTPS (DoH) and DNS over TLS (DoT)

Traditional DNS is unencrypted on UDP/53 — visible to any network observer. DoH (port 443, HTTPS) and DoT (port 853, TLS) encrypt queries.

- **DoH**: Blends with HTTPS traffic; browsers can use it directly (bypassing OS resolver)
- **DoT**: Dedicated port 853; easier to block or inspect at enterprise

**Security implications for blue teams**: DoH bypasses DNS logging at the network layer. If an endpoint uses DoH to 8.8.8.8, your DNS server sees nothing. Solutions: block DoH servers at firewall (8.8.8.8:443 for DNS purposes), force DNS through a proxy (SSL inspection), or use endpoint DNS monitoring (EDR telemetry).

---

### DNS Security

#### DNS Amplification (Reflection + Amplification DDoS)

UDP/53 enables reflection: attacker sends a small query with spoofed source IP (victim's IP) to an open resolver. The resolver sends a large response to the victim.

```
Attacker (spoofed as victim) → Open Resolver: "ANY isc.org?" (40 bytes)
Open Resolver → Victim: DNSSEC-signed ANY response (4000+ bytes)
Amplification: ~100x
```

Mitigation:
- BCP38 / ingress filtering at ISPs (prevent spoofed source IPs from leaving)
- Rate limiting (RRL) on authoritative nameservers
- Disable recursive queries on authoritative servers (only allow from known clients)
- Disable DNSSEC ANY responses or return minimal responses

#### DNS Tunneling

Data can be encoded in DNS query labels and response payloads. Because DNS (UDP/53) is almost never blocked, it's used for C2 and data exfiltration through firewalls that allow DNS.

**How it works:**
```
# Exfil: encode "secret data" in subdomain labels
QLABELS: c2VjcmV0.ZGF0YQ.attacker-c2.com → resolver → attacker's NS
         (base32/64 encoded payload)

# C2 response: attacker's NS returns commands in TXT/CNAME/NULL records
```

**Tools**: `iodine` (TCP over DNS), `dnscat2` (encrypted C2 over DNS), `dns2tcp`, `DNSExfiltrator`

**Detection signals**:
- High query rate from a single host
- Long/random subdomain labels (entropy analysis)
- Queries for uncommon record types (NULL, TXT requests to external)
- Non-existent domain (NXDOMAIN) flood
- Large TXT responses from unusual domains
- Single parent domain receives many unique subdomains (not cached)

```bash
# Measure subdomain label length distribution
zeek: dns.log | awk '{print length($9)}' | sort -n | uniq -c

# Entropy analysis on DNS query names (high entropy = likely encoded)
python3 -c "
import math, collections
label = 'a7f3k9x2b8m1n4p'
freq = collections.Counter(label)
entropy = -sum((c/len(label))*math.log2(c/len(label)) for c in freq.values())
print(f'Entropy: {entropy:.2f}')  # Normal domains ~2.5; encoded ~4.5+
"
```

**ATT&CK**: T1071.004 — Application Layer Protocol: DNS; T1048.003 — Exfiltration Over Alternative Protocol; T1568.002 — Domain Generation Algorithms

#### DNS Hijacking

Attackers redirect DNS queries to malicious IP addresses:
- **Compromised resolver**: Attacker gains access to a recursive resolver (BGP hijack of DNS provider IPs, credential theft)
- **MITM on UDP/53**: ARP poison + DNS response injection (Responder, Ettercap)
- **Registrar compromise**: Change NS records at the domain registrar
- **ccTLD hijack**: Government-level control of country code TLD

#### DNSSEC

DNSSEC adds cryptographic signatures to DNS records. The chain of trust runs from the IANA root zone down to the authoritative nameserver.

- **RRSIG**: Signature over an RRset
- **DNSKEY**: Public key for a zone
- **DS (Delegation Signer)**: Hash of child zone's DNSKEY, stored in parent zone
- **NSEC/NSEC3**: Authenticated denial of existence (prevents enumeration with NSEC3)

DNSSEC prevents response forgery but does NOT encrypt queries (that's DoH/DoT). It is also complex to implement and a common source of outages when keys expire.

#### Subdomain Takeover

A CNAME points to an external service (e.g., GitHub Pages, Heroku, Azure) that has been deprovisioned. The subdomain is "dangling" — an attacker can claim the service and host content under the victim's domain.

```bash
# Find potential takeover: CNAME with NXDOMAIN target
dig sub.victim.com CNAME   # Returns: sub.victim.com → someapp.github.io
dig someapp.github.io       # NXDOMAIN → claimable!
```

Tools: `subjack`, `nuclei -t subdomain-takeover`, `dnsx`

**Impact**: Serve phishing pages under trusted domain, bypass CSP (same-origin content), steal cookies (if domain-scoped), issue TLS certificates (DV cert for sub.victim.com via ACME challenge).

---

## Switching & Network Devices

### Firewalls

#### Packet Filtering (Stateless)

Matches traffic against rules based on header fields only: source/destination IP, source/destination port, protocol. No connection state tracking.

```
Rule: permit tcp 10.0.0.0/8 any eq 443
Problem: Cannot distinguish legitimate HTTPS response from attacker sending packets 
         with destination port 443 (response side)
```

Used in: Router ACLs (Cisco IOS `access-list`), iptables raw table.

#### Stateful Inspection

Tracks the state of every TCP connection and UDP "pseudo-connection." Only permits return traffic that matches an established flow in the state table.

```
Client → Server: TCP SYN (firewall creates state entry: HALF-OPEN)
Server → Client: TCP SYN-ACK (state updates: HALF-OPEN → ESTABLISHED)
Server → Client: TCP data (matches established state → permitted)
Attacker → Client: TCP data (no state entry → DROPPED)
```

**State table exhaustion**: SYN flood or UDP flood can fill the state table → legitimate connections dropped. Mitigation: connection rate limits, SYN cookies on the firewall.

#### Next-Generation Firewall (NGFW)

Operates at Layer 7 with deep packet inspection (DPI):
- **Application identification**: Identifies applications by behavior, not just port (BitTorrent on port 443)
- **User identity**: Integrates with AD to enforce per-user policies
- **SSL/TLS inspection**: Decrypts, inspects, re-encrypts HTTPS traffic (requires trust root on endpoints)
- **URL filtering**: Block by category (malware, gambling, streaming)
- **Intrusion Prevention**: Inline signature matching on decrypted traffic

**Key NGFW concepts**:
- **Zones**: Logical groupings of interfaces (Trust, Untrust, DMZ, VPN)
- **Security policy**: Zone-based, evaluated top-down, implicit deny at end
- **NAT policy**: Separate from security policy in most NGFWs
- **DMZ architecture**: Internet → Perimeter FW → DMZ (web servers) → Internal FW → Core

#### Firewall Evasion

- **Fragmentation**: Split payload across multiple IP fragments to bypass signature matching
- **Protocol tunneling**: Encapsulate attack traffic in allowed protocol (HTTP, DNS, ICMP)
- **SSL/TLS without inspection**: If NGFW doesn't inspect TLS, all encrypted payloads bypass content inspection
- **Application mimicry**: C2 frameworks that mimic Slack, Teams, Dropbox traffic patterns (Cobalt Strike malleable C2 profiles)
- **IPv6**: Many firewalls have weaker IPv6 rule sets than IPv4

---

### IDS/IPS

#### NIDS vs NIPS

| | NIDS | NIPS |
|---|---|---|
| Placement | Passive (tap/SPAN port) | Inline (traffic must pass through) |
| Response | Alert only | Block and alert |
| Performance impact | Minimal (copies only) | Direct — adds latency |
| Failure mode | Fails open (traffic continues) | Can fail closed or open depending on config |

#### Detection Methods

**Signature-based**: Pattern match on known attack patterns. Fast, low FP rate, blind to unknown attacks (0-day, novel TTPs).

```
Suricata rule: alert tcp any any -> any 80 (msg:"SQL injection attempt"; 
content:"UNION SELECT"; http.uri; nocase; sid:1001;)
```

**Anomaly-based**: Build a baseline of normal behavior, alert on deviations. Can detect novel attacks, but high false positive rate during baseline drift, seasonal variation, or new deployments.

**Behavioral / ML-based**: Cluster network flows, identify outliers, use ML models. Better than simple anomaly for complex environments, requires substantial tuning.

#### IDS/IPS Evasion Techniques

| Technique | How It Works | Detection |
|---|---|---|
| Fragmentation | Split payload across fragments below IDS reassembly threshold | Reassemble at IDS; alert on excessive fragmentation |
| TTL manipulation | Craft packets with TTL that reaches IDS but not target; target ignores | Normalize TTL before inspection |
| Encryption | Encrypt C2/exfil; IDS can't read payload | SSL inspection, behavioral analysis |
| Slow scan | Scan below packets-per-second threshold | Longer time window correlation |
| Polymorphism | Vary payload encoding (XOR, base64 variants) | Normalize before matching; heuristic rules |
| Protocol abuse | Use header fields or options unexpectedly | Protocol anomaly detection |
| Decoys | Flood with noise while real attack proceeds | Prioritized alerting, SOC triage |

Tools for evasion testing: `nmap --data-length`, `fragroute`, `scapy` custom packets, `whisker` (web evasion).

---

### Network Access Control (NAC)

NAC enforces policy before devices can access the network — validating identity, posture (patch level, AV status), and role.

#### 802.1X — Port-Based Network Access Control

802.1X is the standard for authentication before network access is granted. The switch or wireless AP enforces the auth, but does not perform it — it relays to a RADIUS server.

```
Supplicant (PC)  ↔  Authenticator (Switch/AP)  ↔  Authentication Server (RADIUS)
    EAP messages        RADIUS messages
    over 802.1X
```

**EAP Methods** (Extensible Authentication Protocol):

| Method | Credential Type | Security |
|---|---|---|
| EAP-TLS | Client + server certificates | Strongest — mutual cert auth |
| PEAP-MSCHAPv2 | Username + password (inside TLS tunnel) | Common, but MSCHAPv2 is weak if server cert not validated |
| EAP-TTLS | Flexible inner method inside TLS tunnel | More flexible than PEAP |
| EAP-FAST | Cisco; no cert required (PAC-based) | Easier deployment, lower security |

**PEAP-MSCHAPv2 attack**: If clients don't validate the server's TLS certificate, an attacker with Hostapd-WPE or `eaphammer` can impersonate the RADIUS server, capture the MSCHAPv2 challenge/response, and crack it offline with hashcat.

```bash
# Capture 802.1X credentials with eaphammer
eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWiFi --creds
# Then crack captured NTLMv2 hash with hashcat
hashcat -m 5600 captured.hash /usr/share/wordlists/rockyou.txt
```

**MAB (MAC Authentication Bypass)**: For non-802.1X devices (printers, IoT), the switch sends the device's MAC address as the credential to RADIUS. Since MAC addresses are unencrypted and spoofable, MAB is easily bypassed with `macchanger`.

**NAC Vendors**: Cisco ISE, Aruba ClearPass, Forescout eyeSight (agentless), Portnox Cloud.

---

## Wireless Networking — Security Fundamentals

### 802.11 Standards Overview

| Standard | Frequency | Max Speed | Security Relevance |
|---|---|---|---|
| 802.11b | 2.4 GHz | 11 Mbps | Legacy; WEP-era |
| 802.11g | 2.4 GHz | 54 Mbps | WPA era |
| 802.11n (WiFi 4) | 2.4/5 GHz | 600 Mbps | WPA2 common |
| 802.11ac (WiFi 5) | 5 GHz | ~3.5 Gbps | WPA2/WPA3 |
| 802.11ax (WiFi 6/6E) | 2.4/5/6 GHz | ~9.6 Gbps | WPA3, BSS coloring |

**2.4 GHz vs 5 GHz**: 2.4 GHz has longer range (penetrates walls) but more congestion (only 3 non-overlapping channels: 1, 6, 11). 5 GHz has shorter range but more channels and less interference. Evil twin attacks on 2.4 GHz reach more clients.

### WiFi Association Process

```
Client                          AP
  |                              |
  |------ Probe Request -------->|  Broadcast: "Any APs with SSID CorpWiFi?"
  |<----- Probe Response --------|  AP responds with capabilities
  |                              |
  |--- Open Authentication ----->|  (Or Shared Key for WEP — never use)
  |<--- Authentication ACK ------|
  |                              |
  |------ Association Req ------>|  Client requests association, specifies rates/cipher
  |<----- Association Resp ------|  AP accepts, assigns Association ID (AID)
  |                              |
  |<----- DHCP + EAP ----------->|  IP assignment + optional 802.1X
  |                              |
  |====== Data traffic ==========|
```

### WPA2 — How It Actually Works

WPA2-Personal (PSK) does not use the passphrase directly for encryption. The derivation chain is:

```
Passphrase + SSID → PBKDF2-SHA1 (4096 iterations) → PMK (256-bit)
PMK + ANonce + SNonce + AP MAC + Client MAC → PRF-512 → PTK (512-bit)
PTK split into: KCK (128-bit) + KEK (128-bit) + TK (128-bit) + MIC keys
```

**4-Way Handshake** (after authentication):
```
AP → Client:   Message 1: ANonce (AP's random nonce)
Client → AP:   Message 2: SNonce + MIC (client derives PTK, sends SNonce)
AP → Client:   Message 3: GTK (Group Temporal Key) encrypted with KEK + MIC
Client → AP:   Message 4: ACK
→ Both sides now have PTK (unicast) and GTK (broadcast/multicast)
```

**PMKID attack**: The PMKID (a hash of the PMK + MACs) is transmitted in Message 1 of the 4-way handshake. Captured without a client needing to connect — offline dictionary attack against the passphrase.

```bash
# Capture PMKID
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1
# Convert and crack
hcxpcapngtool -o hash.hc22000 capture.pcapng
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

### WPA3 — Improvements

WPA3-Personal replaces PSK with **SAE (Simultaneous Authentication of Equals)**, based on Dragonfly key exchange (Diffie-Hellman variant):
- No PMK derived from passphrase — each session derives a unique PMK
- **Forward secrecy**: Compromising the passphrase doesn't decrypt past traffic
- **Offline dictionary attack protection**: Requires online interaction per guess (rate-limited)
- Vulnerabilities found: Dragonblood (2019) — timing and cache side-channels in some implementations

### WPA2-Enterprise

Uses 802.1X + RADIUS. The passphrase is per-user credentials. Security depends on:
- Server certificate validation by clients (prevent evil twin RADIUS impersonation)
- Strong EAP method (EAP-TLS >> PEAP-MSCHAPv2)
- Rogue AP detection (WIDS/WIPS)

### Wireless Capture

```bash
# Put interface in monitor mode
airmon-ng start wlan0           # Creates wlan0mon
iwconfig wlan0 mode monitor     # Alternative

# Capture traffic on specific channel
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Capture on all channels (channel hopping)
airodump-ng wlan0mon

# Deauth attack to force reconnection (capture 4-way handshake)
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon

# Evil twin / hostapd-based rogue AP
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

**ATT&CK**: T1465 — Rogue Wi-Fi Access Points; T1040 — Network Sniffing; T1557 — MITM

---

## Network Troubleshooting Commands — Security Context

Every command below has security relevance beyond basic troubleshooting. Know what each reveals and why an attacker or defender would run it.

```bash
# ============================================================
# LAYER 3 CONNECTIVITY
# ============================================================

# ICMP echo test — also confirms host is up and ICMP isn't blocked
ping -c 4 8.8.8.8
ping -c 4 -s 1472 8.8.8.8     # Test MTU (1472+28 header = 1500 byte frame)

# Path discovery — reveals routing hops, intermediate IPs (footprinting)
traceroute -n 8.8.8.8          # Linux: UDP probes, -n skips reverse DNS
tracert -d 8.8.8.8             # Windows: ICMP probes, -d skips DNS
traceroute -T -p 443 8.8.8.8   # TCP traceroute on port 443 (bypass ICMP block)

# MTU path discovery
ping -M do -s 1472 gateway_ip  # Linux: DF-bit set, detect MTU
pathping 8.8.8.8               # Windows: combines ping + tracert statistics

# ============================================================
# DNS QUERIES
# ============================================================

nslookup -type=MX domain.com               # MX records (mail servers)
dig domain.com ANY @8.8.8.8               # All records via Google DNS
dig -x 8.8.8.8                            # Reverse DNS (PTR lookup)
dig +trace domain.com                     # Full resolution trace
dig domain.com AXFR @ns1.domain.com       # Zone transfer attempt
host domain.com                           # Simple, readable output
dig domain.com TXT | grep spf            # SPF record
nmap --script dns-brute domain.com        # DNS subdomain brute force

# ============================================================
# NETWORK STATE (CRITICAL FOR INCIDENT RESPONSE)
# ============================================================

# Windows: all connections with PID — find what process owns a connection
netstat -ano
netstat -ano | findstr ESTABLISHED        # Active connections only
netstat -ano | findstr :443               # Specific port

# Linux: better than netstat — faster, more detail
ss -tlnp                                  # TCP listening with process
ss -tunap                                 # TCP+UDP, all, numeric, with process
ss -o state established '( dport = :443 or sport = :443 )'  # HTTPS connections

# Routing table — where does traffic go?
netstat -rn                               # Windows + Linux
ip route show                             # Linux (preferred)
ip route get 8.8.8.8                      # Which route will be used for a destination

# ARP cache — who is on the local segment
arp -a                                    # Windows + Linux
ip neigh show                             # Linux (preferred)
ip neigh show | grep -v REACHABLE         # Find stale or incomplete entries

# ============================================================
# PACKET CAPTURE (WIRESHARK COMPANION)
# ============================================================

# Basic capture — first step in any network investigation
tcpdump -i eth0 -n -c 100

# Targeted captures
tcpdump -i eth0 'tcp port 443 and host 1.2.3.4'   # Specific host+port
tcpdump -i eth0 'not port 22'                      # Exclude SSH noise
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'    # SYN packets only
tcpdump -i eth0 arp                                # ARP traffic (detect poisoning)
tcpdump -i eth0 icmp                               # ICMP traffic

# Save to file for Wireshark analysis
tcpdump -w /tmp/capture.pcap -i eth0 -G 3600 -W 24  # Rotate hourly, keep 24 files

# Wireshark display filters (not capture filters)
# tcp.flags.syn==1 && tcp.flags.ack==0    → SYN packets (scan/handshake start)
# arp.duplicate-address-detected          → ARP poisoning indicator
# dns.qry.name contains "."              → Potential DNS tunneling (long names)
# http.request.method == "POST"           → POST requests (data submission)
# tls.handshake.type == 1                → TLS ClientHello (new TLS connections)

# ============================================================
# PORT SCANNING (RECON)
# ============================================================

nmap -sS -p 1-65535 target              # SYN scan all ports (stealth)
nmap -sV -sC -p 22,80,443,8080 target   # Version + default scripts
nmap -sU -p 53,161,500,4500 target      # UDP scan common ports
nmap -O target                          # OS detection (TTL, TCP options)
nmap -A -T4 target                      # Aggressive: OS + version + scripts + traceroute
nmap -sn 10.0.0.0/24                   # Ping sweep (host discovery)
nmap --script vuln target              # Vulnerability scripts
nmap -sS --script banner target        # Grab banners

# Masscan — much faster for large ranges (does not do version detection)
masscan -p1-65535 10.0.0.0/16 --rate=1000 -oG masscan.out

# ============================================================
# INTERFACE INFORMATION
# ============================================================

ip addr show                            # Linux: interface IPs + MACs
ip link show                            # Linux: interface status (up/down, MTU)
ifconfig                                # Legacy Linux / macOS
ipconfig /all                           # Windows: full interface details
ip -s link                              # Linux: interface statistics (errors, drops)
ethtool eth0                            # Linux: NIC speed, duplex, driver info

# ============================================================
# FIREWALL RULES
# ============================================================

iptables -L -n -v --line-numbers        # Linux: iptables rules with packet counts
iptables -t nat -L -n -v               # NAT rules
ip6tables -L -n -v                     # IPv6 rules (often neglected!)
nft list ruleset                        # nftables (replaces iptables on modern Linux)
ufw status verbose                      # Ubuntu UFW
firewall-cmd --list-all                 # firewalld (RHEL/CentOS)

# Windows
netsh advfirewall show allprofiles     # Windows firewall state
netsh advfirewall firewall show rule name=all  # All rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}  # PowerShell

# ============================================================
# VPN AND TUNNELS
# ============================================================

ip tunnel show                          # Linux: active tunnels
ip -d link show type gre               # GRE tunnels
ip -d link show type vxlan             # VXLAN overlays
ss -tlnp | grep -E '1194|4500|500'    # OpenVPN/IPsec ports listening
wg show                                # WireGuard status
```

---

## Network Security Architecture

### Defense in Depth — Layered Model

```
Internet
    |
[DDoS Scrubbing / Upstream Provider] ← ISP-level volumetric mitigation
    |
[Edge Router] ← BGP filtering, BCP38, prefix validation, RPKI
    |
[Perimeter Firewall / NGFW] ← Stateful inspection, IPS, SSL inspection, URL filter
    |
+--[DMZ]--+
|  Web    |  ← Public-facing servers, reverse proxies, WAF
|  Servers|
+---------+
    |
[Internal Firewall] ← Strict DMZ → Core rules, micro-segmentation
    |
+--[Core Network]--------+
|  AD/LDAP  | DNS  | NTP | ← Critical services, isolated subnet
+-----------+------+-----+
    |
+--[Workstation Segment]--+    +--[Server Segment]--+    +--[IoT/OT]--+
| Endpoints (NAC, 802.1X)  |    | App/DB servers     |    | Isolated   |
+--------------------------+    +--------------------+    +------------+
```

### Traffic Flow and Security Controls

**North-South traffic** (client ↔ server, crossing perimeter):
- Inspected at perimeter firewall
- WAF for web traffic
- SSL inspection for HTTPS
- Proxy for outbound browsing (URL filtering, malware inspection)
- DLP at egress (data exfiltration detection)

**East-West traffic** (server ↔ server, internal lateral movement):
- Often underinspected — switches forward without inspection
- Lateral movement path: compromise one server, pivot to others
- Controls: host-based firewall (Windows Defender Firewall, iptables), microsegmentation (VMware NSX, Illumio, Guardicore), VLAN isolation, internal IDS/NDR sensors

**Zero Trust overlay**:
- Every flow is authenticated and authorized regardless of network segment
- "Never trust, always verify" — being on the corporate network grants no implicit access
- Implementation: identity-aware proxy (BeyondCorp/IAP), ZTNA (Zscaler Private Access, Cloudflare Access, Palo Alto Prisma Access)

### Segmentation Principles

1. **Trust zones**: Define segments by risk level and data sensitivity (DMZ, workstation, server, OT, management)
2. **Communication matrix**: Document which zone talks to which — if it's not documented, it shouldn't be permitted
3. **Least connectivity**: Default deny between zones, explicit permit only for required flows
4. **Management plane isolation**: Out-of-band management network for switches, firewalls, routers (separate from data plane)
5. **Blast radius reduction**: Segment limits how far a compromise spreads — a compromised IoT device on a dedicated /28 can't reach domain controllers

### Key Network Security Controls Summary

| Control | Protects Against | Layer |
|---|---|---|
| VLAN segmentation | Broadcast domain isolation, lateral movement | L2 |
| Port security / Dynamic ARP Inspection | MAC flooding, ARP poisoning | L2 |
| BPDU Guard / Root Guard | STP attacks | L2 |
| 802.1X NAC | Unauthorized device access | L2/L3 |
| Stateful firewall | Unauthorized connections | L3/L4 |
| NGFW + IPS | Application-layer attacks, known exploits | L7 |
| SSL/TLS inspection | Encrypted C2, exfiltration in HTTPS | L6/L7 |
| WAF | OWASP Top 10, web application attacks | L7 |
| RPKI + BGP filters | BGP hijacking | L3 (routing) |
| DNSSEC + DNS filtering | DNS hijacking, C2 over DNS | L7 (DNS) |
| NDR/Network sensors | Anomaly detection, lateral movement | L3-L7 |
| Microsegmentation | East-West lateral movement | L3-L7 |
| DDoS scrubbing | Volumetric + protocol attacks | L3/L4 |

---

## ATT&CK Technique Quick Reference

| ATT&CK ID | Technique | Relevant Protocol / Layer |
|---|---|---|
| T1040 | Network Sniffing | All layers — requires physical/logical access |
| T1046 | Network Service Discovery | TCP/UDP scanning, nmap |
| T1048 | Exfiltration Over Alternative Protocol | DNS, ICMP, HTTP tunneling |
| T1071.001 | Web Protocols (C2) | HTTP/HTTPS — Layer 7 |
| T1071.004 | DNS (C2) | DNS tunneling — Layer 7 |
| T1090 | Proxy | SOCKS, HTTP proxy chaining |
| T1095 | Non-Standard Port | C2 on unusual ports |
| T1557 | Adversary-in-the-Middle | ARP poisoning, DHCP spoofing |
| T1557.002 | ARP Cache Poisoning | Layer 2 MITM |
| T1562.004 | Disable/Modify Firewall | iptables flush, Windows FW disable |
| T1563 | Remote Service Session Hijacking | TCP sequence injection |
| T1568 | Dynamic Resolution | Fast flux DNS, DGA |
| T1572 | Protocol Tunneling | ICMP tunnel, DNS tunnel |
| T1590 | Gather Victim Network Info | WHOIS, BGP, DNS enumeration |
| T1599 | Network Boundary Bridging | VLAN hopping, BGP hijack |

---

*Reference built for cybersecurity practitioners. Depth over brevity — understanding the mechanism is what enables security.*
