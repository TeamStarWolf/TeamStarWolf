# Packet Analysis Reference

A practitioner-level reference for reading raw network traffic, mastering Wireshark, tcpdump, and Zeek, and detecting attacks directly in packet captures.

---

## Reading Network Packets

### Anatomy of a Full Packet (Wireshark Field-by-Field)

Every frame captured on the wire is decoded in layers. Below is a complete TCP SYN packet with security notes on each field.

```
Frame 1: 74 bytes on wire
  Arrival Time: 2024-01-15 10:22:33.412819
  Frame Length: 74 bytes
  Capture Length: 74 bytes

Ethernet II
  Destination: 00:50:56:c0:00:08  (VMware)          ← gateway MAC — verify for ARP spoofing
  Source:      00:0c:29:ab:cd:ef  (VMware)          ← source MAC — track against DHCP leases
  Type: IPv4 (0x0800)

Internet Protocol Version 4
  Version: 4
  Header Length: 20 bytes
  DSCP: 0x00  (Default)
  Total Length: 60
  Identification: 0x1a2b                            ← OS fingerprinting: predictable vs random
  Flags: 0x40  (Don't Fragment)                     ← DF set: path MTU discovery; unset on fragments
    Reserved bit: 0
    Don't fragment: 1
    More fragments: 0
  Fragment Offset: 0
  Time to Live: 128                                 ← TTL 128=Windows, 64=Linux, 255=Cisco IOS
  Protocol: TCP (6)
  Header Checksum: 0x3c1d [correct]
  Source Address: 10.0.0.50
  Destination Address: 93.184.216.34

Transmission Control Protocol
  Source Port: 49152                                ← ephemeral port; range 49152-65535 = Windows
  Destination Port: 443
  Sequence Number: 0         (relative)             ← Wireshark shows relative; raw ISN is random
  Sequence Number (raw): 3482910823                 ← low-entropy ISN = old stack or predictable
  Acknowledgment Number: 0
  Header Length: 40 bytes (10 32-bit words)
  Flags: 0x002 (SYN)                                ← SYN only = connection initiation / port scan
    Congestion Window Reduced: 0
    ECN-Echo: 0
    Urgent: 0
    Acknowledgment: 0
    Push: 0
    Reset: 0
    Syn: 1
    Fin: 0
  Window Size Value: 64240                          ← 64240 = Windows default; 65535 = Linux; 0 = zero-window
  Checksum: 0x4c2d [correct]
  Urgent Pointer: 0
  Options: (20 bytes)
    Maximum Segment Size: 1460                      ← 1460 = standard Ethernet MSS
    No-Operation (NOP)
    Window Scale: 8 (multiply by 256)               ← Window scale present = modern OS
    No-Operation (NOP)
    No-Operation (NOP)
    SACK Permitted                                  ← SACK indicates modern TCP stack
    Timestamps: TSval 1234567, TSecr 0              ← Timestamp present = uptime fingerprinting possible
```

**Security notes on key fields:**

| Field | Attack Relevance |
|---|---|
| TTL | OS fingerprinting (128=Win, 64=Linux); TTL < 10 = many hops or crafted packet |
| DF flag | Fragmentation attacks set MF/fragment offset; legitimate traffic rarely fragments |
| Identification | Sequential IDs = idle scan target (Nmap -sI); random = modern stack |
| TCP flags | Abnormal combos (SYN+FIN, NULL, Xmas) indicate scanning or crafted probes |
| Window size | 0 = flow control issue or DoS; very small windows = slow loris type attacks |
| MSS | Mismatch between MSS and MTU can indicate tunneling |
| Source port | Ports < 1024 from client = raw socket / root process |

---

### TCP Handshake Dissection

**Frame 1 — SYN (Client → Server)**
```
TCP  49152 → 443  [SYN]  Seq=0  Win=64240
  Options: MSS=1460, SACK_PERM, Timestamps, NOP, WS=256
  ISN (raw): 3482910823
```
- `Seq=0` is Wireshark's relative sequence number (actual ISN is random)
- Client advertises capabilities: SACK, timestamps, window scaling
- Only SYN flag set — this is what Nmap SYN scan sends and expects RST back

**Frame 2 — SYN-ACK (Server → Client)**
```
TCP  443 → 49152  [SYN, ACK]  Seq=0  Ack=1  Win=65535
  Options: MSS=1452, SACK_PERM, Timestamps, NOP, WS=128
```
- Server acknowledges client ISN: `Ack = client_ISN + 1`
- Server advertises its own capabilities (may differ from client)
- MSS 1452 vs 1460 = server is behind a VPN/tunnel (extra header bytes)
- If SYN-ACK never arrives → filtered port; if RST arrives → closed port

**Frame 3 — ACK (Client → Server)**
```
TCP  49152 → 443  [ACK]  Seq=1  Ack=1  Win=131072 (after scaling)
```
- `Seq=1` because SYN consumed one sequence number
- `Ack=1` = client acknowledges server ISN
- No data yet — three-way handshake complete
- Window is now scaled: `64240 × 256 = 16,445,440 bytes` effective receive buffer

**Absolute vs relative sequence numbers:**
```
Wireshark default: relative (starts at 0 for readability)
Edit → Preferences → Protocols → TCP → uncheck "Relative sequence numbers"
→ shows raw ISNs like 3482910823
Useful for: correlating with IDS alerts that log raw sequence numbers
```

---

## Wireshark Mastery

### Statistics and Expert Analysis

**Statistics → Conversations**
Shows all unique IP pairs, packet counts, bytes, and duration. Use to:
- Identify top talkers (potential data exfil from internal host to single external IP)
- Find unusual pairs (workstation talking directly to a domain controller over unusual ports)
- Sort by bytes to spot large transfers
- Right-click any conversation → Apply as Filter → drill down

**Statistics → Protocol Hierarchy**
Percentage breakdown of all protocols in the capture. Key indicators:
- Low HTTPS% with high HTTP% = cleartext traffic
- High DNS% with low HTTP% = potential DNS tunneling
- Unknown/custom protocols at top level = potential encapsulation
- `data` protocol = unrecognized application layer (look closer)

**Statistics → IO Graphs**
Traffic rate over time (packets/sec or bytes/sec). Use to:
- Spot traffic bursts indicating scans or exfil
- Identify beaconing (regular peaks at consistent intervals)
- Add multiple filters as separate graph lines for comparison
- Compare `tcp.analysis.retransmission` vs total traffic to find congestion

**Statistics → Flow Graph**
Visual ladder diagram of TCP exchanges. Essential for:
- Verifying handshake completion
- Seeing RST injection timing
- Understanding request/response patterns

**Analyze → Expert Information**
Categorized list of anomalies Wireshark detected:
- **Errors**: Malformed packets, bad checksums
- **Warnings**: Retransmissions, out-of-order segments, window issues
- **Notes**: Keepalives, ACK to unseen segments
- **Chats**: Normal connection events (SYN, FIN, RST)

**Edit → Find Packet (Ctrl+F)**
Search by:
- Display filter: `http.request.uri contains "admin"`
- Hex value: find a specific byte sequence
- String: search payload for "password", "Authorization", credentials
- Regular expression: advanced pattern matching across packet bytes

---

### Display Filter Reference (Comprehensive)

```wireshark
# ── IP Filters ─────────────────────────────────────────────────────────────
ip.addr == 192.168.1.100              # src or dst
ip.src == 10.0.0.0/8                  # RFC 1918 source
ip.dst == 192.168.1.0/24              # subnet destination
ip.src == 10.0.0.0/8 && ip.dst != 10.0.0.0/8   # internal → external
ip.ttl < 10                           # low TTL: traceroute, many hops, crafted
ip.ttl == 1                           # likely traceroute probe
ip.flags.mf == 1                      # more fragments (fragmentation attack)
ip.frag_offset > 0                    # not-first fragment
!(ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16)  # public sources only

# ── TCP Analysis ────────────────────────────────────────────────────────────
tcp.analysis.retransmission           # retransmitted segments
tcp.analysis.out_of_order             # out-of-order (IDS evasion indicator)
tcp.analysis.zero_window              # window full (DoS or slow victim)
tcp.analysis.window_update            # window size changed
tcp.analysis.duplicate_ack            # duplicate ACKs (loss indicator)
tcp.flags.reset == 1                  # RST: port closed, session disrupted
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN only (scan or connect attempt)
tcp.flags.syn == 1 && tcp.flags.ack == 1    # SYN-ACK (open ports)
tcp.flags == 0x000                    # NULL scan (no flags)
tcp.flags == 0x029                    # Xmas scan (FIN+URG+PSH)
tcp.flags.fin == 1 && tcp.flags.syn == 1    # invalid SYN+FIN combo
tcp.dstport == 445 || tcp.dstport == 139    # SMB traffic
tcp.dstport < 1024 && ip.src == 192.168.1.0/24  # internal → privileged ports

# ── UDP ─────────────────────────────────────────────────────────────────────
udp.dstport == 53                     # DNS queries
udp.length > 512                      # large UDP (amplification, tunneling)

# ── DNS Filters ─────────────────────────────────────────────────────────────
dns.qry.name contains "attacker"      # known bad domain
dns.qry.type == 255                   # ANY queries (amplification attack setup)
dns.qry.type == 16                    # TXT queries (often used for tunneling)
dns.qry.name matches "^[a-f0-9]{20,}" # high-entropy hex subdomains (tunneling)
dns.resp.ttl < 60                     # very low TTL (fast flux infrastructure)
dns.count.answers > 10                # many answers (possible amplification)
dns.resp.len > 512                    # large DNS response
!dns.flags.response && dns.qry.name  # queries only (no responses = one-sided view)
dns.flags.rcode != 0                  # DNS error responses (NXDOMAIN, SERVFAIL)

# ── HTTP/HTTPS ───────────────────────────────────────────────────────────────
http.request.method == "POST"         # form submissions, API calls, C2 callbacks
http.request.method == "GET"
http.response.code >= 400             # client/server errors
http.response.code == 200
http.request.uri contains "cmd"       # potential webshell
http.request.uri contains ".php?id="  # SQLi parameter
http.authbasic                        # basic auth (credentials in base64)
http.request.uri matches "(?i)(passwd|shadow|\.env|config)"  # sensitive file access
http contains "password"              # cleartext credential search
http.user_agent contains "sqlmap"     # scanner UA
http.user_agent contains "Nmap"       # Nmap HTTP probes

# ── TLS/SSL ─────────────────────────────────────────────────────────────────
tls.handshake.type == 1               # ClientHello
tls.handshake.type == 2               # ServerHello
tls.handshake.type == 11              # Certificate
tls.handshake.extensions_server_name contains "evil"  # SNI check
tls.record.version == 0x0300          # SSLv3 (insecure)
tls.record.version == 0x0301          # TLS 1.0 (deprecated)
tls.handshake.ciphersuite == 0x0035   # RSA/AES256/SHA (weak, no PFS)
!tls && tcp.dstport == 443            # non-TLS on 443 (anomalous)

# ── ARP ─────────────────────────────────────────────────────────────────────
arp                                   # all ARP
arp.opcode == 1                       # ARP requests
arp.opcode == 2                       # ARP replies
arp.duplicate-address-detected        # duplicate IP (ARP spoofing)
arp.isgratuitous                      # gratuitous ARP (can be legitimate or spoofing)
eth.src == ff:ff:ff:ff:ff:ff          # broadcast (likely ARP/DHCP)

# ── SMB ─────────────────────────────────────────────────────────────────────
smb || smb2                           # all SMB traffic
smb2.cmd == 5                         # SMB2 Create (file open/create)
smb2.filename contains "lsass"        # potential credential dumping
smb2.filename contains ".exe"         # executable transfer via SMB
smb2.filename contains "\\ADMIN$"     # admin share access
smb2.cmd == 14                        # SMB2 IoctlRequest (PsExec, named pipes)

# ── ICMP ─────────────────────────────────────────────────────────────────────
icmp                                  # all ICMP
icmp.type == 8                        # echo request (ping)
icmp.type == 0                        # echo reply
icmp.type == 3                        # destination unreachable
frame.len > 100 && icmp               # large ICMP (possible tunneling)

# ── Credentials ─────────────────────────────────────────────────────────────
ftp.request.command == "PASS"         # FTP password in cleartext
ftp.request.command == "USER"         # FTP username
telnet                                # all telnet (cleartext protocol)
pop.request.command == "PASS"         # POP3 password
imap contains "LOGIN"                 # IMAP login attempt
http.authbasic                        # HTTP basic auth
```

---

### TLS Decryption with SSLKEYLOGFILE

Modern TLS is unreadable without session keys. Browsers support exporting them.

**Setup (Linux/macOS):**
```bash
export SSLKEYLOGFILE=~/tlskeys.log
google-chrome &       # or firefox, curl with --tls-keylog
# Browse, then capture traffic
```

**Setup (Windows):**
```cmd
set SSLKEYLOGFILE=C:\tlskeys.log
start chrome
```

**Load keys in Wireshark:**
Edit → Preferences → Protocols → TLS → (Pre-)Master-Secret log filename → browse to `tlskeys.log`

The `tlskeys.log` format:
```
# Generated by NSS key log
CLIENT_RANDOM <client_random_hex> <master_secret_hex>
```

**With curl:**
```bash
curl --tls-keylog /tmp/keys.log https://target.com -v
```

After loading keys, HTTP/2 and HTTP/1.1 traffic decrypts automatically. Filters like `http.request`, `http2`, and `http.file_data` become active.

---

### Following Streams and Extracting Data

**Follow TCP Stream:** Right-click any TCP packet → Follow → TCP Stream
- Red = client to server, blue = server to client
- Displays reassembled application data
- Can save as raw binary or ASCII
- Use "Find" within stream dialog for quick string search

**Follow HTTP Stream:** Right-click → Follow → HTTP Stream
- Shows HTTP headers + body (if uncompressed)
- Useful for seeing POST body, cookies, auth tokens

**Follow TLS Stream (after key loading):**
Right-click decrypted TLS packet → Follow → TLS Stream

**Export HTTP objects:**
File → Export Objects → HTTP → saves all transferred files to a directory
Works for images, executables, documents, scripts

**Export SMB objects:**
File → Export Objects → SMB → extracts files transferred over SMB

**Export DICOM / IMF objects:**
File → Export Objects → (format)

**Command line with tshark:**
```bash
tshark -r capture.pcap --export-objects http,./http_objects/
tshark -r capture.pcap --export-objects smb,./smb_objects/
tshark -r capture.pcap --export-objects dicom,./dicom_objects/
```

---

## tcpdump Advanced BPF Filters

### Core BPF Syntax
```bash
# Protocol primitives
tcpdump 'tcp'
tcpdump 'udp'
tcpdump 'icmp'
tcpdump 'arp'

# Port-based
tcpdump 'port 80'
tcpdump 'dst port 443'
tcpdump 'portrange 8080-8090'

# Host-based
tcpdump 'host 192.168.1.100'
tcpdump 'src host 10.0.0.1'
tcpdump 'net 192.168.1.0/24'

# Combining
tcpdump 'tcp and dst port 443 and src net 10.0.0.0/8'
tcpdump 'not port 22 and not port 53'
```

### TCP Flag Filters (BPF byte access)
```bash
# TCP flags byte: offset 13 in TCP header
# Bit positions: CWR=128, ECE=64, URG=32, ACK=16, PSH=8, RST=4, SYN=2, FIN=1

# SYN only (no ACK) — new connections / scan detection
tcpdump 'tcp[tcpflags] == tcp-syn'
tcpdump 'tcp[13] == 0x02'

# SYN-ACK — server responses to SYN
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
tcpdump 'tcp[13] == 0x12'

# RST — connection resets
tcpdump 'tcp[tcpflags] & tcp-rst != 0'

# FIN — connection teardown
tcpdump 'tcp[tcpflags] & tcp-fin != 0'

# NULL scan — no flags set (Nmap -sN)
tcpdump 'tcp[tcpflags] == 0'
tcpdump 'tcp[13] == 0x00'

# Xmas scan — FIN+PSH+URG (Nmap -sX)
tcpdump 'tcp[tcpflags] == (tcp-fin|tcp-psh|tcp-urg)'
tcpdump 'tcp[13] == 0x29'

# ACK scan — ACK only (Nmap -sA for firewall mapping)
tcpdump 'tcp[tcpflags] == tcp-ack'
tcpdump 'tcp[13] == 0x10'

# PSH+ACK — data being pushed (normal HTTP, etc.)
tcpdump 'tcp[tcpflags] & (tcp-psh|tcp-ack) == (tcp-psh|tcp-ack)'
```

### Application Layer Content Matching
```bash
# Match HTTP GET requests (bytes 0-3 of payload = "GET ")
tcpdump 'tcp[((tcp[12:1] & 0xf0) >> 2):4] == 0x47455420'

# ICMP tunneling: unusually large ICMP payloads
tcpdump 'icmp and greater 100'

# DNS tunneling: large DNS over UDP (normal DNS < 512 bytes)
tcpdump 'udp port 53 and greater 512'

# Fragmented packets (potential evasion)
tcpdump '(ip[6:2] & 0x3fff) != 0'
```

### Output and Capture Options
```bash
# Hex + ASCII output (most verbose, shows payload)
tcpdump -XX 'port 80'

# ASCII only (faster to read for text protocols)
tcpdump -A 'tcp port 80'

# Extract HTTP Host headers from cleartext traffic
tcpdump -A 'tcp port 80' | grep -oP 'Host: \K[^\r]+'

# Quiet: just timestamp, src, dst, flags
tcpdump -q 'tcp[tcpflags] == tcp-syn'

# Write to pcap file
tcpdump -i eth0 -w /tmp/capture.pcap

# Rotating capture files: new file every hour, keep 48 files (2 days)
tcpdump -i eth0 -G 3600 -w /captures/traffic_%Y%m%d_%H%M%S.pcap -W 48

# Capture specific size (first 96 bytes of each packet for headers only)
tcpdump -i eth0 -s 96 -w /tmp/headers.pcap

# Capture to ring buffer: 100MB files, max 10 files
tcpdump -i eth0 -C 100 -W 10 -w /tmp/ring.pcap

# Read from file and apply filter
tcpdump -r capture.pcap 'tcp and dst port 443'

# Count packets matching filter
tcpdump -r capture.pcap --count 'tcp[tcpflags] == tcp-syn'
```

### Practical Investigation Filters
```bash
# Exclude own SSH session to avoid noise during live capture
tcpdump 'not port 22'

# Capture only DNS and HTTP+HTTPS
tcpdump 'port 53 or port 80 or port 443'

# All traffic from specific subnet going out
tcpdump 'src net 192.168.1.0/24 and dst net not 192.168.1.0/24'

# SMB lateral movement detection
tcpdump 'tcp and (dst port 445 or dst port 139)'

# SMTP exfil detection (outbound email)
tcpdump 'tcp and (dst port 25 or dst port 587 or dst port 465)'

# Detect hosts doing ARP scanning
tcpdump 'arp[6:2] == 1'   # ARP requests from any host

# Show multicast and broadcast (often noise, but check for LLMNR/MDNS)
tcpdump 'ether multicast'
tcpdump 'udp port 5355'    # LLMNR
tcpdump 'udp port 5353'    # mDNS
```

---

## Zeek Network Visibility

### Architecture Overview

Zeek (formerly Bro) is a passive network security monitor. It reads pcaps or live traffic and writes structured logs (TSV or JSON). Each log file corresponds to a protocol or event type.

```bash
# Process a pcap file
zeek -r capture.pcap

# Run with all standard scripts (recommended)
zeek -r capture.pcap local

# JSON output
zeek -r capture.pcap LogAscii::use_json=T

# View logs
ls *.log
```

---

### Key Log Files (Field Reference)

**conn.log** — Every network connection

| Field | Description | Security Use |
|---|---|---|
| ts | Timestamp | Timeline correlation |
| uid | Unique connection ID | Join across log files |
| id.orig_h | Source IP | Identify scanning hosts |
| id.orig_p | Source port | Ephemeral port tracking |
| id.resp_h | Destination IP | Identify C2/exfil targets |
| id.resp_p | Destination port | Service identification |
| proto | tcp/udp/icmp | Protocol filtering |
| service | Detected service (http, dns) | Mismatched port/service |
| duration | Connection duration | Beaconing, long C2 sessions |
| orig_bytes | Bytes sent by originator | Exfil volume |
| resp_bytes | Bytes sent by responder | Response size anomalies |
| conn_state | Connection state | See below |
| history | Flag sequence | Scan patterns |
| local_orig | Source is local | Internal pivot detection |
| local_resp | Dest is local | Inbound connection |

**conn_state values:**
```
S0    SYN sent, no SYN-ACK (filtered/closed, scan indicator)
S1    SYN+SYN-ACK, no final ACK (half-open)
SF    Normal connection, clean finish (SYN→data→FIN)
REJ   SYN met with RST (port closed)
S2    Connection established, originator closed
S3    Connection established, responder closed
RSTO  Originator sent RST mid-connection
RSTR  Responder sent RST mid-connection
SH    SYN→SYN-ACK→originator RST (common in SYN scans)
OTH   Mid-stream traffic (no handshake seen)
```

**dns.log** — DNS queries and responses

| Field | Description | Security Use |
|---|---|---|
| ts | Timestamp | Timeline |
| id.orig_h | Querying host | Identify infected host |
| query | Domain queried | Threat intel lookup |
| qtype_name | A/AAAA/MX/TXT/ANY | ANY=amplification, TXT=tunneling |
| rcode_name | NOERROR/NXDOMAIN | NXDOMAIN spikes = DGA activity |
| answers | Resolved IPs/values | IOC matching |
| TTLs | Response TTLs | Low TTL = fast flux |
| rejected | Query rejected | DNS firewall activity |

**http.log** — HTTP/1.x requests

| Field | Description | Security Use |
|---|---|---|
| method | GET/POST/PUT | POST to rare URIs = C2 |
| host | HTTP Host header | Virtual hosting, CDN bypass |
| uri | Request path | Webshell, traversal, SQLi |
| user_agent | Browser/tool UA | Scanner identification, empty UA |
| status_code | HTTP response code | 404 spikes = scanning |
| request_body_len | POST body size | Large uploads = exfil |
| response_body_len | Response size | Large downloads |
| resp_mime_types | MIME type returned | Executable delivered over HTTP |
| referrer | Referrer header | Phishing chain tracking |

**ssl.log** — TLS/SSL connections

| Field | Description | Security Use |
|---|---|---|
| version | TLS version | TLS 1.0/SSLv3 = old/weak |
| cipher | Cipher suite | Weak cipher detection |
| server_name | SNI (domain) | C2 domain identification |
| validation_status | Certificate trust | Self-signed, expired certs |
| ja3 | Client fingerprint | Malware tooling identification |
| ja3s | Server fingerprint | C2 server fingerprinting |
| established | Handshake completed | Failed handshakes = probing |
| resumed | Session resumed | Beaconing pattern |
| cert_chain_fuids | Cert UIDs | Link to x509.log |

**files.log** — Transferred files

| Field | Description | Security Use |
|---|---|---|
| source | Protocol (HTTP/SMB) | File transfer method |
| tx_hosts | Sending IP | Who sent the file |
| rx_hosts | Receiving IP | Who received the file |
| mime_type | File type | Executable delivery |
| filename | Filename if known | Suspicious file names |
| md5 | MD5 hash | Threat intel |
| sha256 | SHA256 hash | VirusTotal lookup |
| extracted | Path if extracted | Automated extraction |

**x509.log** — TLS Certificates

| Field | Description | Security Use |
|---|---|---|
| certificate.subject | Subject CN | Self-signed or suspicious CN |
| certificate.issuer | Issuing CA | Unknown CA = suspicious |
| certificate.not_valid_before | Issue date | Recently issued = fresh C2 |
| certificate.not_valid_after | Expiry | Expired cert = negligence or malware |
| san.dns | Subject Alt Names | Domain matching |
| basic_constraints.ca | Is a CA | CA cert from non-CA = spoofing |

---

### zq/zed Queries

`zq` (Zed query) is the command-line tool for querying Zeek logs. Syntax is similar to SQL with a pipeline model.

```bash
# ── Long Connections (Beaconing / C2) ───────────────────────────────────────
zq 'where duration > 3600 | sort -r duration | head 20' conn.log

# ── Small Bidirectional Flows (C2 keep-alive pattern) ───────────────────────
zq 'where orig_bytes < 1000 and resp_bytes < 1000 and duration > 300' conn.log

# ── Unique Destination Count per Source (Scanning) ──────────────────────────
zq 'count() by id.orig_h, id.resp_h | count() by id.orig_h | where count > 100 | sort -r count' conn.log

# ── Failed Connections (SYN scan footprint) ──────────────────────────────────
zq 'where conn_state == "S0" or conn_state == "REJ" | count() by id.orig_h | sort -r count | head 20' conn.log

# ── DNS Query Frequency (DGA or tunneling) ───────────────────────────────────
zq 'count() by query | sort -r count | head 20' dns.log

# ── Long DNS Labels (Tunneling — base32/base64 encoded data) ─────────────────
zq 'where len(query) > 50 | sort -r len(query)' dns.log

# ── High-entropy Subdomains (DGA) ────────────────────────────────────────────
zq 'where query matches /^[a-z0-9]{20,}\.[a-z]{2,4}$/' dns.log

# ── NXDomain Spikes (DGA C2 resolution attempts) ─────────────────────────────
zq 'where rcode_name == "NXDOMAIN" | count() by id.orig_h | sort -r count' dns.log

# ── ANY/TXT Query Detection (Amplification / Tunneling) ─────────────────────
zq 'where qtype_name == "ANY" or qtype_name == "TXT"' dns.log

# ── Invalid TLS Certificates ─────────────────────────────────────────────────
zq 'where validation_status != "ok"' ssl.log

# ── Connections with No SNI (Possible C2 or scanner) ────────────────────────
zq 'where server_name == "" or server_name == null' ssl.log

# ── JA3 Malware Fingerprint Lookup ───────────────────────────────────────────
zq 'where ja3 == "51c64c77e60f3980eea90869b68c58a8"' ssl.log

# ── Old TLS Versions ─────────────────────────────────────────────────────────
zq 'where version == "TLSv10" or version == "SSLv3"' ssl.log

# ── Executable File Transfers ────────────────────────────────────────────────
zq 'where mime_type in ["application/x-dosexec","application/x-executable","application/x-msdownload"]' files.log

# ── HTTP POST to Suspicious Paths ────────────────────────────────────────────
zq 'where method == "POST" and uri matches /\.(php|asp|aspx|jsp)\?/' http.log

# ── Scanner User Agents ───────────────────────────────────────────────────────
zq 'where user_agent matches /(?i)(sqlmap|nikto|nmap|masscan|zgrab|dirbuster)/' http.log

# ── Empty User Agent (Common in C2 / malware) ───────────────────────────────
zq 'where user_agent == ""' http.log

# ── HTTP to Non-Standard Ports ───────────────────────────────────────────────
zq 'where id.resp_p != 80 and id.resp_p != 8080 and id.resp_p != 8000' http.log
```

---

### Zeek Detection Script Example

Full working Zeek script to detect DNS-based tunneling by monitoring query rate per host:

```zeek
# dns_tunnel_detect.zeek
# Detects potential DNS tunneling by flagging hosts that exceed a
# query rate threshold or send unusually long DNS labels.

@load base/frameworks/notice

module DNSTunnel;

export {
    redef enum Notice::Type += {
        High_DNS_Query_Rate,    ## Host exceeding DNS query rate threshold
        Long_DNS_Label,         ## DNS label exceeds normal length (tunneling)
    };

    ## Maximum DNS queries per host per interval before alerting
    const query_rate_threshold: count = 500 &redef;

    ## Interval over which to count queries
    const query_rate_interval: interval = 1 min &redef;

    ## Maximum legitimate label length
    const label_length_threshold: count = 50 &redef;
}

# Table to count queries per source IP, expires every query_rate_interval
global query_counts: table[addr] of count
    &default=0
    &create_expire=query_rate_interval;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src = c$id$orig_h;

    # Increment query counter for this source
    ++query_counts[src];

    # Alert on high query rate
    if ( query_counts[src] == query_rate_threshold )
        {
        NOTICE([$note=High_DNS_Query_Rate,
                $conn=c,
                $msg=fmt("Host %s sent %d DNS queries in under %s",
                         src, query_rate_threshold, query_rate_interval),
                $identifier=cat(src),
                $suppress_for=5 min]);
        }

    # Alert on long DNS labels (base32/base64 encoded data in subdomains)
    if ( |query| > label_length_threshold )
        {
        NOTICE([$note=Long_DNS_Label,
                $conn=c,
                $msg=fmt("Long DNS query from %s: %s (%d chars)",
                         src, query, |query|),
                $identifier=cat(src, query),
                $suppress_for=1 min]);
        }
    }
```

**Running the script:**
```bash
zeek -r capture.pcap dns_tunnel_detect.zeek
cat notice.log | zeek-cut ts note msg
```

---

## JA3 / JA3S Fingerprinting

### What JA3 Is

JA3 is an MD5 fingerprint of the TLS ClientHello message, computed from:
```
SSLVersion + Ciphers + Extensions + EllipticCurves + ECPointFormats
```

Each field is joined by `-`, multiple values within a field joined by `-`, fields separated by `,`:
```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
```
MD5 of that string = JA3 hash.

JA3S fingerprints the ServerHello:
```
SSLVersion + Cipher + Extensions
```

**Why it matters:** Malware often uses consistent TLS libraries/configurations even when domains and IPs change. JA3 hashes are stable across C2 infrastructure changes.

---

### Known Malicious JA3 Hashes

| Hash | Malware / Tool | Notes |
|---|---|---|
| 51c64c77e60f3980eea90869b68c58a8 | Dridex | Common banking botnet TLS fingerprint |
| 6734f37431109a4923b928f49d760d69 | Trickbot | Banking trojan, loader for Ryuk/Conti |
| 72a589da586844d7f0818ce684948eea | Cobalt Strike (default) | Operators often change this |
| b386946a5a44d1ddcc843bc75336dfce | Metasploit default | Default meterpreter TLS config |
| de350869b8c85de67a350c8d186f11e6 | AsyncRAT | Remote access trojan |
| a0e9f5d64349fb13191bc781f81f42e1 | Emotet | Banking trojan / loader (historical) |
| 4d7a28d6f2263ed61de88ca66eb011e3 | Cobalt Strike Malleable C2 | Custom profile variant |
| c12f54a3f91dc7bafd92cb59fe009a35 | QakBot (Qbot) | Banking trojan family |

**Lookup databases:**
- [https://ja3er.com/search/<hash>](https://ja3er.com/search/)
- [https://sslbl.abuse.ch/ja3-fingerprints/](https://sslbl.abuse.ch/ja3-fingerprints/)

```bash
# Extract JA3 from pcap (requires ja3 tool)
ja3 -a capture.pcap
ja3 -a capture.pcap --json | jq '.[] | select(.ja3 == "72a589da586844d7f0818ce684948eea")'

# Zeek ssl.log has ja3 and ja3s fields automatically populated
zq 'where ja3 != null | count() by ja3 | sort -r count' ssl.log

# Check for known bad JA3 (using zeek-cut)
cat ssl.log | zeek-cut ts id.orig_h id.resp_h server_name ja3 | \
  grep "72a589da586844d7f0818ce684948eea"
```

---

## Detecting Attacks in PCAPs

### Nmap SYN Scan (-sS)

**Pattern:** Single source sends SYN to many ports on one or more targets; receives RST for closed ports (REJ in Zeek), no response for filtered ports (S0 in Zeek), SYN-ACK for open ports.

```wireshark
# Wireshark: SYN flood from single source
ip.src == <scanner> && tcp.flags.syn == 1 && tcp.flags.ack == 0

# Wireshark: RSTs confirming closed ports (follow the scan)
ip.src == <target> && tcp.flags.reset == 1
```

```bash
# tcpdump: capture SYN-only packets
tcpdump -r capture.pcap 'tcp[tcpflags] == tcp-syn' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn
```

```bash
# Zeek: hosts with > 100 unique dest ports (scanning)
zq 'count() by id.orig_h, id.resp_p | count() by id.orig_h | where count > 100' conn.log

# Zeek: high S0 state count from one host (filtered ports)
zq 'where conn_state == "S0" | count() by id.orig_h | where count > 50' conn.log
```

---

### Cobalt Strike Beacon

**Pattern:** Regular interval callbacks (15-60 second default sleep), HTTP/HTTPS to specific URI patterns (`/jquery-3.3.1.slim.min.js`, `/updates`, malleable C2 paths), JA3 hash match, small request bodies, larger response bodies (tasking).

```wireshark
# Wireshark: Cobalt Strike default URI patterns
http.request.uri matches "/(updates|submit\.php|jquery.*\.js)"

# Wireshark: Regular interval connections to same host
# Use Statistics → IO Graphs with filter: ip.dst == <c2_ip>
# Look for regular peaks at consistent intervals
```

```bash
# Zeek: Identify beaconing by consistent intervals between connections
zq 'sort ts | yield {ts, id.orig_h, id.resp_h} | delta ts by id.orig_h, id.resp_h' conn.log

# Zeek: JA3 match for Cobalt Strike default
zq 'where ja3 == "72a589da586844d7f0818ce684948eea"' ssl.log

# Zeek: Small consistent upload size (beacon check-in)
zq 'where orig_bytes > 0 and orig_bytes < 500 and resp_bytes > 0 | count() by id.orig_h, id.resp_h, id.resp_p | where count > 20' conn.log
```

---

### DNS Tunneling (Iodine, dnscat2, DNSExfiltrator)

**Pattern:** High query volume from single host, unusually long subdomains (base32/base64 encoded data), TXT/NULL/CNAME record types, consistent timing, queries to same parent domain.

```wireshark
# Wireshark: Long DNS queries (data encoded in subdomains)
dns.qry.name matches "^[a-z0-9]{20,}\."

# Wireshark: TXT records (common tunnel data type)
dns.qry.type == 16

# Wireshark: NULL record type
dns.qry.type == 10
```

```bash
# tcpdump: Large DNS packets
tcpdump -r capture.pcap 'udp port 53 and greater 200'
```

```bash
# Zeek: Longest queries
zq 'yield {query, len: len(query), id.orig_h} | where len > 40 | sort -r len' dns.log

# Zeek: Query count per source/domain pair (tunneling = many queries, same parent)
zq 'count() by id.orig_h, query | sort -r count | head 30' dns.log

# Zeek: Identify dnscat2 by NULL record type (type 10)
zq 'where qtype_name == "NULL"' dns.log
```

---

### LLMNR Poisoning (Responder)

**Pattern:** Host sends LLMNR/NBT-NS query (broadcast); attacker immediately replies claiming to be the queried name; victim sends NTLMv2 hash to attacker's IP.

```wireshark
# Wireshark: LLMNR queries (UDP 5355)
udp.port == 5355

# Wireshark: NBT-NS queries (UDP 137)
udp.port == 137

# Wireshark: Suspiciously fast LLMNR response (Responder)
# Filter LLMNR, look for response from non-authoritative source
# Normal LLMNR: no response (name doesn't exist)
# Attack: immediate unicast response from attacker IP
```

```bash
# tcpdump: LLMNR + NBT-NS
tcpdump -r capture.pcap 'udp port 5355 or udp port 137'
```

```bash
# Zeek: LLMNR traffic (Zeek decodes as DNS on port 5355)
zq 'where id.resp_p == 5355' conn.log

# Look for NTLMv2 auth immediately after LLMNR response
# SMB connections from victim to non-DC IP following LLMNR
zq 'where id.resp_p == 445 | join on id.orig_h' conn.log
```

---

### ARP Poisoning / ARP Spoofing

**Pattern:** Gratuitous ARP replies mapping a legitimate IP to attacker's MAC; duplicate IP warnings; victim traffic redirected through attacker (MITM).

```wireshark
# Wireshark: Duplicate IP detection (Wireshark expert info)
arp.duplicate-address-detected

# Wireshark: Gratuitous ARP (IP appears in both sender and target)
arp.isgratuitous == 1

# Wireshark: High rate of ARP replies from single MAC
arp.opcode == 2 && eth.src == <attacker_mac>
```

```bash
# tcpdump: All ARP traffic
tcpdump -r capture.pcap 'arp'

# tcpdump: ARP replies only
tcpdump -r capture.pcap 'arp[6:2] == 2'
```

```bash
# Zeek: ARP events (requires zeek/arp script)
cat arp.log | zeek-cut ts orig_h orig_mac resp_h resp_mac

# Look for same IP claimed by multiple MACs over time
zq 'count() by resp_h, resp_mac | count() by resp_h | where count > 1' arp.log
```

---

### Data Exfiltration

**Pattern:** Sustained high outbound bytes from internal host to single external IP; large file transfers over HTTP/HTTPS/DNS/ICMP; transfer size inconsistent with normal business traffic.

```wireshark
# Wireshark: Top talkers by bytes
# Statistics → Conversations → Sort by Bytes (descending)

# Wireshark: Large HTTP POST (data upload)
http.request.method == "POST" && http.request_body_len > 1000000

# Wireshark: Large outbound flows
ip.src == 10.0.0.0/8 && frame.len > 1500
```

```bash
# Zeek: Total outbound bytes per destination
zq 'where not (id.resp_h in 10.0.0.0/8) | sum(orig_bytes) by id.orig_h, id.resp_h | sort -r sum | head 20' conn.log

# Zeek: Large single connections
zq 'where orig_bytes > 10000000 | sort -r orig_bytes' conn.log

# Zeek: Exfil via DNS (many bytes in queries)
zq 'sum(len(query)) by id.orig_h | sort -r sum | head 10' dns.log
```

---

## PCAP Investigation Workflow

### Step-by-Step Investigation Process

**1. Overview — Conversations**
Statistics → Conversations (IPv4 tab). Sort by Bytes. Note top 5-10 pairs.
Questions: Any internal host sending large volume to single external IP? Unusual port numbers?

**2. Protocol Breakdown**
Statistics → Protocol Hierarchy. Note:
- Is HTTP high relative to HTTPS? (cleartext risk)
- Any protocols you don't expect? (tunneling, legacy protocols)
- Data% high? (unrecognized encapsulation)

**3. Timeline — IO Graph**
Statistics → IO Graphs. Look for:
- Sustained regular peaks (beaconing)
- Single large burst (exfil event)
- Correlation with known event times

**4. Expert Information Review**
Analyze → Expert Information. Check:
- Many retransmissions (congestion, IDS evasion attempt, or normal)
- RST packets mid-stream (injected RSTs, session hijacking)
- Malformed packets (exploit attempts, fuzzing)

**5. Pivot on Suspicious IP**
Apply display filter: `ip.addr == <suspect>`. Review all activity.
Right-click → Apply as Column for interesting fields.

**6. Follow Streams**
Right-click interesting packet → Follow → TCP/HTTP/TLS Stream.
Look for: credentials, commands, file content, C2 protocol.

**7. DNS Review**
Filter: `dns`. Look for:
- High-entropy subdomains
- NXDOMAIN responses (DGA)
- Unusual record types (TXT, NULL, ANY)
- Non-standard DNS servers (not 8.8.8.8, 1.1.1.1, or corporate DNS)

**8. TLS/SNI Review**
Filter: `tls.handshake.type == 1`. Look at server_name column for:
- Newly registered domains
- DGA-like patterns
- IP addresses as SNI (malware)
- Missing SNI (scanner or non-browser client)

**9. Credential Search**
Edit → Find Packet → String → search for: `password`, `Authorization`, `PASS`, `login`
Filter: `http.authbasic || ftp.request.command == "PASS" || telnet`

**10. C2 Pattern Identification**
Statistics → IO Graph → add filter for suspect IP.
Consistent peaks at regular intervals = beaconing.
Cross-reference JA3 hash against threat intel databases.

---

### Extracting Files from PCAPs

```bash
# Extract all HTTP objects (images, executables, scripts)
tshark -r capture.pcap --export-objects http,./http_files/

# Extract all SMB objects (file shares)
tshark -r capture.pcap --export-objects smb,./smb_files/

# Extract all DICOM objects
tshark -r capture.pcap --export-objects dicom,./dicom_files/

# Reconstruct all TCP streams as individual files
tcpflow -r capture.pcap -o ./tcp_streams/

# Reconstruct streams with metadata
tcpflow -r capture.pcap -o ./tcp_streams/ -B -AJ

# Extract files using NetworkMiner (GUI tool, Windows/Mono)
# File → Open → select pcap → Files tab shows all extracted files

# Hash all extracted files for threat intel lookup
find ./http_files/ -type f -exec sha256sum {} \; > extracted_hashes.txt

# Check extracted executables
file ./http_files/*
find ./http_files/ -name "*.exe" -o -name "*.dll" -o -name "*.ps1"
```

---

## Tools Quick Reference

| Tool | Purpose | Key Command | Notes |
|---|---|---|---|
| **Wireshark** | GUI packet analysis, deep protocol decode | `wireshark capture.pcap` | Best for interactive investigation |
| **tshark** | CLI Wireshark, scriptable | `tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name` | Use for automation and parsing |
| **tcpdump** | Capture and quick filter | `tcpdump -i eth0 -w out.pcap 'tcp[13]==0x02'` | Best for live capture on servers |
| **Zeek** | Protocol analysis, log generation | `zeek -r cap.pcap local` | Best for structured data at scale |
| **zq / zed** | Query Zeek logs | `zq 'where duration > 3600' conn.log` | SQL-like pipeline for log analysis |
| **Arkime (Moloch)** | Full packet capture at scale | Web UI + API | Enterprise PCAP storage and search |
| **NetworkMiner** | Passive file extraction, OS fingerprinting | GUI, drag-and-drop pcap | Fast artifact extraction |
| **tcpflow** | Reconstruct TCP streams to files | `tcpflow -r cap.pcap -o ./streams/` | Better stream reassembly than tshark |
| **Scapy** | Craft and parse packets in Python | `from scapy.all import *; rdpcap('cap.pcap')` | Custom analysis scripts |
| **ja3** | Extract JA3 fingerprints from pcap | `ja3 -a capture.pcap` | Requires `ja3` pip package |
| **p0f** | Passive OS fingerprinting | `p0f -r capture.pcap -o output.log` | No active probing needed |
| **ngrep** | Grep for patterns in packet payloads | `ngrep -I cap.pcap 'password'` | Fast content search |
| **strings** | Extract printable strings from binary | `strings capture.pcap \| grep -i 'http\|pass'` | Quick dirty search |
| **Suricata** | IDS/IPS with PCAP replay | `suricata -r capture.pcap -l ./logs/` | Rule-based detection on pcap |
| **RITA** | Detect beaconing, long connections | `rita analyze --pcap capture.pcap` | Automated C2 detection from Zeek logs |
