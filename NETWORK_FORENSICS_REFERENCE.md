# Network Forensics Reference

> Comprehensive reference for incident responders and network forensics analysts covering evidence collection, packet analysis, protocol decoding, traffic anomaly detection, malware traffic patterns, incident reconstruction, encrypted traffic analysis, wireless forensics, cloud forensics, and reporting standards.

| | |
|---|---|
| **Read this when** | you need to capture or preserve network evidence that may end up in court, you are reconstructing an incident timeline from PCAP/flow/log data, you suspect C2 beaconing or data exfiltration and need to prove it from traffic |
| **Start at** | [Network Forensics Fundamentals & Evidence Collection](#_1-network-forensics-fundamentals-amp-evidence-collection), [Malware Traffic Analysis](#_5-malware-traffic-analysis), [Forensic Reporting & Tools Reference](#_10-forensic-reporting-amp-tools-reference) |
| **Pairs with** | [Packet Analysis Reference](PACKET_ANALYSIS_REFERENCE.md), [Digital Forensics Reference](DIGITAL_FORENSICS_REFERENCE.md), [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md), [Network Monitoring Reference](NETWORK_MONITORING_REFERENCE.md) |

---

## Table of Contents

1. [Network Forensics Fundamentals & Evidence Collection](#_1-network-forensics-fundamentals-amp-evidence-collection)
2. [Packet Capture Tools & Infrastructure](#_2-packet-capture-tools-amp-infrastructure)
3. [Protocol Analysis & Decoding](#_3-protocol-analysis-amp-decoding)
4. [NetFlow & Traffic Analysis](#_4-netflow-amp-traffic-analysis)
5. [Malware Traffic Analysis](#_5-malware-traffic-analysis)
6. [Incident Reconstruction from Network Evidence](#_6-incident-reconstruction-from-network-evidence)
7. [Encrypted Traffic Analysis](#_7-encrypted-traffic-analysis)
8. [Wireless & Remote Access Forensics](#_8-wireless-amp-remote-access-forensics)
9. [Cloud & Container Network Forensics](#_9-cloud-amp-container-network-forensics)
10. [Forensic Reporting & Tools Reference](#_10-forensic-reporting-amp-tools-reference)

---

## 1. Network Forensics Fundamentals & Evidence Collection

### Goals of Network Forensics

Network forensics is the capture, recording, and analysis of network events for the purpose of discovering the source of security attacks or other problem incidents. Primary objectives include:

- **Incident Reconstruction**: Establishing an accurate timeline of attacker actions — initial access vector, lateral movement, privilege escalation, data staging, and exfiltration — by correlating packet captures, flow records, and log sources.
- **Attribution**: Identifying threat actors through IP addresses, ASN ownership, infrastructure reuse (C2 hostnames, TLS certificates), behavioral TTPs, and threat intelligence correlation. Attribution is probabilistic, not deterministic.
- **Evidence for Legal Proceedings**: Producing forensically sound evidence packages that can withstand scrutiny in civil litigation or criminal prosecution, including chain-of-custody documentation, authenticated hash values, and examiner logs.
- **Threat Intelligence Production**: Extracting IOCs (IP addresses, domains, JA3 hashes, YARA-matchable patterns) from network captures to improve detection across the enterprise.
- **Damage Assessment**: Quantifying data exfiltration volume, scope of lateral movement, and number of compromised hosts from network evidence.

### Evidence Types

| Evidence Type | Description | Retention Considerations |
|---|---|---|
| Full PCAP | Complete packet payload capture | High storage cost; 1 Gbps link = ~450 GB/hour uncompressed |
| NetFlow/IPFIX | Flow-level metadata (5-tuple + bytes/packets/duration) | 1/1000th the volume of full PCAP |
| SNMP | Device health counters, interface statistics | Useful for bandwidth anomaly baseline |
| Firewall Logs | Allow/deny decisions with 5-tuple and rule name | Critical for perimeter reconstruction |
| Proxy Logs | Full URL, user-agent, referrer, response code, bytes | Required for web incident reconstruction |
| DNS Logs | All queries/responses with client IP and timestamp | Essential for C2 domain detection |
| DHCP Logs | IP-to-MAC-to-hostname mapping with lease times | Required to translate IPs to identities |
| Syslog | Device events: auth failures, config changes, ACL hits | Correlates with network behavior |
| Endpoint Telemetry | EDR network connection events (process + socket) | Provides process-level attribution |
| VPC Flow Logs | Cloud provider flow metadata | Replaces NetFlow in cloud environments |

### Collection Points

**Network TAPs (Test Access Points)**
- Passive, out-of-band copper or fiber tap that copies all traffic without introducing latency or failure points.
- Aggregation TAPs combine both directions of a full-duplex link into a single capture stream.
- Best practice for forensic-grade evidence collection; TAP failure does not affect the production link.
- Vendors: Gigamon, IXIA, Cubro, Garland Technology.

**SPAN / Mirror Ports**
- Switch-configured port that copies traffic to a designated monitoring port.
- Introduces risk of dropped packets under high load (switch CPU/ASIC oversubscription).
- Remote SPAN (RSPAN) tunnels mirrored traffic across VLANs; ERSPAN encapsulates in GRE for IP delivery.
- Sufficient for incident response in most environments where TAP deployment is not feasible.

**Inline vs. Passive**
- **Inline**: Device sits in the traffic path (IPS, SSL inspection proxy). Can decrypt TLS, modify or block traffic. Introduces latency and becomes a failure point.
- **Passive**: Device receives a copy of traffic (IDS, full-packet capture appliance). No impact on production traffic. Cannot decrypt TLS without a copy of the private key or a pre-shared session key.

**Cloud VPC Flow Logs**
- AWS VPC Flow Logs capture at the ENI level; do not capture all packet headers, only flow metadata.
- Enable at VPC or subnet level; deliver to CloudWatch Logs or S3.
- Azure NSG Flow Logs: captured at the NSG level, JSON format, version 2 adds throughput data.
- GCP VPC Flow Logs: sampled by default (1/10 of flows); enable full sampling for forensic accuracy.

### Legal Considerations

**Chain of Custody for Network Evidence**
- Document every person who handles the evidence: name, role, date/time of access, purpose.
- Evidence bags, tamper-evident seals, and hash verification at each transfer point.
- Maintain a custody log that travels with the evidence from collection through courtroom.

**Wiretapping Laws — ECPA (Electronic Communications Privacy Act)**
- Title I (Wiretap Act): prohibits real-time interception of wire, oral, or electronic communications without consent or court order.
- Title II (Stored Communications Act): governs access to stored electronic communications.
- Business exception: employers may monitor their own networks if employees have been given notice (acceptable use policy).
- Law enforcement must obtain a Title III court order for real-time network interception.

**GDPR Article 32 (EU)**
- Requires appropriate technical and organizational measures to ensure data security, including the ability to detect security incidents.
- Network monitoring logs may contain personal data (IP addresses are PII under GDPR); data minimization and retention limits apply.
- Data Protection Impact Assessment (DPIA) required before deploying pervasive packet capture.

**Sector-Specific Requirements**
- HIPAA: PHI in network captures must be protected; audit logs required for access.
- PCI-DSS Requirement 10: log all access to network resources and cardholder data.
- FISMA/FedRAMP: continuous monitoring mandated; NIST SP 800-137 guidance.

### Evidence Integrity

**PCAP SHA-256 Hashing**
```bash
# Hash immediately after capture
sha256sum capture.pcap > capture.pcap.sha256
# Verify later
sha256sum -c capture.pcap.sha256
# MD5 for legacy systems (not recommended for legal proceedings)
md5sum capture.pcap
```

**Write-Blocking for Stored Captures**
- Software write-blockers (e.g., `blockdev --setro` on Linux) prevent modification of capture files on storage media.
- Hardware write-blockers (Tableau, WiebeTech) are preferred for legal proceedings.
- Mount evidence storage read-only before analysis: `mount -o ro /dev/sdb1 /mnt/evidence`

**RFC 3227 — Guidelines for Evidence Collection and Archiving**
- Order of volatility: network state → running processes → memory → swap → disk → archival media.
- For network evidence, capture volatile data first (ARP table, routing table, active connections).
- Minimize footprint: use known-good binaries, document every command executed.
- Timestamp synchronization: ensure all collection systems are NTP-synced to UTC; document clock skew.

### Network Forensics Timeline Framework

```
Detection ──► Triage ──► Evidence Preservation ──► Analysis ──► Containment ──► Recovery
     │             │              │                       │
  Alert or      Scope         Enable/increase         Reconstruct
  tip-off       assessment    log retention           timeline
                              Full PCAP capture       Extract IOCs
                              Snapshot flow data      Attribute actors
                              Freeze log rotation     Document findings
```

**Key Timestamps to Preserve**
1. First indicator timestamp (SIEM alert, analyst report, threat intel hit)
2. Earliest network evidence of attacker activity (earliest PCAP/flow record)
3. Initial access event (first external connection to compromised host)
4. Lateral movement events (authentication + network connection sequence)
5. Data staging/exfiltration events (large outbound transfers, DNS exfil queries)
6. Containment action timestamps (firewall block, account disable, host isolation)

---

## 2. Packet Capture Tools & Infrastructure

### tcpdump — Deep Reference

tcpdump is the de facto standard CLI packet capture utility, available on all UNIX-like systems.

**Core BPF Filter Syntax**

```bash
# Capture by host
tcpdump host 192.168.1.100
tcpdump src host 10.0.0.1
tcpdump dst host 8.8.8.8

# Capture by network
tcpdump net 192.168.0.0/16
tcpdump src net 10.0.0.0/8

# Capture by port
tcpdump port 443
tcpdump portrange 1024-65535
tcpdump not port 22

# Capture by protocol
tcpdump tcp
tcpdump udp
tcpdump icmp
tcpdump ip6

# Logical combinators
tcpdump 'host 10.1.1.1 and (port 80 or port 443)'
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'
tcpdump 'not arp and not icmp'

# Capture specific TCP flags (SYN-only for connection tracking)
tcpdump 'tcp[13] = 2'
# SYN-ACK
tcpdump 'tcp[13] = 18'
# RST
tcpdump 'tcp[13] & 4 != 0'
```

**Key Flags**

| Flag | Purpose |
|---|---|
| `-i eth0` | Specify capture interface (`-i any` for all) |
| `-w file.pcap` | Write to pcap file |
| `-r file.pcap` | Read from pcap file |
| `-s 0` | Full snaplen (default 262144 bytes; older: 65535) |
| `-n` | No DNS resolution |
| `-nn` | No DNS or service name resolution |
| `-v/-vv/-vvv` | Increasing verbosity |
| `-c 1000` | Capture N packets then stop |
| `-C 100` | Rotate output file every N MB |
| `-W 10` | Limit to N rotated files (ring buffer) |
| `-G 3600` | Rotate every N seconds |
| `-z gzip` | Compress rotated files |
| `-e` | Print link-layer (Ethernet) headers |
| `-A` | Print ASCII payload |
| `-X` | Print hex + ASCII payload |

**Ring Buffer for Continuous Capture**
```bash
# Rotate every 100MB, keep 50 files = ~5GB rolling capture
tcpdump -i eth0 -w /capture/dump-%Y%m%d-%H%M%S.pcap -C 100 -W 50 -z gzip

# Time-based rotation every hour
tcpdump -i eth0 -w /capture/dump-%Y%m%d-%H%M%S.pcap -G 3600 -W 24
```

### Wireshark

**Display Filters (applied after capture)**
```
# Filter by IP
ip.addr == 192.168.1.100
ip.src == 10.0.0.1 && ip.dst == 8.8.8.8

# Filter by protocol
http
dns
tls
smb2

# HTTP filters
http.request.method == "POST"
http.response.code == 200
http.user_agent contains "curl"

# DNS filters
dns.qry.name contains "evil.com"
dns.flags.rcode != 0    # NXDOMAIN / SERVFAIL

# TLS filters
tls.handshake.type == 1    # ClientHello
tls.record.version == 0x0303   # TLS 1.2

# Follow stream: right-click → Follow → TCP/UDP/TLS Stream
```

**tshark CLI Equivalent**
```bash
# Read pcap and filter
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name

# Extract TLS SNI
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn

# Extract X.509 certificate info
tshark -r capture.pcap -Y "tls.handshake.certificate" -T fields \
  -e tls.handshake.certificate -e x509af.rdnSequence
```

**Companion Utilities**
- `editcap`: Split, trim, and convert pcap files. `editcap -c 10000 large.pcap split/chunk.pcap` splits into 10k-packet files.
- `mergecap`: Merge multiple pcap files sorted by timestamp. `mergecap -w merged.pcap a.pcap b.pcap`
- `capinfos`: Summarize pcap metadata (start/end time, packet count, data rate). `capinfos capture.pcap`
- `pcapng vs pcap`: pcapng supports multiple interfaces, comments, and per-packet flags; preferred for modern captures.

### Zeek (formerly Bro)

Zeek generates structured log files from live traffic or pcap replay. Key logs:

| Log File | Key Fields | Use Case |
|---|---|---|
| `conn.log` | ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state | Connection inventory, long-duration flows, beaconing |
| `dns.log` | ts, uid, query, qtype_name, rcode_name, answers, TTLs | C2 domain detection, DNS tunneling |
| `http.log` | ts, uid, host, uri, method, status_code, user_agent, request_body_len, response_body_len | Web incident reconstruction |
| `ssl.log` | ts, uid, server_name, subject, issuer, ja3, ja3s, validation_status | TLS fingerprinting, certificate analysis |
| `files.log` | ts, fuid, tx_hosts, rx_hosts, source, mime_type, filename, sha256 | Malware file detection, DLP |
| `notice.log` | ts, note, msg, src, dst, uid | Policy violations, known-bad indicators |
| `weird.log` | ts, name, msg | Protocol anomalies |

```bash
# Replay pcap through Zeek
zeek -r capture.pcap local

# Query conn.log for long-duration connections
zeek-cut ts uid id.orig_h id.resp_h duration < conn.log | awk '$4 > 3600' | sort -k4 -rn | head -20

# Identify top external destinations
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -rn | head -20
```

### Additional Capture Tools

**tcpflow** — Reconstructs TCP sessions from pcap, writing each flow as a file named by 4-tuple. `tcpflow -r capture.pcap -o sessions/`

**NetworkMiner** — Windows-based passive network forensics tool. Auto-extracts files, images, credentials, and messages from pcap. Performs passive OS fingerprinting using TCP/IP stack behavior (TTL, window size, options).

**Security Onion** — Integrated Linux distribution for network security monitoring:
- Zeek for protocol logs
- Suricata for signature-based detection
- Elasticsearch + Kibana for log analysis
- TheHive for case management
- Useful for rapid deployment of full packet capture + detection + analysis stack.

**Arkime (formerly Moloch)** — Full PCAP capture, indexing, and search platform. Indexes sessions in Elasticsearch; enables search by any protocol field. Supports PCAP download for any session. Scales to 100+ Gbps with clustered deployment.

### Cloud Provider Flow Logs

**AWS VPC Flow Logs**
```
# Default v2 format:
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status

# Example record:
2 123456789010 eni-abc123 10.0.1.5 52.84.12.99 54321 443 6 12 5824 1620000000 1620000060 ACCEPT OK

# Athena query for top external destinations (rejected)
SELECT dstaddr, COUNT(*) as count, SUM(bytes) as total_bytes
FROM vpc_flow_logs
WHERE action = 'REJECT' AND dstaddr NOT LIKE '10.%' AND dstaddr NOT LIKE '172.%'
GROUP BY dstaddr ORDER BY count DESC LIMIT 20;
```

**Azure NSG Flow Logs** — JSON format, delivered to Storage Account, analyzed in Sentinel via `AzureNetworkAnalytics_CL` table.

**GCP VPC Flow Logs** — Ingested via Cloud Logging; query with Logs Explorer or BigQuery.

---

## 3. Protocol Analysis & Decoding

### HTTP/HTTPS Analysis

**Request/Response Parsing in Wireshark**
```
# Display filter for all HTTP traffic
http

# Follow full web session
http.request.method == "GET" or http.response

# Identify POST with body
http.request.method == "POST" and http.request_body_len > 0

# Export HTTP objects: File → Export Objects → HTTP
```

**User-Agent Anomalies**
- Default OS user-agents (no browser) may indicate scripted access or C2 traffic.
- Empty user-agent: `http.user_agent == ""` — common in simple implants.
- Known-bad UAs: `python-requests`, `Go-http-client`, `curl/7.68`, `libwww-perl` — flag for investigation.
- Browser UA on non-browser port (e.g., port 8080, 4444) suggests C2 over alternate port.

**Header Fingerprinting**
- Header order and presence are characteristic of specific HTTP implementations.
- Legitimate browsers send Accept, Accept-Encoding, Accept-Language; C2 frameworks often omit these.
- HTTP/2 HPACK static table indices can fingerprint client libraries (ALPN negotiation).

### DNS Analysis

**Query/Response Pattern Analysis**
```bash
# Using tshark to extract DNS queries with client IP
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type

# Count NXDOMAIN responses (high rate = DGA or scanning)
tshark -r capture.pcap -Y "dns.flags.rcode == 3" \
  -T fields -e ip.src | sort | uniq -c | sort -rn

# Find unusual TXT record queries (common in DNS exfil)
tshark -r capture.pcap -Y "dns.qry.type == 16" \
  -T fields -e ip.src -e dns.qry.name
```

**TTL Anomalies**
- Legitimate CDN domains use TTL of 60-300 seconds; unusually low TTLs (< 30s) on non-CDN domains suggest fast-flux C2 infrastructure.
- High TTL on rarely-queried domains (sinkhole confirmation).
- DNS tunneling indicators: long subdomain labels (> 50 characters), high query rate to same domain, entropy in subdomain.

**EDNS0 Extensions**
- EDNS0 (Extension Mechanisms for DNS) adds UDP payload size advertisement and DNSSEC support.
- `OPT` record in DNS queries enables EDNS0; absence may indicate legacy resolver or custom implementation.
- DNS Cookie (EDNS0 option 10) helps detect DNS cache poisoning.

**DNS-over-HTTPS in PCAP**
- DoH sends DNS queries as HTTPS POST/GET to port 443 resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9).
- Detect by identifying HTTPS connections to known DoH resolver IPs with Content-Type: `application/dns-message`.
- Use SNI extraction: `cloudflare-dns.com`, `dns.google`, `dns.quad9.net` in TLS SNI field.

### TLS/SSL Forensics

**JA3 Client Fingerprinting**
JA3 generates an MD5 hash from the TLS ClientHello fields: SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats.

```bash
# Extract JA3 hashes with Zeek ssl.log
grep -v "^#" ssl.log | zeek-cut ja3 server_name | sort | uniq -c | sort -rn | head -20

# Using ja3 Python tool
python3 ja3.py -j capture.pcap

# Known Cobalt Strike default JA3: b70de2e22a17a7ddd01c9beae47a8cc9
# Query abuse.ch JA3 feed
curl -s "https://ja3er.com/search/b70de2e22a17a7ddd01c9beae47a8cc9"
```

**JA3S Server Fingerprinting**
JA3S fingerprints the ServerHello response (SSLVersion, Ciphers, Extensions). Together, JA3 + JA3S identify specific client-server pairs regardless of IP/domain rotation.

**TLS Certificate Extraction**
```bash
# Extract certificate from pcap with openssl
openssl s_client -connect target.com:443 -showcerts < /dev/null 2>/dev/null | \
  openssl x509 -text -noout

# Extract certificates from pcap with tshark
tshark -r capture.pcap -Y "tls.handshake.certificate" \
  -T fields -e tls.handshake.certificate > certs_hex.txt

# Decode certificate
echo "308203..." | xxd -r -p | openssl x509 -inform DER -text -noout
```

**JARM Active Fingerprinting**
JARM probes a TLS server with 10 specially crafted ClientHellos and hashes the server responses to produce a 62-character fingerprint identifying the TLS server implementation.
```bash
python3 jarm.py target.com 443
# Known JARM fingerprints: Cobalt Strike, Metasploit, Cobalt Strike with profile changes
```

### SMB/RPC Analysis

```
# Wireshark display filters for SMB forensics
smb2
smb2.cmd == 5          # SMB2 Create (file open)
smb2.cmd == 8          # SMB2 Read
smb2.cmd == 9          # SMB2 Write
smb2.cmd == 14         # SMB2 IoctlRequest
smb2.filename contains "ADMIN$"    # Admin share access
smb2.tree contains "\\\\10.0.0.1\\"  # Tree connect to remote share
```

### Email Protocol Forensics

**SMTP Transaction Analysis**
```
# Track SMTP session
smtp
smtp.req.command == "MAIL"     # Envelope sender
smtp.req.command == "RCPT"     # Envelope recipient
smtp.req.command == "DATA"     # Message body follows
smtp.response.code == 250      # Message accepted

# Extract Message-ID for correlation
tshark -r capture.pcap -Y smtp -T fields -e smtp.req.parameter | grep "Message-ID"
```

**MIME Extraction**
- Use `munpack` or NetworkMiner to extract MIME attachments from SMTP captures.
- Hash extracted files for VirusTotal lookup: `sha256sum extracted_file.exe`

### FTP/SFTP Session Reconstruction

```bash
# FTP uses separate control (port 21) and data channels (PASV negotiates port)
# Follow control channel for commands
tshark -r capture.pcap -Y "ftp" -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg

# Reassemble FTP-DATA stream with tcpflow
tcpflow -r capture.pcap -o ftp-sessions/ port 20 or portrange 1024-65535

# SFTP is tunneled over SSH (port 22); reconstruct sessions from Zeek files.log
grep "SFTP\|SSH" files.log
```

### VoIP Forensics

```
# SIP signaling analysis
sip
sip.Method == "INVITE"
sip.Status-Code == 200

# RTP media streams
rtp

# Follow RTP stream: Telephony → VoIP Calls → select call → Player
# Export audio: Telephony → RTP → Stream Analysis → Save payload
```

### Custom Protocol Decoding with Lua

```lua
-- Minimal Wireshark Lua dissector skeleton
local myproto = Proto("myproto", "My Custom Protocol")
local f_type = ProtoField.uint8("myproto.type", "Message Type", base.HEX)
local f_len  = ProtoField.uint16("myproto.length", "Length", base.DEC)
myproto.fields = {f_type, f_len}

function myproto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "MYPROTO"
    local subtree = tree:add(myproto, buffer())
    subtree:add(f_type, buffer(0,1))
    subtree:add(f_len,  buffer(1,2))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(4444, myproto)
```

---

## 4. NetFlow & Traffic Analysis

### NetFlow Format Comparison

| Feature | NetFlow v5 | NetFlow v9 | IPFIX (RFC 7011) |
|---|---|---|---|
| Transport | UDP | UDP | UDP/SCTP/TCP |
| Header | 24-byte fixed | Variable | Variable |
| Template | Fixed 7-field | Template-based | Template-based (IANA IEs) |
| IPv6 support | No | Yes | Yes |
| MPLS | No | Yes | Yes |
| Variable-length | No | No | Yes |
| Extensibility | None | High | Very high (enterprise IEs) |

**NetFlow v5 Record Fields**: srcaddr, dstaddr, nexthop, input (SNMP ifIndex), output, dPkts, dOctets, first (SysUpTime ms), last, srcport, dstport, tcp_flags, prot, tos, src_as, dst_as, src_mask, dst_mask

**NetFlow v9 Template Flexibility**: Exporters send template flowsets before data flowsets. Common fields: PROTOCOL, L4_SRC_PORT, L4_DST_PORT, IPV4_SRC_ADDR, IPV4_DST_ADDR, IN_BYTES, IN_PKTS, DIRECTION, INPUT_SNMP, OUTPUT_SNMP, FIRST_SWITCHED, LAST_SWITCHED.

### Collector/Exporter Architecture

```
Router/Switch (Exporter) ──UDP──► Flow Collector ──► Storage/Analysis
                                        │
                                   nfcapd (nfdump)
                                   flow-tools
                                   ntopng
                                   Elastic Flow
                                   Scrutinizer
```

### nfdump Analysis Commands

```bash
# Basic read
nfdump -r /data/flows/nfcapd.202401010000 -o long

# Time range across multiple files
nfdump -R /data/flows/nfcapd.2024010100:nfcapd.2024010200

# Top N talkers by bytes
nfdump -r file.nf -s srcip/bytes -n 20

# Top N destinations
nfdump -r file.nf -s dstip/flows -n 20

# Filter: traffic to specific IP
nfdump -r file.nf 'dst ip 203.0.113.42'

# Filter: long-duration flows (beaconing candidates)
nfdump -r file.nf -o long 'duration > 3600'

# Filter: high-volume outbound to external
nfdump -r file.nf 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8 and bytes > 10000000'

# Stat mode: aggregated by protocol
nfdump -r file.nf -s record/bytes -n 10 -o long

# Aggregation by IP pair
nfdump -r file.nf -A srcip,dstip -o long 'proto tcp'

# Time series (flows per minute)
nfdump -r file.nf -t 2024-01-01/00:00:00:2024-01-01/01:00:00 -o line
```

### SiLK (System for Internet-Level Knowledge)

SiLK is the CERT NetSA toolkit for large-scale flow analysis:

```bash
# Convert NetFlow to SiLK binary format
flowcap | rwflowpack

# Filter flows
rwfilter --start-date=2024/01/01 --end-date=2024/01/01 \
  --proto=6 --any-port=443 --pass=stdout | rwcut

# Top N source IPs by bytes
rwfilter --pass=stdout ... | rwstats --fields=sip --value=bytes --count=20

# Count flows per 5-minute bin
rwfilter --pass=stdout ... | rwcount --bin-size=300

# Unique IP pairs
rwfilter --pass=stdout ... | rwuniq --fields=sip,dip --value=flows,bytes,packets

# Beaconing detection: look for regularly-spaced connections
rwfilter --pass=stdout --any-address=203.0.113.42 | rwcut --fields=sTime,sIP,dIP | sort
```

### Argus Flow Analysis

```bash
# Capture to Argus format
argus -i eth0 -w capture.argus

# Read with ra client
ra -r capture.argus -s saddr daddr sport dport proto dur sbytes dbytes

# Binetflow output (bidirectional)
ra -r capture.argus -s saddr daddr proto dur totpkts totbytes -c ','
```

### Baseline Creation & Anomaly Detection

**Daily/Weekly Traffic Baseline Metrics**
- Total bytes per hour by direction (in/out)
- Top 20 external IP destinations by bytes and flows
- Port usage distribution (unique dst ports per hour)
- New external IP addresses not seen in prior 30 days
- DNS query volume per hour
- SMTP relay volume (messages and bytes)

**Anomaly Detection Criteria**

| Anomaly | Detection Method |
|---|---|
| New external IP | Compare dst IPs against 30-day whitelist |
| Unusual port | Port not seen in baseline → alert |
| Data volume spike | Z-score > 3 on hourly bytes outbound |
| Long-duration low-rate connection | Duration > 4h AND bytes/hour < 10KB |
| Beaconing | StdDev of inter-connection intervals < 5% of mean |
| Non-business-hours traffic | Outbound flows 2:00-5:00 local time |
| DNS exfiltration | Query name length > 100 chars or > 1000 queries/min to single domain |

**Automated Beaconing Detection**
```python
import statistics
from collections import defaultdict

def detect_beaconing(flows, threshold_cv=0.1):
    """Coefficient of Variation < threshold indicates regular beaconing."""
    connections = defaultdict(list)
    for f in flows:
        key = (f['src'], f['dst'], f['dport'])
        connections[key].append(f['timestamp'])
    
    beacons = []
    for key, times in connections.items():
        if len(times) < 10:
            continue
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            continue
        cv = statistics.stdev(intervals) / mean_interval
        if cv < threshold_cv:
            beacons.append({'flow': key, 'interval': mean_interval, 'cv': cv, 'count': len(times)})
    return sorted(beacons, key=lambda x: x['cv'])
```

---

## 5. Malware Traffic Analysis

### C2 Communication Patterns

**Periodic Beaconing**
- Most implants check in at regular intervals (15s to 1h) to receive commands.
- Jitter (randomization of ±10-30%) is added by sophisticated frameworks to evade simple interval-based detection.
- Detection: analyze connection intervals for coefficient of variation; legitimate applications rarely beacon.

**HTTP GET/POST Patterns**
- GET-based beaconing: implant sends check-in as HTTP GET with encoded data in URI or custom headers.
- POST-based: task results exfiltrated in POST body (often base64 or XOR encoded).
- Look for: consistent URI length with variable data, unusual HTTP verbs (OPTIONS, PUT), missing standard headers.

**DNS Beaconing**
- Implant encodes data in DNS subdomain labels; resolver delivers to attacker-controlled authoritative DNS.
- Query pattern: `<base64_data>.<session_id>.c2domain.com`
- Detection: high query rate to same parent domain, long subdomains, high entropy in subdomain labels, no corresponding HTTP traffic.

**ICMP Tunneling**
- Data encoded in ICMP echo (ping) payload; unusual payload size or content.
- Legitimate ping payloads are 32-64 bytes; tunneled ICMP may carry 1400+ byte payloads.
- `icmp.data.len > 64` in Wireshark to identify suspicious ICMP.

### Identifying Malware Families by Traffic Pattern

**Cobalt Strike Beacon**
- Default beacon interval: 60 seconds (configurable via Malleable C2 profile).
- Default staging: GET to `/updates` or random URI specified in profile.
- Default JA3 (HTTPS beacon): `b70de2e22a17a7ddd01c9beae47a8cc9`
- Default JARM varies by listener type (HTTP/HTTPS/SMB/DNS).
- Malleable C2 profiles transform HTTP headers, URI, and body; behavioral analysis needed to identify non-default profiles.
- Look for: jitter around 60s intervals, consistent User-Agent from profile, base64 response body.

**Emotet/Qakbot/IcedID Loader Traffic**
- Emotet: C2 over HTTPS to multiple IPs in rapid succession (module download); uses TLS with self-signed certs; fast-flux C2 IP rotation.
- Qakbot: uses HTTPS to compromised websites for C2; characteristic Accept-Language header variations; also uses SMB for lateral movement.
- IcedID: HTTPS C2 with legitimate-looking server certificates; uses GOZIv2 network protocol; often delivered via compromised legitimate sites.

**Ransomware Pre-Encryption Staging**
1. Credential harvesting: Mimikatz output via SMB to attacker C2 or RDP-accessible drop server.
2. Reconnaissance: SMB scanning (`\\target\ADMIN$` enumeration), network share discovery.
3. Data staging: large outbound transfers to cloud storage (Mega, Rclone, SFTP) before encryption.
4. Lateral movement: PsExec over SMB, WMI over port 135, RDP, Cobalt Strike SMB beacon.
5. Ransomware deployment: SMB file copy + remote execution; watch for same binary deployed to many hosts in short time.

### Suricata ET Rules for Malware Traffic

```
# Key ET categories for malware detection
ET MALWARE        - Known malware family signatures
ET CNC            - C2 server communications
ET TROJAN         - Trojan-specific patterns
ET DNS            - DNS-based threats (DGA, tunneling)
ET EXPLOIT        - Exploitation attempt signatures

# Example rule structure (ET MALWARE Cobalt Strike)
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Beacon Observed";
  flow:established,to_server;
  content:"GET"; http_method;
  content:"/updates"; http_uri;
  classtype:trojan-activity;
  sid:2019714; rev:3;
)
```

### PCAP Analysis Workflow

```
1. Capture/Obtain PCAP
   └── Verify hash, document chain of custody

2. Identify Unusual Flows
   ├── Zeek conn.log: long duration, high bytes
   ├── New external IPs not in baseline
   └── Unusual port usage

3. Decode Protocol
   ├── Apply Wireshark display filters
   ├── Follow TCP/UDP stream
   └── Identify encoding (base64, XOR, custom)

4. Extract IOCs
   ├── IP addresses, domains, URLs
   ├── JA3/JA3S hashes
   ├── File hashes from extracted payloads
   └── Network signatures (byte sequences)

5. Correlate with Threat Intelligence
   ├── VirusTotal (IP/domain/file lookups)
   ├── Shodan (infrastructure fingerprinting)
   ├── MISP (IOC correlation)
   └── Vendor-specific feeds (Recorded Future, Mandiant, etc.)
```

### Extracting Files from PCAP

```bash
# tcpxtract: extract files by magic bytes
tcpxtract -f capture.pcap -o extracted/

# foremost: carve files from raw stream
tcpflow -r capture.pcap -o streams/
foremost -i streams/001.stream -o carved/

# Zeek file extraction script
# In zeek local policy:
@load base/frameworks/files/magic
redef FileExtract::prefix = "/data/zeek-files/";
event files::local_file(f: fa_file) {
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}

# NetworkMiner: GUI → Files tab → right-click → Open folder

# Hash and lookup all extracted files
find extracted/ -type f -exec sha256sum {} \; > hashes.txt
# Submit to VirusTotal API in bulk
```

---

## 6. Incident Reconstruction from Network Evidence

### Building a Network Timeline

Effective incident reconstruction requires correlating evidence across multiple data sources with accurate timestamps. All sources must be verified against NTP-synchronized UTC.

**Evidence Source Correlation Matrix**

| Evidence Source | Timestamp Field | Key Identifier | Linked To |
|---|---|---|---|
| PCAP | frame.time (UTC) | 5-tuple | Flow record |
| Zeek conn.log | ts (epoch) | uid + 5-tuple | All Zeek logs via uid |
| NetFlow | FIRST_SWITCHED | 5-tuple | PCAP session |
| Firewall logs | timestamp | 5-tuple + rule | Connection |
| DHCP logs | timestamp | MAC + IP + hostname | IP address |
| DNS logs | timestamp | client IP + query | PCAP DNS session |
| Proxy logs | timestamp | client IP + URL | HTTP session |
| SIEM alert | event time | alert ID + IOC | Triggering log |

**DHCP → IP → Hostname → User Mapping Chain**
```bash
# Step 1: Find IP from DHCP logs at time of event
grep "192.168.1.142" /var/log/dhcp.log | awk '{print $1, $2, $5, $6}'
# Output: 2024-01-15 14:23:01 DHCPACK to 192.168.1.142 for 00:11:22:33:44:55 (DESKTOP-ABC123)

# Step 2: Correlate hostname to AD user from Windows event logs
# Event 4624 (Logon): look for DESKTOP-ABC123 workstation logons near that time

# Step 3: Map MAC to port/switch for physical location
snmpwalk -v2c -c public switch.corp.local BRIDGE-MIB::dot1dTpFdbPort | grep "33:44:55"
```

### Session Reconstruction

**TCP Stream Reconstruction**
```bash
# tcpflow: reconstruct application-layer data per session
tcpflow -r capture.pcap -o sessions/ -a
# Creates files named by IP:port pairs; also generates report.xml

# Wireshark: Right-click on packet → Follow → TCP Stream
# Shows complete request/response in human-readable form

# Reassemble specific session by 4-tuple
tcpflow -r capture.pcap -o single/ host 10.0.0.1 and host 203.0.113.5 and port 443
```

### Reconstructing Web Sessions

**HTTP Request/Response Sequence**
```
1. DNS query: resolve target.com → 203.0.113.5 (timestamp T1)
2. TCP SYN to 203.0.113.5:443 (timestamp T2, ~T1+1ms)
3. TLS ClientHello + ServerHello (timestamp T3)
4. HTTP GET /login.php with Cookie: session=... (timestamp T4)
5. HTTP 200 response with Set-Cookie: new_session=... (timestamp T5)
6. HTTP POST /admin/exec.php with payload (timestamp T6) ← attacker action
7. HTTP 200 with command output (timestamp T7)

# Timeline shows: DNS pre-resolution, TLS establishment, authentication, command execution
```

**Cookie Tracking for Session Attribution**
```
# Extract cookies from HTTP stream
tshark -r capture.pcap -Y "http.cookie" -T fields -e frame.time -e ip.src -e http.cookie -e http.request.uri

# Correlate Set-Cookie with subsequent Cookie headers to track session
tshark -r capture.pcap -Y "http.set_cookie" -T fields -e frame.time -e ip.src -e http.set_cookie
```

### Email Incident Reconstruction

**SMTP Log Analysis**
```
# Reconstruct email relay chain from SMTP logs (Postfix format)
grep "message-id=<attack@evil.com>" /var/log/mail.log

# Key fields in SMTP transaction (from PCAP)
# EHLO: connecting client hostname/IP
# MAIL FROM: envelope sender (may differ from From: header)
# RCPT TO: envelope recipient
# DATA: message body + MIME parts
# Received: headers in message show relay hops with timestamps

# Extract Message-ID for cross-system correlation
tshark -r capture.pcap -Y "smtp.req.command == \"DATA\"" -T fields -e smtp.req.parameter | \
  grep -i "Message-ID" | head -20
```

### Lateral Movement Reconstruction

**SMB + Authentication Timing Analysis**
```
# Correlate: Windows Event 4624 (Logon Type 3 = Network) with SMB connection in PCAP

# Step 1: Find SMB connections to host in PCAP
tshark -r capture.pcap -Y "smb2 and ip.dst == 10.0.0.50" \
  -T fields -e frame.time -e ip.src -e smb2.cmd -e smb2.filename

# Step 2: Correlate timestamp with authentication events
# Event 4624 LogonType=3 on 10.0.0.50 at 14:32:15 matches SMB connection from 10.0.0.20 at 14:32:15

# Step 3: Check subsequent lateral movement from 10.0.0.50
# 10.0.0.50 → 10.0.0.51 SMB at 14:32:45 (30 seconds later = scripted)
```

### Data Exfiltration Quantification

```bash
# Sum bytes transferred to external IP using nfdump
nfdump -r flows/ -s dstip/bytes 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8' -n 10

# Same using Zeek conn.log
awk '!/^#/ {if ($7 !~ /^10\./ && $7 !~ /^192\.168\./) sum[$7]+=$11} \
  END {for (ip in sum) print sum[ip], ip}' conn.log | sort -rn | head -20

# DNS exfiltration byte estimation
# Each DNS query label = max 63 chars; typical encoding = 50 usable chars
# 1000 queries/min to same domain = 50,000 chars/min ≈ 3MB/hour
tshark -r capture.pcap -Y "dns.flags.response == 0 and dns.qry.name contains \"evil.com\"" \
  -T fields -e dns.qry.name | awk '{len += length($1)} END {print "Total encoded bytes:", len}'
```

### VPN Forensics

```
# OpenVPN over UDP 1194: identify handshake phase
udp.port == 1194

# WireGuard handshake initiation (type = 1, 148 bytes)
udp and frame.len == 148

# IPsec IKEv2: identify SA negotiation
isakmp
isakmp.typepayload == 33    # SA payload
isakmp.typepayload == 34    # KE (Diffie-Hellman)

# Correlate VPN auth log with tunnel traffic timing
# 1. Auth log: user "jsmith" authenticated at 14:22:33, assigned 10.8.0.5
# 2. VPN traffic from 10.8.0.5 starting at 14:22:35 = jsmith's activity
```

### Cloud Incident Reconstruction

```sql
-- AWS: Correlate VPC Flow Logs with CloudTrail API calls
-- Step 1: Find suspicious outbound flow in VPC Flow Logs
SELECT srcaddr, dstaddr, dstport, bytes, start, end
FROM vpc_flow_logs
WHERE srcaddr = '10.0.1.45' AND action = 'ACCEPT'
  AND dstaddr NOT LIKE '10.%'
ORDER BY bytes DESC LIMIT 10;

-- Step 2: Find CloudTrail events from same EC2 instance around same time
SELECT eventTime, eventName, sourceIPAddress, userAgent, requestParameters
FROM cloudtrail_logs
WHERE sourceIPAddress = '10.0.1.45'
  AND eventTime BETWEEN '2024-01-15T14:00:00Z' AND '2024-01-15T15:00:00Z'
ORDER BY eventTime;
```

---

## 7. Encrypted Traffic Analysis

### Challenges of Encrypted Traffic

TLS 1.3 (RFC 8446) encrypts the Certificate message and removes many previously-visible handshake fields, significantly reducing metadata available for inspection. Key challenges:

- **No plaintext SNI in TLS 1.3 with ECH** (Encrypted Client Hello, draft RFC): destination hostname is encrypted.
- **Forward secrecy**: ECDHE key exchange means private key compromise does not enable retrospective decryption of captured traffic.
- **QUIC/HTTP3**: UDP-based, encrypted at the transport layer; QUIC Initial packets are cleartext for CRYPTO frames but subsequent records are encrypted.
- **Certificate pinning**: prevents MITM inspection by client applications.
- **SSL inspection proxies**: effective but legally complex, technically intrusive, and ineffective against certificate-pinned apps.

### JA3/JA3S Fingerprinting Methodology

**JA3 Construction**
```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
→ concatenate with dashes within groups, commas between groups
→ MD5 hash of resulting string

Example:
771,4866-4867-4865-...,0-23-65281-10-11-35-16-5-...,29-23-24,0
→ MD5 = "aaa" (browser-specific fingerprint)
```

**JA3 Databases and Feeds**
- **ja3er.com**: community database mapping JA3 hashes to user-agent strings.
- **abuse.ch JA3 Fingerprint Feed**: malicious JA3 hashes associated with malware families.
- **Salesforce/Joe Security**: JA3 research publications with known-bad hash lists.
- Local detection: maintain a whitelist of expected JA3 hashes for your environment.

**JARM Active Fingerprinting**
```bash
# Probe target TLS server
python3 jarm.py 203.0.113.42 443

# Compare against known-bad JARM fingerprints:
# Cobalt Strike default:  07d14d16d21d21d07c42d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926
# Metasploit default:     07d19d1ad21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823
# Interactsh:             2ad2ad0002ad2ad22c2ad2ad2ad2ad4e1e27286e2ad2ad2ad2ad2ad2ad2ad

# Store JARM of all internet-facing servers as baseline
```

### Traffic Metadata Analysis

Even without decryption, metadata reveals significant information:

**Packet Timing Analysis**
- TLS record sizes leak application-layer protocol details (e.g., consistent 1400-byte TLS records may indicate file transfer vs. interactive sessions with small variable-size records).
- Inter-packet timing fingerprints interactive protocols (SSH keystrokes: < 20ms inter-packet gaps) vs. bulk transfer.

**Flow Duration Patterns**
- Beaconing C2: many short flows with regular timing, small data volume per session.
- Legitimate HTTPS: varied flow durations, larger data volumes (page loads: 50KB-5MB).
- Tunneled protocols: extremely long-duration flows with low data rate (e.g., ICMP/DNS tunnel).

**Size Distribution Analysis**
```python
# Compare packet size distributions between flows
import collections

def packet_size_distribution(packets):
    sizes = [len(p) for p in packets]
    return {
        'mean': sum(sizes)/len(sizes),
        'median': sorted(sizes)[len(sizes)//2],
        'distribution': collections.Counter(
            round(s/100)*100 for s in sizes  # round to nearest 100 bytes
        )
    }
```

### ML-Based Encrypted Traffic Classification

**ACSAC / Cisco ETA Approach (Encrypted Traffic Analytics)**
- Feature vector: Sequence of first N packet lengths + inter-arrival times (SPLT)
- Also uses: byte distribution, TLS record lengths, initial data packet (IDP) analysis
- Models: Random Forest, Gradient Boosting, Neural Networks trained on labeled flow data
- Cisco ETA: embedded in switches, uses telemetry exported to Stealthwatch; no decryption required

**Implementation Approach**
```python
# Feature extraction from flow for ML classification
def extract_flow_features(flow_packets):
    features = {}
    # Sequence of first 5 packet lengths and inter-arrival times
    lengths = [len(p) for p in flow_packets[:5]]
    iats = [flow_packets[i+1].time - flow_packets[i].time 
            for i in range(min(4, len(flow_packets)-1))]
    features['mean_pkt_len'] = sum(lengths) / len(lengths)
    features['std_pkt_len'] = statistics.stdev(lengths) if len(lengths) > 1 else 0
    features['mean_iat'] = sum(iats) / len(iats) if iats else 0
    features['bytes_ratio'] = flow_packets[0].payload_size / max(flow_packets[-1].payload_size, 1)
    return features
```

### SNI Extraction and Certificate Transparency

```bash
# Extract all SNI values from a capture
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | \
  sort -u > sni_list.txt

# Categorize SNI against threat intelligence
while read ip sni; do
  # Query passive DNS, categorization services
  echo "$sni" | grep -f malicious_domains.txt
done < sni_list.txt

# Certificate Transparency lookup (crt.sh)
curl -s "https://crt.sh/?q=%.evil.com&output=json" | python3 -c \
  "import json,sys; [print(c['name_value']) for c in json.load(sys.stdin)]"

# Extract certificate from pcap for CT log correlation
tshark -r capture.pcap -Y "tls.handshake.certificate" -T fields \
  -e tls.handshake.certificate > cert_der_hex.txt
echo "$(head -1 cert_der_hex.txt)" | xxd -r -p | \
  openssl x509 -inform DER -noout -fingerprint -sha256
```

### QUIC/HTTP3 Forensics

```
# Identify QUIC traffic (UDP 443)
udp.port == 443 and udp.length > 1200

# QUIC Initial packets have plaintext CRYPTO frames (before encryption)
# Version: 0x00000001 (QUICv1)
# Display filter for QUIC
quic

# QUIC Long Header packet types:
# 0x00 = Initial (contains TLS ClientHello in CRYPTO frame)
# 0x02 = Handshake (contains TLS Finished)
# 0x03 = Retry

# Extract SNI from QUIC Initial packet (same as TLS ClientHello SNI)
quic.tls.handshake.extensions_server_name
```

---

## 8. Wireless & Remote Access Forensics

### 802.11 Frame Forensics

**Capture Setup**
```bash
# Enable monitor mode
airmon-ng start wlan0
# Capture on specific channel
tcpdump -i wlan0mon -w wireless.pcap

# Capture on all channels (channel hopping) with airodump-ng
airodump-ng --write capture --output-format pcap wlan0mon

# Filter by BSSID (AP MAC address)
tcpdump -i wlan0mon -w ap_capture.pcap 'ether host AA:BB:CC:DD:EE:FF'
```

**802.11 Frame Types in Wireshark**
```
# Management frames (type = 0)
wlan.fc.type == 0
wlan.fc.subtype == 8    # Beacon
wlan.fc.subtype == 4    # Probe Request
wlan.fc.subtype == 5    # Probe Response
wlan.fc.subtype == 11   # Authentication
wlan.fc.subtype == 0    # Association Request

# Control frames (type = 1)
wlan.fc.type == 1
wlan.fc.subtype == 11   # RTS
wlan.fc.subtype == 12   # CTS
wlan.fc.subtype == 13   # ACK

# Data frames (type = 2)
wlan.fc.type == 2

# Key fields: BSSID, SSID, channel, signal strength (radiotap header)
wlan.bssid, wlan.ssid, radiotap.channel.freq, radiotap.dbm_antsignal
```

**Deauthentication Flood Detection**
```
# Filter for deauth frames
wlan.fc.type_subtype == 0x000c

# High rate of deauth frames from single source = deauth flood attack
wlan.fc.type_subtype == 0x000c and wlan.sa == "AA:BB:CC:DD:EE:FF"

# Deauth reason codes:
# 6 = Class 2 frame received from nonauthenticated station
# 7 = Class 3 frame received from nonassociated station
```

**WPA2 4-Way Handshake Analysis**
```
# Filter for EAPOL (WPA2 handshake key exchange)
eapol

# Handshake sequence:
# Frame 1: AP → Client: ANonce (Authenticator Nonce)
# Frame 2: Client → AP: SNonce + MIC (Supplicant Nonce)
# Frame 3: AP → Client: GTK (encrypted Group Temporal Key) + MIC
# Frame 4: Client → AP: ACK

# Export handshake for offline cracking (hashcat format)
# Use hcxpcapngtool (formerly cap2hccapx)
hcxpcapngtool -o hash.hc22000 wireless.pcap
```

**Evil Twin Detection**
```bash
# Identify multiple APs with same SSID but different BSSID
tshark -r wireless.pcap -Y "wlan.fc.subtype == 8" \
  -T fields -e wlan.ssid -e wlan.bssid -e radiotap.channel.freq | \
  sort -u | awk -F'\t' '{ssid[$1][bssid]=$2} END {for (s in ssid) if (length(ssid[s]) > 1) print s}'

# More precise: same SSID + different BSSID + different channel or signal level
# Compare RSN Information Elements; evil twin may lack WPA2 PMKID or have different cipher suites
```

### VPN Forensics

**OpenVPN**
```
# OpenVPN over UDP 1194
udp.port == 1194

# OpenVPN over TCP 443 (obfuscated mode)
tcp.port == 443 and data.len > 0 and not tls

# OpenVPN packet opcode (first nibble of first byte after 2-byte length):
# 0x08 = TLS_CLIENT_HELLO
# 0x40 = CONTROL_V1 (key negotiation)
# 0x60 = ACK_V1
# 0x70 = DATA_V1
```

**WireGuard**
```
# WireGuard uses UDP (default port 51820 but configurable)
# Handshake Initiation: 148-byte UDP packet with message type = 1
udp and frame.len == 148

# Handshake Response: 92-byte packet
udp and frame.len == 92

# Identify WireGuard sessions by consistent packet size distribution
# Data packets are variable-length encrypted UDP datagrams
```

**IPsec IKEv2**
```
# IKE/ISAKMP phase 1 (UDP 500 or UDP 4500 for NAT-T)
isakmp

# IKE_SA_INIT exchange (SPI = 0, exchange type = 34)
isakmp.extype == 34

# IKE_AUTH exchange (exchange type = 35)
isakmp.extype == 35

# Identify NAT-T (UDP 4500, non-ESP marker prefix)
udp.port == 4500
```

### RADIUS Authentication Forensics

**802.1X RADIUS Accounting Fields**

| RADIUS Attribute | Description | Forensic Value |
|---|---|---|
| Acct-Session-Id | Unique session identifier | Correlates auth log with network traffic |
| NAS-IP-Address | Network Access Server IP (switch/AP) | Physical location of access point |
| NAS-Port-Id | Interface/port identifier | Switch port → physical location |
| Framed-IP-Address | IP assigned to client | Maps to all subsequent traffic |
| User-Name | Authenticated username | Ties network activity to person |
| Acct-Session-Time | Session duration | Determines access window |
| Acct-Input-Octets | Bytes received by client | Volume of inbound data |
| Acct-Output-Octets | Bytes sent by client | Volume of outbound data |
| Called-Station-Id | BSSID of AP (wireless) | Identifies specific AP |
| Calling-Station-Id | Client MAC address | Device identification |

```bash
# Parse RADIUS log to build IP-to-user-to-time mapping
grep "Acct-Status-Type = Start" /var/log/radius/radius.log | \
  awk '/User-Name/ {user=$NF} /Framed-IP/ {ip=$NF} /Acct-Session-Id/ {id=$NF} \
    /NAS-IP/ {nas=$NF} END {print user, ip, nas, id}' | sort
```

### RDP Forensics

```
# RDP runs on TCP 3389 by default
tcp.port == 3389

# CredSSP negotiation (NTLM/Kerberos credentials over TLS)
# TPKT + COTP + RDP Negotiation Request
rdp

# RDP connection sequence:
# 1. TCP SYN/SYN-ACK/ACK (TCP handshake)
# 2. Client Connection Request (COTP CC)
# 3. Server Connection Confirm
# 4. TLS/CredSSP negotiation (authentication)
# 5. Client Security Exchange
# 6. Client Info (username, domain, timezone)
# 7. License negotiation
# 8. Capability exchange
# 9. Session begin (graphics/input channels)

# Identify RDP on non-standard ports (common evasion)
tcp and tcp.payload[0:3] == 03:00:00 and frame.len < 100
```

---

## 9. Cloud & Container Network Forensics

### AWS VPC Flow Logs

**Log Format (v2)**
```
# Fields: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789010 eni-0a12b34c d56e7f89 10.0.1.15 52.84.12.99 54231 443 6 14 7340 1620000000 1620000060 ACCEPT OK
2 123456789010 eni-0a12b34c d56e7f89 203.0.113.45 10.0.1.15 4444 4444 6 0 0 1620000000 1620000060 REJECT OK

# Protocol numbers: 6=TCP, 17=UDP, 1=ICMP, 50=ESP, 51=AH
```

**Athena Queries for Incident Response**

```sql
-- Top external destinations by bytes (potential exfiltration)
SELECT dstaddr,
       SUM(bytes) AS total_bytes,
       COUNT(*) AS flow_count,
       SUM(packets) AS total_packets
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND dstaddr NOT LIKE '10.%'
  AND dstaddr NOT LIKE '172.16.%'
  AND dstaddr NOT LIKE '192.168.%'
  AND from_unixtime(start) >= current_timestamp - interval '24' hour
GROUP BY dstaddr
ORDER BY total_bytes DESC
LIMIT 20;

-- All REJECTED inbound connections (reconnaissance)
SELECT srcaddr, dstport, COUNT(*) as attempts
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND dstaddr LIKE '10.%'
GROUP BY srcaddr, dstport
ORDER BY attempts DESC;

-- Connections to known-bad IP
SELECT srcaddr, dstaddr, srcport, dstport, bytes, start, end
FROM vpc_flow_logs
WHERE dstaddr IN ('203.0.113.1', '198.51.100.42', '192.0.2.99')
  AND action = 'ACCEPT';

-- East-west traffic (lateral movement indicator)
SELECT srcaddr, dstaddr, dstport, SUM(bytes) as bytes
FROM vpc_flow_logs
WHERE srcaddr LIKE '10.%' AND dstaddr LIKE '10.%'
  AND dstport IN (445, 3389, 22, 135, 5985, 5986)
GROUP BY srcaddr, dstaddr, dstport
ORDER BY bytes DESC;

-- Beaconing detection: regular intervals from one source to one destination
SELECT srcaddr, dstaddr, dstport,
       COUNT(*) as connections,
       MAX(start) - MIN(start) as time_span,
       STDDEV(start) as timing_stddev
FROM vpc_flow_logs
WHERE start >= 1620000000 AND start <= 1620086400
GROUP BY srcaddr, dstaddr, dstport
HAVING COUNT(*) > 10 AND STDDEV(start) < 60
ORDER BY timing_stddev;
```

### Azure NSG Flow Logs

**v2 JSON Format**
```json
{
  "time": "2024-01-15T14:32:00Z",
  "systemId": "...",
  "category": "NetworkSecurityGroupFlowEvent",
  "properties": {
    "flows": [{
      "rule": "DefaultRule_AllowInternetOutBound",
      "flows": [{
        "mac": "000D3A123456",
        "flowTuples": ["1705329120,10.0.0.5,52.84.12.99,54321,443,T,O,A,B,10,5000,8,7500"]
      }]
    }]
  }
}
```

**Sentinel KQL Query**
```kql
// Top external destinations from NSG flow logs
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where FlowDirection_s == "O" and FlowStatus_s == "A"
| where not(DestPublicIPs_s has_any ("10.", "172.16.", "192.168."))
| summarize TotalBytes = sum(OutboundBytes_d), Flows = count() by DestPublicIPs_s
| order by TotalBytes desc
| take 20
```

### Container Network Forensics

**Docker Bridge Network**
```bash
# Inspect Docker network
docker network inspect bridge

# View container iptables rules
iptables -L -n -v --line-numbers | grep DOCKER

# Capture container traffic using nsenter + tcpdump
PID=$(docker inspect -f '{{.State.Pid}}' mycontainer)
nsenter -t $PID -n tcpdump -i eth0 -w /tmp/container.pcap

# Alternatively: capture on docker0 bridge (all containers on bridge network)
tcpdump -i docker0 -w /tmp/docker-bridge.pcap
```

**Cilium Hubble (eBPF-based observability)**
```bash
# List recent flows
hubble observe --last 100

# Filter by namespace and direction
hubble observe --namespace production --type drop

# Filter specific IP pair
hubble observe --from-ip 10.0.0.5 --to-ip 10.0.0.10

# Export flows as JSON for analysis
hubble observe --output json --last 1000 > flows.json

# Watch specific pod communication
hubble observe --pod frontend/nginx-pod --follow
```

### Kubernetes Network Policy Audit

```bash
# List all network policies
kubectl get networkpolicies --all-namespaces -o yaml

# Trace which pods a policy applies to
kubectl get pods --selector app=frontend -o wide

# Check effective network policies for a pod
# (requires Cilium or similar CNI with policy visibility)
hubble observe --pod default/suspicious-pod --follow

# Kubernetes audit log for API server calls (network-related)
# In audit log, filter for NetworkPolicy resource changes
kubectl get events --field-selector reason=NetworkPolicyChanged

# CNI plugin logs (varies by CNI)
# Calico
kubectl logs -n kube-system -l k8s-app=calico-node | grep "Policy"
# Cilium
kubectl logs -n kube-system -l k8s-app=cilium | grep "DENIED\|ACCEPT"
```

### Service Mesh Forensics (Istio)

```bash
# Istio Envoy access logs (JSON format)
kubectl logs -n production deploy/frontend -c istio-proxy | \
  python3 -c "import json,sys; [print(json.dumps(json.loads(l))) for l in sys.stdin]" | \
  jq 'select(.response_code == 403 or .response_code >= 500)'

# Key Envoy log fields:
# downstream_remote_address: client IP
# upstream_host: backend service endpoint
# method, path, protocol: HTTP request details
# response_code: HTTP response
# bytes_received, bytes_sent: payload sizes
# duration: request latency
# x_forwarded_for: original client IP through proxy chain

# Extract mTLS certificate info from Envoy pcap
tshark -r envoy-capture.pcap -Y "tls.handshake.certificate" \
  -T fields -e tls.handshake.certificate | head -1 | xxd -r -p | \
  openssl x509 -inform DER -text -noout | grep -E "Subject:|Issuer:|Not After"
```

### Serverless & Lambda Network Forensics

```bash
# Lambda functions in VPC: traffic goes through NAT Gateway
# CloudWatch Logs Insights for Lambda VPC NAT traffic
# 1. Enable VPC Flow Logs on NAT Gateway ENI

# CloudWatch Logs Insights query for Lambda execution
fields @timestamp, @message
| filter @message like /ERROR|REPORT|Task timed out/
| sort @timestamp desc
| limit 50

# Correlate Lambda execution ID with VPC Flow Log
# Lambda logs: "RequestId: abc-123-def-456 ..."
# VPC Flow Log: srcaddr = NAT Gateway private IP, timestamp overlaps with Lambda execution

# API Gateway access logs for Lambda invocations
aws logs filter-log-events \
  --log-group-name /aws/api-gateway/myapi \
  --filter-pattern "{ $.httpMethod = \"POST\" && $.status >= 400 }" \
  --start-time 1705329600000 \
  --end-time 1705416000000
```

---

## 10. Forensic Reporting & Tools Reference

### Comprehensive Network Forensics Tools Reference

| Tool | Category | Key Use Cases | Platform |
|---|---|---|---|
| **tcpdump** | Capture | CLI capture, BPF filtering, ring buffer | Linux/macOS/Windows (via WinPcap) |
| **Wireshark** | Capture + Analysis | GUI pcap analysis, protocol dissection, stream following | Windows/Linux/macOS |
| **tshark** | Capture + Analysis | CLI Wireshark, field extraction, scriptable | Linux/macOS/Windows |
| **Zeek** | Analysis | Protocol logs, scripted analysis, file extraction | Linux/macOS |
| **Suricata** | Detection | Signature IDS/IPS, protocol analysis, pcap replay | Linux/macOS/Windows |
| **Arkime** | PCAP Platform | Full packet capture, session indexing, web UI search | Linux |
| **NetworkMiner** | Analysis | Passive OS fingerprinting, file/credential extraction | Windows (Mono: Linux) |
| **nfdump/nfcapd** | Flow Analysis | NetFlow v5/v9/IPFIX capture, CLI analysis | Linux |
| **SiLK** | Flow Analysis | Large-scale flow analysis, beaconing detection | Linux |
| **ntopng** | Flow Visualization | Real-time flow dashboard, historical analysis | Linux/Windows |
| **CapLoader** | PCAP Analysis | Fast pcap indexing, protocol identification, geolocation | Windows |
| **xplico** | Reconstruction | Network content reconstruction (email, web, VoIP) | Linux |
| **tcpflow** | Reconstruction | TCP session file extraction | Linux/macOS |
| **ja3** | Fingerprinting | JA3 hash extraction from pcap | Python (cross-platform) |
| **JARM** | Fingerprinting | TLS server active fingerprinting | Python (cross-platform) |
| **editcap/mergecap/capinfos** | PCAP Utilities | Pcap manipulation and metadata | Cross-platform (with Wireshark) |

### Case Documentation Standards

**Chain of Custody Form — Required Fields**

```
EVIDENCE CHAIN OF CUSTODY

Case Number: _______________          Date: _______________
Examiner: _______________            Organization: _______________

Evidence Item #: _______________
Description: _______________
Collection Method: _______________
Collection Location (logical/physical): _______________
Collection Date/Time (UTC): _______________

Hash Value (SHA-256): _______________
Hash Verified: [ ] Yes  [ ] No     Date Verified: _______________

CUSTODY TRANSFERS:
Released By: _______________ Date/Time: _______________ Signature: _______________
Received By: _______________ Date/Time: _______________ Signature: _______________
Purpose: _______________

(Repeat for each transfer)
```

**Evidence Hash Log**
```
# Create and maintain hash log for all evidence files
# Format: SHA256HASH  FILENAME  SIZE_BYTES  COLLECTION_TIMESTAMP  EXAMINER
sha256sum evidence/*.pcap > evidence_hashes.txt
# Add metadata
echo "# Evidence Hash Log - Case 2024-001" > evidence_manifest.txt
echo "# Generated: $(date -u)" >> evidence_manifest.txt
echo "# Examiner: J. Smith (GCFE #12345)" >> evidence_manifest.txt
cat evidence_hashes.txt >> evidence_manifest.txt
```

**Examination Log (required per NIST SP 800-86)**
- Log every command executed during analysis with timestamp and examiner ID.
- Use `script` command to capture all terminal output: `script -t 2>timing.log analysis_session.log`
- Note: any changes to evidence (even read errors that modify access times).

### NIST SP 800-86 and Related Standards

**NIST SP 800-86 — Guide to Integrating Forensic Techniques**
- Four-phase forensics process: Collection → Examination → Analysis → Reporting.
- Network forensics–specific guidance in Section 4.
- Key principle: use forensic tools that do not alter the original evidence.
- Maintain toolset validation log: version, known limitations, test results.

**RFC 4810 — Long-Term Archive and Notary Services**
- Addresses long-term integrity verification of digital evidence.
- Timestamp evidence files using a trusted timestamping authority at time of collection.
- Renew timestamps before hash algorithm becomes computationally broken.

**Expert Witness Testimony Preparation**
1. Maintain clear separation between facts (what the evidence shows) and conclusions (analyst interpretation).
2. Document tool versions, validation procedures, and known limitations.
3. Be prepared to explain tcpdump BPF syntax, pcap file format, and chain of custody to a non-technical jury.
4. All conclusions must be stated to "a reasonable degree of professional certainty."
5. Retain all working notes, intermediate files, and hash logs; opposing counsel may request them in discovery.

### Network Forensics Report Structure

```
NETWORK FORENSICS EXAMINATION REPORT

1. EXECUTIVE SUMMARY (1-2 pages, non-technical)
   - Incident overview
   - Key findings (breach timeline, data accessed/exfiltrated, attacker actions)
   - Recommended remediation actions
   - Confidence level in conclusions

2. SCOPE AND METHODOLOGY
   - Evidence examined (list with hashes and sizes)
   - Tools used (name, version, purpose)
   - Analysis period
   - Limitations and caveats

3. TECHNICAL FINDINGS
   Section 3.1: Initial Access
   - Timestamp of first malicious activity
   - Attack vector (phishing, exploitation, credential abuse)
   - Evidence sources supporting conclusion
   
   Section 3.2: Lateral Movement
   - Internal hosts accessed (with evidence citations)
   - Techniques used (SMB, RDP, WMI, etc.)
   - Timeline of movement
   
   Section 3.3: Data Exfiltration
   - Data sets accessed or exfiltrated
   - Volume (bytes) and destination
   - Exfiltration method

4. INDICATOR OF COMPROMISE (IOC) TABLE
   | Type | Value | First Seen | Last Seen | Source |
   |------|-------|------------|-----------|--------|
   | IP | 203.0.113.42 | 2024-01-15T14:22Z | 2024-01-15T18:45Z | VPC Flow Log |
   | Domain | c2.evil.com | 2024-01-15T14:23Z | ... | DNS Log |
   | JA3 | b70de2e22a... | 2024-01-15T14:24Z | ... | ssl.log |
   | SHA256 | abc123... | 2024-01-15T14:30Z | ... | files.log |

5. NETWORK FORENSICS TIMELINE
   [Tabular timeline correlating all evidence sources — see Section 6 methodology]

6. EVIDENCE APPENDIX
   - Evidence hash manifest
   - Chain of custody forms
   - Raw log excerpts supporting findings
   - PCAP session references (file, packet number)
```

### IOC Extraction Template

```bash
#!/bin/bash
# IOC extraction from Zeek logs

CASE_DIR="/cases/2024-001"
mkdir -p "$CASE_DIR/iocs"

# Extract external IPs from conn.log
echo "# External IP addresses" > "$CASE_DIR/iocs/ip_addresses.txt"
zeek-cut id.resp_h < conn.log | \
  grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1)' | \
  sort | uniq -c | sort -rn >> "$CASE_DIR/iocs/ip_addresses.txt"

# Extract domains from DNS log
echo "# Queried domains" > "$CASE_DIR/iocs/domains.txt"
zeek-cut query < dns.log | sort | uniq >> "$CASE_DIR/iocs/domains.txt"

# Extract JA3 hashes from ssl.log
echo "# JA3 hashes" > "$CASE_DIR/iocs/ja3_hashes.txt"
zeek-cut ja3 server_name < ssl.log | sort | uniq >> "$CASE_DIR/iocs/ja3_hashes.txt"

# Extract file hashes from files.log
echo "# File hashes (SHA256)" > "$CASE_DIR/iocs/file_hashes.txt"
zeek-cut sha256 mime_type filename < files.log | \
  grep -v "^-" | sort | uniq >> "$CASE_DIR/iocs/file_hashes.txt"

# Extract URLs from http.log
echo "# URLs" > "$CASE_DIR/iocs/urls.txt"
zeek-cut host uri method status_code < http.log | \
  awk '$3 == "POST" || $4 != "200"' >> "$CASE_DIR/iocs/urls.txt"

echo "IOC extraction complete: $CASE_DIR/iocs/"
```

### STIX/TAXII for Sharing Network-Derived IOCs

```python
# Create STIX 2.1 bundle from network IOCs
from stix2 import (Bundle, Indicator, IPv4Address, DomainName,
                   Relationship, ThreatActor, AttackPattern)
import uuid

# Create network IOC indicators
ip_indicator = Indicator(
    name="C2 Server IP",
    indicator_types=["malicious-activity"],
    pattern="[ipv4-addr:value = '203.0.113.42']",
    pattern_type="stix",
    valid_from="2024-01-15T14:22:00Z",
    description="Cobalt Strike C2 server observed in pcap",
    labels=["c2", "cobalt-strike"]
)

domain_indicator = Indicator(
    name="C2 Domain",
    indicator_types=["malicious-activity"],
    pattern="[domain-name:value = 'c2.evil.com']",
    pattern_type="stix",
    valid_from="2024-01-15T14:23:00Z",
)

# Create STIX bundle for TAXII sharing
bundle = Bundle(objects=[ip_indicator, domain_indicator])
print(bundle.serialize(pretty=True))

# Push to TAXII server
from taxii2client.v21 import Server
server = Server("https://taxii.example.com/", user="analyst", password="secret")
api_root = server.api_roots[0]
collection = api_root.get_collection("network-iocs")
collection.push(bundle)
```

### SIEM Integration

**Splunk TA for PCAP Analysis**
```
# Splunk TA: TA-pcap
# Extracts Zeek logs, Suricata alerts, and packet metadata
# Key sourcetypes: zeek:conn, zeek:dns, zeek:http, zeek:ssl, suricata:alert

index=network sourcetype="zeek:conn" 
| where dest_ip!="10.0.0.0/8" 
| stats sum(bytes) as total_bytes by dest_ip 
| sort -total_bytes 
| head 20
```

**Elastic Network Packet Capture**
```yaml
# filebeat.yml for Zeek logs
filebeat.inputs:
- type: log
  paths: [/var/log/zeek/current/conn.log]
  fields:
    event.dataset: zeek.connection
  processors:
  - decode_json_fields:
      fields: ["message"]
      target: ""

# EQL query for beaconing detection
sequence by source.ip, destination.ip, destination.port with maxspan=1h
  [network where event.action == "connection_attempted"] with runs=10
```

### Automated Forensics Pipeline

```yaml
# Docker Compose: Automated Zeek + ELK + MISP IOC Enrichment

version: '3.8'
services:
  zeek:
    image: zeek/zeek:latest
    volumes:
      - ./pcap:/pcap
      - ./logs:/logs
    command: zeek -r /pcap/capture.pcap -l /logs local

  logstash:
    image: docker.elastic.co/logstash/logstash:8.x
    volumes:
      - ./logs:/logs
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    # logstash.conf: parse Zeek JSON logs → enrich with MISP → index in ES

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.x
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true

  misp-enrichment:
    build: ./misp-enrichment
    # Python service: reads IOCs from Zeek logs, queries MISP API,
    # writes enrichment back to Elasticsearch
    environment:
      - MISP_URL=https://misp.example.com
      - MISP_KEY=${MISP_API_KEY}
```

```python
# MISP IOC enrichment script
import pymisp
import json

def enrich_ioc(ioc_type, ioc_value, misp_url, misp_key):
    """Query MISP for IOC reputation and return enrichment."""
    misp = pymisp.PyMISP(misp_url, misp_key, ssl=True)
    results = misp.search(type_attribute=ioc_type, value=ioc_value,
                          pythonify=True)
    if not results:
        return {"matched": False, "ioc": ioc_value}
    
    threats = []
    for event in results:
        threats.append({
            "event_id": event.id,
            "info": event.info,
            "threat_level": event.threat_level_id,
            "tags": [str(t) for t in event.tags]
        })
    return {"matched": True, "ioc": ioc_value, "threats": threats}

# Example: enrich all IPs from Zeek conn.log
with open('/logs/conn.log') as f:
    for line in f:
        if line.startswith('#'):
            continue
        fields = line.strip().split('\t')
        dest_ip = fields[4]  # id.resp_h
        enrichment = enrich_ioc('ip-dst', dest_ip, MISP_URL, MISP_KEY)
        if enrichment['matched']:
            print(json.dumps(enrichment))
```

---

*Reference compiled for incident responders and network forensics analysts. Verify tool versions and legal applicability for your jurisdiction before use in legal proceedings. Hash all evidence immediately upon collection and maintain strict chain of custody.*
