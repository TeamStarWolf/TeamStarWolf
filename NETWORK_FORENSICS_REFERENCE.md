# Network Forensics Reference

Practical network forensics and traffic analysis reference covering Zeek, Wireshark, tcpdump, Suricata, and network incident response techniques.

---

## Traffic Capture Quick Reference

### tcpdump Essential Commands

```bash
# Capture all traffic on interface, write to file
tcpdump -i eth0 -w capture.pcap

# Capture with timestamps, verbose, no name resolution
tcpdump -i eth0 -tttt -vvv -n -w capture.pcap

# Filter by host
tcpdump -i eth0 host 192.168.1.100 -w host_capture.pcap

# Filter by port
tcpdump -i eth0 port 443 -w https_traffic.pcap

# Capture DNS traffic
tcpdump -i eth0 port 53 -n -vv

# Capture SMTP/email traffic
tcpdump -i eth0 'port 25 or port 587 or port 465' -w email.pcap

# Capture non-standard ports (potential C2)
tcpdump -i eth0 'not port 80 and not port 443 and not port 53 and not port 22' -w suspicious.pcap

# Limit capture size
tcpdump -i eth0 -C 100 -W 10 -w /tmp/capture.pcap   # 10 x 100MB files rotating

# Read and filter existing capture
tcpdump -r capture.pcap 'tcp and host 10.0.0.1'

# Extract IPs from capture
tcpdump -r capture.pcap -n | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn
```

### Wireshark Display Filters

```
# Basic filters
ip.addr == 192.168.1.100          # Traffic to/from IP
ip.src == 192.168.1.0/24         # From subnet
tcp.port == 4444                  # TCP port (common Meterpreter)
http.request                      # All HTTP requests
http.response.code == 200         # Successful HTTP responses
dns.qry.name contains "evil"      # DNS queries containing string

# C2 detection filters
tcp.flags.syn == 1 and tcp.flags.ack == 0   # SYN packets (new connections)
frame.time_delta > 30 and frame.time_delta < 70  # Beaconing ~60s interval
http.user_agent contains "Mozilla/5.0" and http.request.uri contains "/submit.php"  # CS default

# Credential hunting
http.request.method == "POST" and http.request.uri contains "login"
ftp.request.command == "PASS"
telnet                            # Plaintext credentials

# Malware traffic patterns
dns.qry.name matches "^[a-z0-9]{20,}\\.com$"   # High-entropy DGA domains
icmp and data.len > 100          # Large ICMP payloads (ICMP tunneling)
dns.qry.type == 16               # TXT record queries (DNS tunneling)
http.content_type contains "application/octet-stream"  # Binary downloads

# SMB lateral movement
smb2.cmd == 0x0005               # SMB2 Create (file access)
smb.cmd == 0x75                  # Tree Connect (share access)

# Beaconing analysis
# Follow TCP Stream, look for periodic connections to same IP/domain
```

### Wireshark Forensics Workflow

```
1. Statistics -> Conversations -> TCP tab -- identify most active connections
2. Statistics -> Protocol Hierarchy -- understand traffic composition
3. Statistics -> IO Graphs -- visualize beaconing patterns
4. File -> Export Objects -> HTTP -- extract downloaded files
5. Edit -> Find Packet -> String -- search packet data for keywords
6. Analyze -> Follow -> TCP Stream -- reconstruct full conversations
7. Analyze -> Expert Information -- find anomalies flagged by Wireshark
```

---

## Zeek (Bro) Network Analysis

Zeek converts raw packet captures into structured, queryable logs -- the foundation for NSM (Network Security Monitoring).

### Key Log Files

| Log | Content | Key Fields |
|---|---|---|
| conn.log | All network connections | uid, orig_h, resp_h, proto, service, duration, orig_bytes, resp_bytes, conn_state |
| dns.log | DNS queries and responses | query, qtype_name, answers, rcode_name |
| http.log | HTTP transactions | host, uri, method, status_code, user_agent, resp_mime_types |
| ssl.log | TLS handshakes | server_name (SNI), subject, issuer, cipher, version, ja3, ja3s |
| files.log | File transfers | source, mime_type, md5, sha256, extracted |
| notice.log | Zeek policy alerts | note, msg, src, dst |
| smtp.log | Email transactions | from, to, subject, mailfrom, rcptto |
| x509.log | Certificate details | certificate.subject, certificate.issuer, certificate.not_valid_before |

### Zeek + Zed/ZQuery Analysis

```bash
# Install zeek and zq
# Process a pcap
zeek -C -r suspicious.pcap LogAscii::use_json=T

# Query with zed (fast log analytics)
# Find all connections to port 4444
zq 'resp_p == 4444' conn.log

# Large data transfers (potential exfil)
zq 'orig_bytes > 10000000 | sort -r orig_bytes | head 20' conn.log

# Find DNS queries for high-entropy domains
zq 'len(query) > 40 and !is_error(query)' dns.log

# HTTP with suspicious User-Agent
zq 'user_agent matches /^Mozilla\/4\.0/ or user_agent == ""' http.log

# Extract unique JA3 hashes (TLS fingerprinting)
zq 'count() by ja3 | sort -r count' ssl.log

# Find connections with no bytes transferred
zq 'orig_bytes == 0 and resp_bytes == 0 and proto == "tcp"' conn.log
```

### JA3/JA3S TLS Fingerprinting

JA3 fingerprints TLS ClientHello parameters (SSL version, ciphers, extensions, elliptic curves, elliptic curve point formats) into a 32-character MD5 hash. JA3S fingerprints the ServerHello.

**Known Malicious JA3 Hashes**:
| JA3 Hash | Associated Malware |
|---|---|
| `51c64c77e60f3980eea90869b68c58a8` | Cobalt Strike default HTTP beacon |
| `a0e9f5d64349fb13191bc781f81f42e1` | Dridex |
| `6734f37431670b3ab4292b8f60f29984` | TrickBot |
| `4d7a28d6f2263ed61de88ca66eb011e3` | IcedID |

```bash
# Extract JA3 hashes from capture using zeek
zeek -C -r capture.pcap /opt/zeek/share/zeek/policy/protocols/ssl/ja3.zeek
# Results appear in ssl.log with ja3 and ja3s fields
```

---

## Network Incident Response Workflow

### Phase 1: Initial Scoping

```bash
# Quick statistical overview of a capture
capinfos capture.pcap

# Top talkers (who is generating the most traffic?)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e frame.len \
  | awk '{bytes[$1" "$2]+=$3} END {for(k in bytes) print bytes[k], k}' \
  | sort -rn | head 20

# Unique destination IPs (external connections)
tshark -r capture.pcap -T fields -e ip.dst \
  | sort | uniq -c | sort -rn | head 30

# Protocol distribution
tshark -r capture.pcap -q -z io,phs
```

### Phase 2: Suspicious Connection Identification

```bash
# Find connections to rare/new destinations
# Establish baseline first, then diff new traffic against it

# Extract all HTTP hosts
tshark -r capture.pcap -T fields -e http.host | sort | uniq -c | sort -rn

# Find DNS queries for domains and flag high-entropy ones
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name | python3 -c "
import sys, math
from collections import Counter

def entropy(s):
    if not s: return 0
    p = Counter(s)
    return -sum(c/len(s)*math.log2(c/len(s)) for c in p.values())

for line in sys.stdin:
    domain = line.strip().split('.')[0]
    if entropy(domain) > 3.5:
        print(f'{entropy(domain):.2f} {line.strip()}')
" | sort -rn | head 30
```

### Phase 3: Payload Extraction

```bash
# Extract HTTP objects (downloaded files) using tshark
tshark -r capture.pcap --export-objects http,/tmp/http_objects/

# Extract SMB objects (shared files)
tshark -r capture.pcap --export-objects smb,/tmp/smb_objects/

# Extract SMTP attachments
tshark -r capture.pcap --export-objects imf,/tmp/email_objects/

# Calculate hashes on extracted files
find /tmp/http_objects/ -type f -exec sha256sum {} \;

# Check hashes against VirusTotal (requires API key)
# curl "https://www.virustotal.com/api/v3/files/HASH" -H "x-apikey: KEY"
```

### Phase 4: Timeline Reconstruction

```bash
# Extract all TCP streams with timestamps
tshark -r capture.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport -e frame.len -E separator=, > timeline.csv

# Sort by timestamp
sort -t',' -k1 timeline.csv > timeline_sorted.csv

# Find first and last packet times
tshark -r capture.pcap -T fields -e frame.time | head -1
tshark -r capture.pcap -T fields -e frame.time | tail -1
```

---

## Suricata for Network Monitoring

### Installation and Configuration

```bash
# Install
apt install suricata   # Debian/Ubuntu
yum install suricata   # RHEL

# Update threat rules (ET Open -- free)
suricata-update

# Run against pcap
suricata -r capture.pcap -l /var/log/suricata/ -k none

# Run as IDS on interface
suricata -i eth0 -l /var/log/suricata/

# Key log files
# /var/log/suricata/eve.json -- all events in JSON (main log)
# /var/log/suricata/fast.log -- alert summary
```

### Querying EVE JSON with jq

```bash
# Show all alerts
jq -r 'select(.event_type=="alert") | [.timestamp, .alert.signature, .src_ip, .dest_ip] | @tsv' eve.json

# Count alerts by signature
jq -r 'select(.event_type=="alert") | .alert.signature' eve.json | sort | uniq -c | sort -rn | head 20

# Find DNS queries for suspicious domains
jq -r 'select(.event_type=="dns" and .dns.type=="query") | [.timestamp, .src_ip, .dns.rrname] | @tsv' eve.json

# Show HTTP events with unusual user agents
jq -r 'select(.event_type=="http") | [.timestamp, .src_ip, .dest_ip, .http.http_user_agent, .http.url] | @tsv' eve.json

# Find large file transfers
jq -r 'select(.event_type=="fileinfo" and .fileinfo.size > 1000000) | [.timestamp, .src_ip, .dest_ip, .fileinfo.filename, .fileinfo.size, .fileinfo.sha256] | @tsv' eve.json
```

---

## Network Indicators of Compromise

### Port-Based Anomalies

| Unusual Pattern | Likely Explanation | Investigation |
|---|---|---|
| Outbound port 4444 | Metasploit Meterpreter default | Check process making connection; isolate host |
| Outbound port 8080/8443 | Cobalt Strike or Havoc C2 | JA3 fingerprint; beacon cadence analysis |
| Port 53 with large payloads | DNS tunneling | Count bytes per query; entropy of subdomain labels |
| Outbound port 445 | SMB lateral movement | Check source/dest; auth logs for logon type 3 |
| High-volume ICMP | ICMP tunneling | Check payload size and entropy |
| Outbound port 6667 | IRC C2 (older malware) | Bot communication channel |
| Outbound port 1194 | OpenVPN (unauthorized tunnel) | Check if approved VPN |

### Beaconing Indicators

- **Regular interval** connections (every 30s, 60s, 5min) to same external IP/domain
- **Consistent packet sizes** -- C2 check-in often has predictable payload
- **Low data volume per connection** -- C2 check-in typically <1KB unless tasked
- **Connections at odd hours** -- legitimate users don't generate traffic at 3 AM
- **Encrypted traffic to unusual hosts** -- TLS to IP (no SNI) or self-signed cert

### Data Exfiltration Indicators

- **Sustained outbound transfers** -- large total bytes sent to external host
- **Compression utilities** -- zip/rar/7z activity before outbound transfer
- **Staged exfil** -- data moved to internal staging server first, then external
- **Cloud service abuse** -- high volume to Dropbox/OneDrive/Box from servers
- **DNS exfil** -- high query volume, long subdomain labels, many TXT queries

---

## Threat Hunting with Network Data

### Hunt: Cobalt Strike via JA3
```bash
# In Zeek ssl.log
grep "51c64c77e60f3980eea90869b68c58a8" ssl.log

# Or with zq
zq 'ja3 == "51c64c77e60f3980eea90869b68c58a8"' ssl.log
```

### Hunt: DNS Beaconing
```bash
# Count DNS queries per domain per hour (high count = beaconing)
zq 'count() by query, cut_time(ts, 1h) | sort -r count | head 50' dns.log
```

### Hunt: Large Internal-to-External Transfers (Exfil)
```bash
# Connections sending > 10MB outbound
zq 'orig_bytes > 10000000 and !addr_in_subnet(resp_h, "10.0.0.0/8") and !addr_in_subnet(resp_h, "192.168.0.0/16")' conn.log | sort -r orig_bytes
```

### Hunt: SMB Lateral Movement
```bash
# In Zeek smb_files.log or smb_mapping.log
# Look for multiple hosts being accessed from same source
zq 'count() by path, action | where action == "SMB::FILE_OPEN"' smb_files.log
```

---

## Network Forensics Tools Reference

| Tool | Purpose | Key Commands |
|---|---|---|
| Wireshark | GUI packet analysis | Display filters, stream following, object export |
| tcpdump | CLI packet capture | Filter syntax, file rotation |
| tshark | CLI Wireshark | Scriptable packet analysis and extraction |
| Zeek | NSM log generation | Converts pcap to structured JSON logs |
| Suricata | IDS/IPS | Signature-based detection, EVE JSON logging |
| NetworkMiner | Windows PCAP analysis | OS fingerprinting, credential extraction, file carving |
| Arkime (Moloch) | Full packet capture | Scalable pcap storage and search |
| Security Onion | NSM platform | Zeek + Suricata + Kibana + Strelka integrated stack |
| Rita | Zeek log analysis | Beaconing, long connections, DNS tunneling detection |
| Maltrail | Malicious traffic detection | Threat intel feed correlation against logs |

## Related Resources
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) -- Suricata and Sigma rules
- [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) -- DNS beaconing and C2 hunting procedures
- [Network Security Discipline](disciplines/network-security.md) -- NSM methodology and architecture
- [Digital Forensics Discipline](disciplines/digital-forensics.md) -- Memory and disk forensics
