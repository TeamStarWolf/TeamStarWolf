# Network Monitoring Reference

> **Audience**: Security practitioners — SOC analysts, detection engineers, and network defenders. This reference covers the full NSM (Network Security Monitoring) stack: sensors, log sources, detection logic, and threat hunting workflows.

---

## Table of Contents

- [Network Monitoring Architecture](#1-network-monitoring-architecture)
- [Zeek (formerly Bro)](#2-zeek-formerly-bro)
- [Suricata IDS/IPS](#3-suricata-idsips)
- [JA3/JA3S TLS Fingerprinting](#4-ja3ja3s-tls-fingerprinting)
- [NetFlow / IPFIX / sFlow](#5-netflow--ipfix--sflow)
- [Network Threat Hunting](#6-network-threat-hunting)
- [DNS Security Monitoring](#7-dns-security-monitoring)
- [Full Packet Capture](#8-full-packet-capture)
- [Security Onion Platform](#9-security-onion-platform)
- [Detection KQL/Elasticsearch](#10-detection-kqlelasticsearch)
- [Tools Reference Table](#11-tools-reference-table)

---

## 1. Network Monitoring Architecture

### TAP vs SPAN Port

| Attribute | Network TAP (Hardware) | SPAN Port (Switch Mirror) |
|---|---|---|
| **Type** | Passive inline hardware device | Software-configured port mirror |
| **Traffic fidelity** | 100% -- captures all frames including errors | May drop frames under high load; no CRC errors |
| **Impact on network** | None -- fully passive | CPU/memory overhead on switch |
| **Duplex handling** | Full duplex: requires two monitor ports (or aggregation TAP) | Single port, may need aggregation |
| **Cost** | Higher upfront ($200-$5,000+) | Free (built into managed switches) |
| **Deployment complexity** | Requires physical inline installation | CLI config only |
| **Failure mode** | Fail-open (traffic passes if TAP loses power) | Port mirror disabled if switch reboots |
| **Use case** | Production perimeter, compliance recording | Lab, low-budget, quick deployment |
| **Vendors** | Garland Technology, Ixia, Gigamon | Cisco RSPAN, Juniper port mirroring |

**Rule of thumb**: Use hardware TAPs for critical perimeter monitoring where you cannot afford to drop packets. Use SPAN for internal segments and lateral movement detection where cost matters more than absolute fidelity.

---

### Deployment Points

```
[Internet] ---> [TAP/SPAN] ---> [Perimeter Sensor]  (internet-facing: C2, exfil, inbound attacks)
                    |
              [Firewall/IDS]
                    |
[DMZ] --------> [TAP/SPAN] ---> [DMZ Sensor]         (web servers, mail, bastion: exploitation, lateral)
                    |
             [Core Switch]
                    |
[Internal LAN] -> [SPAN] ----> [Core Sensor]          (east-west: lateral movement, privilege escalation)
                    |
[DC VLAN] -------> [SPAN] ---> [DC Sensor]            (AD replication, Kerberoasting, DCSync)
```

**Key deployment locations**:

1. **Internet perimeter** -- Catches inbound exploitation, outbound C2, and data exfiltration. Highest signal-to-noise ratio for external threats.
2. **DMZ** -- Monitors services exposed to the internet. Look for web shell activity, unauthorized outbound from DMZ hosts.
3. **Core backbone** -- East-west traffic between VLANs. Critical for detecting lateral movement that bypasses perimeter controls.
4. **Domain controller VLAN** -- High-value: Kerberoasting (AS-REP, TGS requests), DCSync (DRSUAPI), LDAP enumeration.
5. **Critical asset segments** -- Finance, HR, R&D VLANs. Data exfiltration detection.

---

### NSM Components

| Component | Tool | Purpose |
|---|---|---|
| **Full Packet Capture** | Arkime (Moloch) | Indexed PCAP storage and search, session reconstruction |
| **Metadata / Protocol Logs** | Zeek (Bro) | Parsed application-layer logs: conn, DNS, HTTP, SSL, SMTP |
| **IDS / IPS** | Suricata, Snort | Signature-based detection, rule-driven alerting |
| **Flow Data** | NetFlow v9/IPFIX, sFlow | 5-tuple flow records from routers/switches, long-term retention |
| **Flow Analysis** | SiLK, nfdump, Elastic | Query flow records for beaconing, exfil, scanning |
| **Platform** | Security Onion | Integrated NSM stack: Zeek + Suricata + Elasticsearch + Kibana |
| **File Extraction** | Strelka, Zeek files.log | Extract files from network sessions, scan with YARA/AV |
| **TLS Fingerprinting** | JA3/JA3S, JARM | Identify malicious TLS clients/servers by fingerprint |

---

## 2. Zeek (formerly Bro)

### Log File Reference

| Log File | Description | Key Fields |
|---|---|---|
| `conn.log` | All network connections (TCP/UDP/ICMP) | ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, history |
| `dns.log` | DNS queries and responses | ts, uid, id.orig_h, query, qtype_name, rcode_name, answers, TTLs, AA, TC |
| `http.log` | HTTP requests and responses | ts, uid, id.orig_h, method, host, uri, referrer, user_agent, status_code, resp_mime_types, request_body_len, response_body_len |
| `ssl.log` | TLS/SSL sessions | ts, uid, id.orig_h, id.resp_h, id.resp_p, version, cipher, curve, server_name (SNI), resumed, validation_status, subject, issuer, ja3, ja3s |
| `x509.log` | X.509 certificate details | ts, id (cert fingerprint), certificate.subject, certificate.issuer, certificate.not_valid_before, certificate.not_valid_after, san.dns, san.ip |
| `files.log` | Files transferred over network | ts, fuid, tx_hosts, rx_hosts, conn_uids, source, mime_type, filename, md5, sha1, sha256, extracted |
| `smtp.log` | SMTP email sessions | ts, uid, id.orig_h, mailfrom, rcptto, subject, x_originating_ip, tls, user_agent, last_reply |
| `ssh.log` | SSH connections | ts, uid, id.orig_h, id.resp_h, auth_success, auth_attempts, client, server, cipher_alg, mac_alg, host_key_alg, kex_alg |
| `rdp.log` | RDP sessions | ts, uid, id.orig_h, id.resp_h, cookie, result, security_protocol, client_build, client_name, cert_subject |
| `weird.log` | Protocol anomalies and unexpected behavior | ts, uid, id.orig_h, id.resp_h, name, addl, notice |
| `notice.log` | Zeek-generated alerts and policy notices | ts, uid, id.orig_h, note, msg, sub, src, dst, p, actions, suppress_for |
| `intel.log` | Intel framework matches (IOC hits) | ts, uid, id.orig_h, id.resp_h, seen.indicator, seen.indicator_type, seen.where, matched, sources |
| `pe.log` | Portable Executable (PE) file metadata | ts, id, machine, compile_ts, os, subsystem, is_exe, is_dll, uses_aslr, uses_dep, has_debug, section_names |

---

### Zeek Query Examples (zeek-cut)

```bash
# Top talkers by bytes sent (source IPs)
zeek-cut id.orig_h orig_bytes < conn.log | \
  awk '{bytes[$1]+=$2} END {for(ip in bytes) print bytes[ip], ip}' | \
  sort -rn | head 10

# Top 10 destination IPs by bytes received
zeek-cut id.resp_h resp_bytes < conn.log | \
  awk '{bytes[$1]+=$2} END {for(ip in bytes) print bytes[ip], ip}' | \
  sort -rn | head 10

# Find connections from same src->dst pair with high connection count (beaconing)
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | \
  awk '{print $2"->"$3":"$4}' | sort | uniq -c | sort -rn | \
  awk '$1 > 100' | head 20

# Long-duration connections (C2 keepalive) -- over 1 hour
zeek-cut ts id.orig_h id.resp_h id.resp_p duration service < conn.log | \
  awk '$5 > 3600 {print $0}' | sort -t$'\t' -k5 -rn | head 20

# SSL with self-signed or invalid certificates
zeek-cut ts id.orig_h id.resp_h id.resp_p server_name validation_status < ssl.log | \
  grep "self signed\|unable to get local issuer\|certificate verify failed" | head 20

# HTTP with non-browser user-agents (exclude common clients)
zeek-cut ts id.orig_h host uri user_agent status_code < http.log | \
  grep -v "Mozilla\|curl\|wget\|python-requests\|Go-http-client\|libwww" | \
  awk '$4 != "-"' | head 20

# Show only suspicious or empty user-agents
zeek-cut ts id.orig_h host uri user_agent < http.log | \
  awk -F'\t' '$5 == "-" || $5 ~ /^[a-z]{1,15}$/' | head 20

# DNS queries to suspicious TLDs
zeek-cut ts id.orig_h query qtype_name rcode_name < dns.log | \
  awk '$3 ~ /\.(xyz|top|pw|tk|ml|ga|cf|gq|cn|ru|su|buzz|click|loan|win|download|stream)$/' | \
  sort | head 30

# NXDOMAIN storm (potential DGA) -- top sources by NXDOMAIN count
zeek-cut ts id.orig_h query rcode_name < dns.log | \
  awk '$4 == "NXDOMAIN"' | \
  awk '{nxd[$2]++} END {for(ip in nxd) print nxd[ip], ip}' | \
  sort -rn | head 10

# Extract PE file hashes from files.log
zeek-cut ts tx_hosts rx_hosts mime_type filename md5 sha256 < files.log | \
  awk '$4 ~ /executable|x-dosexec|octet-stream/' | \
  awk '$6 != "-"' | head 20

# Long subdomain labels (DNS tunneling indicator -- labels > 50 chars)
zeek-cut ts id.orig_h query < dns.log | \
  awk '{
    split($3, parts, ".");
    for (i=1; i<=length(parts); i++) {
      if (length(parts[i]) > 50) { print $0; break }
    }
  }' | head 20

# High query rate to single apex domain (DNS tunneling)
zeek-cut ts id.orig_h query < dns.log | \
  awk '{n=split($3,a,"."); print $2, a[n-1]"."a[n]}' | \
  sort | uniq -c | sort -rn | head 20
```

---

### Zeek Scripting Example: C2 Beacon Detection

```zeek
# detect_beacon.zeek
# Detects potential C2 beaconing: many connections from same src->dst with low jitter

module BeaconDetect;

export {
    redef enum Notice::Type += {
        Potential_C2_Beacon
    };
}

global beacon_tracker: table[addr, addr, port] of vector of time
    &create_expire = 10min
    &default = function(key: any): vector of time { return vector(); };

global BEACON_MIN_CONNS = 40;
global BEACON_JITTER_MAX = 0.10;   # stddev / mean < 10% = regular = beacon
global BEACON_INTERVAL_MAX = 300.0; # ignore if mean > 5 minutes

event connection_state_remove(c: connection) {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local rport = c$id$resp_p;

    beacon_tracker[orig, resp, rport] += c$start_time;

    local times = beacon_tracker[orig, resp, rport];
    if (|times| < BEACON_MIN_CONNS) return;

    local sorted_times = sort(times);
    local intervals: vector of double = vector();
    for (i in sorted_times) {
        if (i == 0) next;
        local iv = interval_to_double(sorted_times[i] - sorted_times[i-1]);
        if (iv > 0.5) intervals += iv;
    }
    if (|intervals| < 5) return;

    local sum = 0.0;
    for (iv in intervals) sum += intervals[iv];
    local mean = sum / |intervals|;
    if (mean > BEACON_INTERVAL_MAX) return;

    local sq_sum = 0.0;
    for (iv in intervals) sq_sum += (intervals[iv] - mean) ^ 2;
    local stddev = sqrt(sq_sum / |intervals|);
    local jitter = stddev / mean;

    if (jitter < BEACON_JITTER_MAX) {
        NOTICE([$note = Potential_C2_Beacon,
                $src  = orig,
                $dst  = resp,
                $p    = rport,
                $msg  = fmt("C2 beacon candidate: %s -> %s:%s | conns=%d mean=%.1fs jitter=%.3f",
                            orig, resp, rport, |times|, mean, jitter),
                $identifier = cat(orig, resp, rport)]);
        # Reset tracker after alert to avoid duplicate spam
        delete beacon_tracker[orig, resp, rport];
    }
}
```

---

### Zeek Intel Framework

**intel.dat format** (tab-separated):
```
#fields indicator  indicator_type   meta.source     meta.desc                   meta.url
evil.example.com   Intel::DOMAIN    ThreatFeed-v1   Known C2 domain             https://ti.example.com/ioc/123
198.51.100.42      Intel::ADDR      ThreatFeed-v1   Cobalt Strike teamserver    https://ti.example.com/ioc/456
d41d8cd98f00b204e9800998ecf8427e  Intel::FILE_HASH  YARA-Hits  Malware dropper MD5
a0e9f5d64349fb13191bc781f81f42e1  Intel::CERT_HASH  JA3-List   Cobalt Strike JA3
```

**Loading intel in local.zeek**:
```zeek
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += {
    "/opt/zeek/share/zeek/site/intel.dat"
};
```

Zeek automatically checks loaded intel against conn.log, dns.log, http.log, ssl.log, and files.log. Matches appear in `intel.log`.

```bash
# View intel hits in real time
zeek-cut ts id.orig_h id.resp_h seen.indicator seen.indicator_type matched sources < intel.log
```

---

## 3. Suricata IDS/IPS

### Modes

| Mode | Description | Use Case |
|---|---|---|
| **Passive IDS** | af-packet or pcap -- read-only, no blocking | Monitoring, alerting, NSM |
| **Inline IPS** | NFQueue or netmap -- can drop/reject packets | Enforcement, automated blocking |
| **Offline (PCAP)** | Analyze stored PCAP file | Incident response, hunt |

```bash
# IDS mode (passive, high-performance af-packet)
suricata -c /etc/suricata/suricata.yaml -i eth0

# IPS mode (inline via NFQueue)
iptables -I FORWARD -j NFQUEUE --queue-num 0
suricata -c /etc/suricata/suricata.yaml -q 0

# Offline PCAP analysis
suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l /tmp/suricata-logs/
```

---

### Complete Rule Syntax

```
action proto src_ip src_port direction dst_ip dst_port (option:value; option:value; ...)
```

- **Actions**: `alert` | `drop` | `reject` | `pass`
- **Directions**: `->` (one-way) | `<>` (bidirectional)
- **Variables**: `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_SERVERS`, `$SQL_SERVERS`, `$DNS_SERVERS`, `any`

---

### 5 Full Example Rules

```
# Rule 1: Mimikatz User-Agent (credential dumping C2 callback)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET MALWARE Mimikatz sekurlsa User-Agent";
    flow:established,to_server;
    http.user_agent; content:"sekurlsa"; nocase;
    classtype:trojan-activity;
    sid:9000001; rev:1;
)

# Rule 2: PowerShell Download Cradle (IEX + WebClient/DownloadString)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"ET ATTACK PowerShell IEX WebClient Download Cradle";
    flow:established,to_server;
    http.uri;
    pcre:"/(\bIEX\b|\bInvoke-Expression\b).*(\bWebClient\b|\bDownloadString\b)/i";
    classtype:attempted-intrusion;
    threshold:type limit, track by_src, count 1, seconds 60;
    sid:9000002; rev:2;
)

# Rule 3: DNS on Non-Standard Port (DNS tunneling / C2)
alert udp $HOME_NET any -> $EXTERNAL_NET !53 (
    msg:"ET POLICY DNS Query on Non-Standard Port Possible Tunneling";
    byte_test:1,&,0xF8,2;
    content:"|00 01 00 00|";
    offset:4; depth:4;
    classtype:policy-violation;
    sid:9000003; rev:1;
)

# Rule 4: Cobalt Strike Default JA3 Fingerprint
alert tls $EXTERNAL_NET any -> $HOME_NET any (
    msg:"ET MALWARE Cobalt Strike Default Beacon TLS JA3";
    ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1";
    flow:established,to_server;
    classtype:trojan-activity;
    reference:url,sslbl.abuse.ch/ja3-fingerprints;
    sid:9000004; rev:1;
)

# Rule 5: SMB EternalBlue Exploit (MS17-010)
alert smb $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"ET EXPLOIT EternalBlue MS17-010 Trans2 Request";
    flow:established,to_server;
    content:"|FF|SMB|73 00 00 00 00 18 07 C0|";
    depth:16;
    content:"|00 00 00 00 00|";
    distance:59; within:5;
    classtype:attempted-admin;
    reference:cve,2017-0144;
    sid:9000005; rev:3;
)
```

---

### Rule Options Quick Reference

| Option | Description | Example |
|---|---|---|
| `content` | Match literal bytes in payload | `content:"malware.exe"; nocase;` |
| `pcre` | Perl-compatible regex | `pcre:"/cmd\.exe/i";` |
| `http.method` | HTTP request method | `http.method; content:"POST";` |
| `http.uri` | HTTP request URI (normalized) | `http.uri; content:"/shell.php";` |
| `http.user_agent` | HTTP User-Agent header | `http.user_agent; content:"python";` |
| `http.host` | HTTP Host header | `http.host; content:"evil.xyz";` |
| `dns.query` | DNS query name | `dns.query; content:"dga-domain";` |
| `tls.sni` | TLS SNI field | `tls.sni; content:".xyz"; endswith;` |
| `ja3.hash` | JA3 TLS client fingerprint MD5 | `ja3.hash; content:"a0e9f5d...";` |
| `ja3s.hash` | JA3S TLS server fingerprint | `ja3s.hash; content:"...";` |
| `filemd5` | Match file MD5 hash (from file list) | `filemd5:hashes.md5;` |
| `threshold` | Alert rate limiting | `threshold:type limit,track by_src,count 1,seconds 60;` |
| `flow` | Connection state + direction | `flow:established,to_server;` |
| `flowbits` | Set/check state across packets | `flowbits:set,malware.stage1;` |
| `distance` | Offset from previous content match | `distance:4; within:8;` |
| `nocase` | Case-insensitive match | `content:"POST"; nocase;` |
| `fast_pattern` | Performance optimization hint | `content:"..."; fast_pattern;` |

---

### Key suricata.yaml Settings

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    threads: 4

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      community-id: true
      types:
        - alert:
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - smtp
        - ssh
        - stats:
            totals: yes
            threads: yes
        - flow
        - netflow
```

---

### Rule Management with suricata-update

```bash
# List available rule sources
suricata-update list-sources

# Enable Emerging Threats Open (free)
suricata-update enable-source et/open

# Update all enabled sources
suricata-update

# Disable a noisy rule by SID
suricata-update add-disabled-rule 2019401

# Reload rules without restart
kill -USR2 $(pidof suricata)
# Or via socket:
suricatasc -c reload-rules

# Test config syntax before applying
suricata -T -c /etc/suricata/suricata.yaml
```

---

## 4. JA3/JA3S TLS Fingerprinting

### How JA3 Works

JA3 creates an MD5 fingerprint of a TLS ClientHello message using five fields:
- **SSLVersion** -- TLS version offered by client
- **Ciphers** -- cipher suites listed (comma-separated, excluding GREASE values)
- **Extensions** -- extension type numbers
- **EllipticCurves** -- supported groups (named curves)
- **EllipticCurvePointFormats** -- point format values

The five values are concatenated with dashes, then MD5-hashed:
```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats -> MD5 hash
```

### How JA3S Works

JA3S fingerprints the TLS ServerHello response:
- **SSLVersion** -- negotiated TLS version
- **Cipher** -- single selected cipher suite
- **Extensions** -- server extension types

JA3S identifies the server-side TLS stack -- useful for detecting C2 frameworks by their server configuration regardless of IP address or certificate.

---

### Known Malicious JA3 Hashes

| Hash | Malware / Tool | Notes |
|---|---|---|
| `a0e9f5d64349fb13191bc781f81f42e1` | Cobalt Strike (default) | Default Malleable C2 profile beacon |
| `d4e2b5194d1d48f1f51d11b81a0d9ff0` | Metasploit Meterpreter | Default TLS configuration |
| `6734f37431670b3ab4292b8f60f29984` | Dridex banking trojan | Observed in multiple campaigns |
| `51c64c77e60f3980eea90869b68c58a8` | Agent Tesla RAT | Credential stealer |
| `e7d705a3286e19ea42f587b6058e1da3` | Trickbot / BazarLoader | Banking trojan and loader stage |
| `72a589da586844d7f0818ce684948eea` | Empire PowerShell C2 | |
| `7dd80d593b8f87e32a3d56e96c57fc2e` | AsyncRAT | Open-source remote access trojan |

**Reference**: https://sslbl.abuse.ch/ja3-fingerprints/ -- live database of malicious JA3 hashes with context and campaign attribution.

---

### JARM: Active TLS Server Fingerprinting

JARM sends 10 specially crafted TLS ClientHello packets and records server responses to create a 62-character fingerprint that identifies the server TLS stack.

```bash
# Install JARM
git clone https://github.com/salesforce/jarm.git
cd jarm

# Fingerprint a target server
python3 jarm.py google.com 443
python3 jarm.py 192.168.1.100 8443

# Known JARM fingerprints for C2 frameworks:
# Cobalt Strike: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
# Metasploit:    07d19d1ad21d21d00042d43d000000aa99ce74e2c1d808d530603799a05405
# Brute Ratel:   3fd21b20d00000021c43d21b21b43de0ae012d3cfd21d21d21d21d21d21d
```

---

### Extracting JA3 from Zeek ssl.log

```bash
# View all unique JA3 hashes with destination IP and SNI
zeek-cut ts id.orig_h id.resp_h id.resp_p server_name ja3 ja3s < ssl.log | \
  awk '$6 != "-"' | sort -k6 | head 30

# Hunt for Cobalt Strike JA3 hash
zeek-cut ts id.orig_h id.resp_h server_name ja3 < ssl.log | \
  awk '$5 == "a0e9f5d64349fb13191bc781f81f42e1"'

# Count unique JA3 hashes (threat profiling)
zeek-cut id.orig_h ja3 < ssl.log | \
  sort | uniq | awk '{print $2}' | sort | uniq -c | sort -rn | head 20
```

---

## 5. NetFlow / IPFIX / sFlow

### Protocol Comparison

| Feature | NetFlow v5 | NetFlow v9 | IPFIX | sFlow |
|---|---|---|---|---|
| **Standard** | Cisco proprietary | Cisco proprietary | IETF RFC 7011 | RFC 3176 |
| **Template-based** | No (fixed format) | Yes | Yes | Yes (sampling) |
| **IPv6 support** | No | Yes | Yes | Yes |
| **MPLS support** | No | Yes | Yes | Yes |
| **Sampling** | No | Optional | Optional | Built-in |
| **Vendor support** | Cisco only | Cisco, Juniper | Universal | Universal |
| **Granularity** | 5-tuple flow | Extensible | RFC fields | Packet samples |

### Flow Record Fields

| Field | Description |
|---|---|
| `sIP` | Source IP address |
| `dIP` | Destination IP address |
| `sPort` | Source port (TCP/UDP) |
| `dPort` | Destination port |
| `proto` | IP protocol (6=TCP, 17=UDP, 1=ICMP) |
| `bytes` | Total bytes in flow |
| `packets` | Total packets |
| `sTime` | Flow start timestamp |
| `eTime` | Flow end timestamp |
| `tcpFlags` | OR of all TCP flags (SYN/ACK/FIN/RST/PSH/URG) |
| `tos` | IP Type of Service / DSCP |
| `in_iface` | Input interface SNMP index |
| `out_iface` | Output interface SNMP index |
| `nextHop` | Next-hop IP address |

---

### SiLK Tool Examples

```bash
# Top talkers by bytes (src+dst pairs)
rwstats --fields=sip,dip --values=bytes --count=10 flows.rw

# Top destinations by packet count
rwstats --fields=dip --values=packets --count=20 flows.rw

# Large outbound transfers (>10MB) to external IPs -- potential exfiltration
rwfilter flows.rw \
  --scidr=192.168.0.0/16 \
  --not-dcidr=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 \
  --bytes=10000000- \
  --pass=stdout | rwcut --fields=sip,dip,dport,bytes,packets,stime

# Port scanning: sources connecting to >100 unique destination IPs (SYN only)
rwfilter flows.rw --proto=6 --flags-initial=S/SA \
  --pass=stdout | \
  rwstats --fields=sip --values=distinct:dip --count=20 | \
  awk '$2 > 100'

# Beaconing detection: bin by 60-second intervals, look for consistent activity
rwcount flows.rw --bin-size=60 | head 120

# Analyze timing for a specific src->dst pair
rwfilter flows.rw \
  --saddress=192.168.1.50 \
  --daddress=203.0.113.10 \
  --pass=stdout | rwcut --fields=stime,etime,bytes,packets

# Internal SMB/RDP scanning (lateral movement)
rwfilter flows.rw \
  --scidr=192.168.0.0/16 \
  --dcidr=192.168.0.0/16 \
  --dport=445,3389 \
  --pass=stdout | \
  rwstats --fields=sip --values=distinct:dip --count=20

# DNS traffic top talkers
rwfilter flows.rw --dport=53 --pass=stdout | \
  rwstats --fields=sip --values=flows --count=20
```

---

## 6. Network Threat Hunting

### Beaconing Detection (Python + Zeek conn.log)

```python
#!/usr/bin/env python3
# beacon_detect.py -- detect C2 beaconing from Zeek conn.log
# Usage: python3 beacon_detect.py /path/to/conn.log

import sys
import statistics
from collections import defaultdict

JITTER_THRESHOLD = 0.10   # stddev < 10% of mean = likely beacon
MIN_CONNECTIONS  = 30      # minimum connections to analyze
MAX_INTERVAL     = 3600    # ignore mean interval > 1 hour
INTERNAL_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def is_internal(ip):
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def load_conn_log(path):
    pairs = defaultdict(list)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if len(parts) < 6:
                continue
            try:
                ts    = float(parts[0])
                orig  = parts[2]
                resp  = parts[4]
                rport = parts[5]
            except (ValueError, IndexError):
                continue
            pairs[(orig, resp, rport)].append(ts)
    return pairs


def analyze_beaconing(pairs):
    results = []
    for (src, dst, dport), timestamps in pairs.items():
        if len(timestamps) < MIN_CONNECTIONS:
            continue
        ts_sorted = sorted(timestamps)
        intervals = [ts_sorted[i] - ts_sorted[i-1]
                     for i in range(1, len(ts_sorted))
                     if ts_sorted[i] - ts_sorted[i-1] > 0]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue
        mean = statistics.mean(intervals)
        if mean > MAX_INTERVAL or mean < 1:
            continue
        try:
            stddev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            continue
        jitter = stddev / mean if mean > 0 else 1.0
        if jitter < JITTER_THRESHOLD:
            results.append({
                "src": src, "dst": dst, "dport": dport,
                "connections": len(timestamps),
                "mean_interval_s": round(mean, 2),
                "stddev_s": round(stddev, 2),
                "jitter_ratio": round(jitter, 4),
                "direction": "internal->external"
                             if (is_internal(src) and not is_internal(dst))
                             else "other"
            })
    return sorted(results, key=lambda x: x["jitter_ratio"])


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "conn.log"
    print(f"[*] Loading {log_path}...")
    pairs = load_conn_log(log_path)
    print(f"[*] Analyzing {len(pairs)} unique src->dst:port pairs...")
    beacons = analyze_beaconing(pairs)
    if not beacons:
        print("[*] No beaconing detected.")
        return
    print(f"\n[!] Potential beacons ({len(beacons)} found):\n")
    hdr = f"{'SRC':<18} {'DST':<18} {'PORT':<8} {'CONNS':<7} {'MEAN_S':<10} {'STDDEV':<10} {'JITTER':<8} DIRECTION"
    print(hdr)
    print("-" * len(hdr))
    for b in beacons[:20]:
        print(f"{b['src']:<18} {b['dst']:<18} {b['dport']:<8} {b['connections']:<7} "
              f"{b['mean_interval_s']:<10} {b['stddev_s']:<10} {b['jitter_ratio']:<8} {b['direction']}")


if __name__ == "__main__":
    main()
```

---

### DGA Detection (Python + Zeek dns.log)

```python
#!/usr/bin/env python3
# dga_detect.py -- detect DGA (Domain Generation Algorithm) domains in Zeek dns.log
# Usage: python3 dga_detect.py /path/to/dns.log

import sys
import math
import re
from collections import defaultdict

ENTROPY_THRESHOLD  = 3.5   # bits -- DGA labels typically > 3.5
MIN_DOMAIN_LEN     = 10
MIN_VOWEL_RATIO    = 0.20  # legitimate words have ~40% vowels; DGA often < 20%
NXDOMAIN_THRESHOLD = 10    # flag src with > N NXDOMAINs
WHITELIST = {"google.com", "youtube.com", "facebook.com", "microsoft.com",
             "amazon.com", "apple.com", "netflix.com", "github.com"}


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


def vowel_ratio(s):
    return sum(1 for c in s.lower() if c in "aeiou") / len(s) if s else 0.0


def extract_apex(fqdn):
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


def score_domain(domain):
    label = domain.split(".")[0]
    ent   = shannon_entropy(label)
    vr    = vowel_ratio(label)
    length = len(label)
    score, flags = 0, []
    if ent > ENTROPY_THRESHOLD:
        score += 2; flags.append(f"entropy={ent:.2f}")
    if vr < MIN_VOWEL_RATIO:
        score += 2; flags.append(f"vowels={vr:.2f}")
    if length > 20:
        score += 1; flags.append(f"long={length}")
    if re.match(r"^[a-z]{15,}$", label):
        score += 1; flags.append("all_alpha_run")
    if re.search(r"[0-9]{4,}", label):
        score += 1; flags.append("numeric_run")
    return {"domain": domain, "label": label, "score": score, "flags": flags,
            "entropy": round(ent, 3), "vowel_ratio": round(vr, 3)}


def parse_dns_log(path):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            if len(parts) < 10:
                continue
            src   = parts[2]
            query = parts[9].lower().rstrip(".")
            rcode = parts[13] if len(parts) > 13 else "-"
            if query and query != "-":
                records.append((src, query, rcode))
    return records


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "dns.log"
    records = parse_dns_log(log_path)
    nxd_by_src = defaultdict(int)
    candidates = []
    for src, query, rcode in records:
        if extract_apex(query) in WHITELIST:
            continue
        if rcode == "NXDOMAIN":
            nxd_by_src[src] += 1
        result = score_domain(query)
        if result["score"] >= 3:
            result["src"] = src
            result["rcode"] = rcode
            candidates.append(result)

    print("\n[!] High-NXDOMAIN sources (potential DGA):")
    for src, cnt in sorted(nxd_by_src.items(), key=lambda x: -x[1]):
        if cnt > NXDOMAIN_THRESHOLD:
            print(f"  {src}: {cnt} NXDOMAINs")

    print(f"\n[!] High-entropy / suspicious domains ({len(candidates)} found):")
    seen = set()
    for c in sorted(candidates, key=lambda x: -x["score"])[:30]:
        if c["domain"] in seen:
            continue
        seen.add(c["domain"])
        print(f"  score={c['score']} src={c['src']} domain={c['domain']} "
              f"entropy={c['entropy']} vowels={c['vowel_ratio']} "
              f"rcode={c['rcode']} flags={','.join(c['flags'])}")


if __name__ == "__main__":
    main()
```

---

### Lateral Movement Detection

```bash
# Internal hosts making SMB connections to many other internal hosts
# Flag sources with > 5 unique internal SMB destinations
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | \
  awk '$4 == "445"' | \
  awk '$2 ~ /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/' | \
  awk '$3 ~ /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/' | \
  awk '{print $2, $3}' | sort | uniq | \
  awk '{count[$1]++} END {for(src in count) if(count[src]>5) print src, count[src]}' | \
  sort -k2 -rn | head 20

# Zeek smb_files.log: access to admin shares (IPC$, C$, ADMIN$)
zeek-cut ts id.orig_h id.resp_h path action < smb_files.log 2>/dev/null | \
  awk '$4 ~ /IPC\$|C\$|ADMIN\$|D\$|E\$/' | head 30

# Internal RDP connections (lateral movement)
zeek-cut ts id.orig_h id.resp_h cookie result < rdp.log | \
  awk '$2 ~ /^(192\.168\.|10\.|172\.)/ && $3 ~ /^(192\.168\.|10\.|172\.)/' | head 30

# WMI/DCOM lateral movement (port 135 between internal hosts)
zeek-cut ts id.orig_h id.resp_h id.resp_p service < conn.log | \
  awk '$4 == "135" && $2 ~ /^(192\.168\.|10\.|172\.)/ && $3 ~ /^(192\.168\.|10\.|172\.)/' | \
  awk '{print $2, $3}' | sort | uniq -c | sort -rn | head 20
```

---

## 7. DNS Security Monitoring

### Key Anomaly Types

| Anomaly | Indicator | Detection Method |
|---|---|---|
| **DGA traffic** | High NXDOMAIN rate per source | NXDOMAIN count > 50/min per src |
| **DNS tunneling** | Long subdomain labels (>50 chars) | Label length check in dns.log |
| **DNS tunneling** | High entropy subdomains | Shannon entropy > 3.5 bits |
| **DNS tunneling** | High query rate to single apex | >100 queries/min to one domain |
| **Data exfil via DNS** | TXT record queries with large content | TXT queries with payloads |
| **C2 via DNS** | DNS on non-standard ports | Port != 53 with DNS traffic |
| **Reconnaissance** | ANY/AXFR record queries | qtype = ANY or AXFR |
| **Homograph attacks** | Unicode look-alike domains | IDN/punycode in query |
| **Fast flux** | Rapidly changing A record IPs | TTL < 60s + many unique answers |

---

### DNS Tunneling Detection

```bash
# Long query labels (>50 characters -- potential base64/hex payload)
zeek-cut ts id.orig_h query qtype_name < dns.log | \
  awk '{
    n = split($3, parts, ".")
    for (i=1; i<=n-2; i++) {
      if (length(parts[i]) > 50) {
        print $1, $2, $3, "label_len=" length(parts[i])
        break
      }
    }
  }' | head 20

# High entropy subdomain detection (inline Python)
python3 - << 'PYEOF'
import sys, math, collections

def entropy(s):
    freq = collections.Counter(s)
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

with open("dns.log") as f:
    for line in f:
        if line.startswith("#"): continue
        parts = line.strip().split("\t")
        if len(parts) < 10: continue
        query  = parts[9]
        labels = query.split(".")
        if len(labels) < 3: continue
        sub = ".".join(labels[:-2])
        if len(sub) > 20 and entropy(sub) > 3.5:
            print(f"HIGH_ENTROPY src={parts[2]} query={query} ent={entropy(sub):.2f}")
PYEOF

# High query rate to single apex domain (60-second bins, > 200 queries)
zeek-cut ts id.orig_h query < dns.log | \
  awk '{
    window = int($1 / 60) * 60
    n = split($3, p, ".")
    apex  = p[n-1] "." p[n]
    key   = window ":" $2 ":" apex
    count[key]++
  } END {
    for (k in count) if (count[k] > 200) print count[k], k
  }' | sort -rn | head 10
```

---

### Passive DNS for Threat Hunting

```bash
# Query SecurityTrails passive DNS API
curl -H "apikey: $ST_API_KEY" \
  "https://api.securitytrails.com/v1/history/evil.example.com/dns/a" | \
  jq '.records[] | {first_seen, last_seen, values: .values[].ip}'

# Build local passive DNS database from Zeek dns.log
zeek-cut ts query answers < dns.log | \
  awk '$3 != "-" && $3 ~ /^[0-9]/' | \
  awk '{print $2, $3}' | sort -u > pdns_local.txt
```

---

### DNS RPZ (Response Policy Zone) for Blocking

```
; named.conf -- enable RPZ
options {
    response-policy { zone "rpz.blocklist"; };
};

; rpz.blocklist.zone
$TTL 60
@ IN SOA localhost. root.localhost. 1 3600 900 604800 60
  IN NS  localhost.

; Block malicious domains (return NXDOMAIN)
evil.example.com.rpz.blocklist.  IN CNAME .
*.evil.example.com.rpz.blocklist. IN CNAME .

; Redirect to sinkhole for logging
malware-c2.xyz.rpz.blocklist.    IN A 192.168.1.254
```

---

## 8. Full Packet Capture

### Arkime (Moloch)

Arkime is an open-source large-scale full packet capture and indexed session analysis platform. It stores PCAP to disk and indexes sessions into Elasticsearch for fast field-level queries.

**Key Arkime search fields**:

```
# IP addressing
ip == 192.168.1.50
ip.src == 10.0.0.0/8
ip.dst == 203.0.113.0/24
port == 443
port.dst == 8443

# HTTP fields
http.host == "evil.example.com"
http.uri == "/shell.php"
http.method == "POST"
http.user-agent == "python-requests/2.28.0"
http.status-code == 200

# DNS fields
dns.query == "suspicious.xyz"
dns.status == "NXDOMAIN"

# TLS/SSL fields
tls.ja3 == "a0e9f5d64349fb13191bc781f81f42e1"
tls.server-name == "*.evil.xyz"

# File fields
file.md5 == "d41d8cd98f00b204e9800998ecf8427e"
file.mime == "application/x-dosexec"

# Logic operators
ip == 192.168.1.50 && port == 443
http.host == "*.xyz" && http.method == "POST"
```

---

### Wireshark Hunting Display Filters

```
// Non-browser HTTP user-agents
http.user_agent and not (
  http.user_agent contains "Mozilla" or
  http.user_agent contains "curl" or
  http.user_agent contains "wget"
)

// Empty user-agent (suspicious)
http.request and not http.user_agent

// Suspicious URI patterns (webshells)
http.request.uri matches "/(cmd|shell|exec|upload|eval|phpinfo)(\.php)?"

// Large HTTP POST (potential exfiltration)
http.request.method == "POST" and http.content_length > 100000

// HTTP to non-standard ports
http and not (tcp.port == 80 or tcp.port == 8080 or tcp.port == 8000)

// DNS on non-standard port (tunneling)
dns and not (udp.port == 53 or tcp.port == 53)

// DNS zone transfer attempt
dns.qry.type == 252

// SMB NTLM authentication (lateral movement indicator)
ntlmssp

// Kerberoasting: TGS-REQ with RC4 encryption type (23)
kerberos.msg_type == 12 and kerberos.etype == 23

// TLS without SNI (unusual for modern legitimate traffic)
tls.handshake.type == 1 and not tls.handshake.extensions_server_name

// SYN scan (many SYN packets, no data)
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.len == 0

// ICMP sweep (ping scan)
icmp.type == 8 and ip.dst != ip.src
```

---

### tcpdump for Capture

```bash
# Basic capture on interface, write PCAP
tcpdump -i eth0 -s 65535 -w /captures/traffic.pcap

# Capture only HTTP/HTTPS
tcpdump -i eth0 -s 65535 -w http.pcap 'tcp port 80 or tcp port 443'

# Capture from/to specific host
tcpdump -i eth0 -w host.pcap 'host 192.168.1.100'

# Ring buffer: rotate every hour, keep 24 files, limit each to 100MB
tcpdump -i eth0 -s 65535 \
  -G 3600 \
  -C 100 \
  -W 24 \
  -w '/captures/traffic-%Y%m%d-%H%M%S.pcap' \
  -z gzip

# Read and filter existing PCAP
tcpdump -r traffic.pcap -w filtered.pcap 'host 192.168.1.50 and port 443'

# Read with ASCII decode
tcpdump -r traffic.pcap -A 'port 80' | head 100
```

---

## 9. Security Onion Platform

### Architecture Overview

Security Onion integrates the full NSM stack into a single deployable platform:

| Component | Role |
|---|---|
| **Zeek** | Application-layer log generation |
| **Suricata** | Signature-based IDS alerting |
| **Strelka** | Real-time file analysis (YARA + PE + scripts) |
| **Elasticsearch** | Log indexing and search backend |
| **Kibana** | Visualization and dashboards |
| **Hunt UI** | Alert triage with ATT&CK mapping |
| **Arkime** | Full PCAP storage and session replay |
| **FleetDM** | Endpoint agent management (osquery) |

**Deployment modes**:
- **Single-node (standalone)**: All components on one server. Minimum: 4 CPU, 16GB RAM, 200GB storage.
- **Distributed**: Manager node + forward sensors. Sensors run Zeek + Suricata + Arkime; manager handles Elasticsearch/Kibana.

---

### Alert Triage Workflow

```
1. Suricata alert fires in Hunt / Kibana
   |
   v
2. Examine alert metadata:
   - Rule SID, message, and severity
   - Source and destination IP/port
   - Timestamp and flow direction
   |
   v
3. Pivot to PCAP (Arkime):
   - Click "PCAP" link from alert
   - Full session reconstruction and stream reassembly
   - Examine raw bytes and decoded protocol fields
   |
   v
4. Pivot to Zeek logs (matching UID / Community ID):
   - conn.log: bytes, duration, connection state
   - dns.log: pre-connection DNS lookups
   - http.log: HTTP request/response details
   - ssl.log: TLS version, cipher, JA3 fingerprint
   - files.log: extracted files and hashes
   |
   v
5. Full context assessment:
   - Is source IP internal or external?
   - Is destination IP known-bad (TI feed match)?
   - What user/device is the source? (DHCP/asset inventory)
   - Are there related alerts in the +/- 1 hour window?
   |
   v
6. Escalate or close with documented justification
```

---

### Key Commands

```bash
# Initial setup
sudo so-setup-wizard

# Update Suricata rules
sudo so-rule-update

# Restart all services
sudo so-restart

# Check service status
sudo so-status

# Query Elasticsearch
sudo so-elasticsearch-query '{"query": {"match": {"event.module": "zeek"}}}'

# Tail Suricata alerts (EVE JSON)
sudo tail -f /nsm/suricata/eve.json | jq '. | select(.event_type == "alert")'

# Tail Zeek conn.log
sudo tail -f /nsm/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p service

# Add a custom local Suricata rule
echo 'alert http any any -> any any (msg:"Test Rule"; content:"test"; sid:9999999; rev:1;)' \
  | sudo tee -a /opt/so/rules/local.rules
sudo so-rule-update
```

---

## 10. Detection KQL/Elasticsearch

### Beaconing Query

```json
// Elasticsearch aggregation: find high-count src->dst:port pairs
POST /zeek-conn-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term":  {"event.dataset": "zeek.conn"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}}
      ]
    }
  },
  "aggs": {
    "connections": {
      "composite": {
        "sources": [
          {"src":  {"terms": {"field": "source.ip"}}},
          {"dst":  {"terms": {"field": "destination.ip"}}},
          {"port": {"terms": {"field": "destination.port"}}}
        ]
      },
      "aggs": {
        "connection_count": {"value_count": {"field": "@timestamp"}},
        "total_bytes":      {"sum":         {"field": "network.bytes"}}
      }
    }
  }
}
```

---

### DNS Tunneling Query

```kql
// Kibana KQL: DNS queries with long names (> 40 chars)
event.dataset: "zeek.dns" AND dns.question.name: *
  | where length(dns.question.name) > 40
  | stats count() by source.ip, dns.question.name
  | sort count desc

// High NXDOMAIN rate per source (possible DGA)
event.dataset: "zeek.dns" AND dns.response_code: "NXDOMAIN"
  | stats count() by source.ip
  | where count > 100
  | sort count desc
```

---

### Large Exfiltration Query

```kql
// Outbound transfers > 100MB to external IPs
event.dataset: "zeek.conn"
  AND source.ip: (192.168.0.0/16 OR 10.0.0.0/8)
  AND NOT destination.ip: (192.168.0.0/16 OR 10.0.0.0/8)
  | where network.bytes_out > 104857600
  | stats sum(network.bytes_out) as total_bytes by source.ip, destination.ip
  | sort total_bytes desc
```

---

### RITA (Real Intelligence Threat Analytics)

RITA is an open-source behavioral analytics framework built on Zeek for automated detection of:
- **Beaconing C2** -- statistical analysis of connection timing intervals
- **Long connections** -- persistent sessions exceeding configurable threshold
- **DNS tunneling** -- query length, entropy, and FQDN anomaly scoring
- **Threat intelligence** -- automatic IOC matching against imported feeds

**Reference**: https://github.com/activecm/rita

```bash
# Install RITA
curl https://raw.githubusercontent.com/activecm/rita/master/install.sh | bash

# Import Zeek logs for a dataset
rita import /path/to/zeek/logs/ incident-2024-01

# Show beacon candidates
rita show-beacons incident-2024-01 --all

# Show DNS tunneling indicators
rita show-dns-tunneling incident-2024-01 --all

# Show long-duration connections
rita show-long-connections incident-2024-01 --all

# Generate HTML report
rita html-report incident-2024-01 --open-browser
```

---

## 11. Tools Reference Table

| Tool | Category | Purpose | URL |
|---|---|---|---|
| **Zeek** | NSM / Protocol Logging | Application-layer log generation: conn, dns, http, ssl, smtp, files | https://zeek.org |
| **Suricata** | IDS/IPS | Signature detection, EVE JSON output, inline IPS mode | https://suricata.io |
| **Snort** | IDS/IPS | Oldest open-source IDS, large community ruleset, DAQ library | https://snort.org |
| **Security Onion** | NSM Platform | Integrated: Zeek + Suricata + Elastic + Kibana + Strelka + FleetDM | https://securityonion.net |
| **Arkime** | Full Packet Capture | Indexed PCAP storage and session search (Moloch successor) | https://arkime.com |
| **Wireshark** | Packet Analysis | GUI-based PCAP analysis, protocol dissection, 2000+ dissectors | https://wireshark.org |
| **tshark** | Packet Analysis | CLI Wireshark -- scriptable PCAP analysis, field extraction | https://wireshark.org/docs/man-pages/tshark.html |
| **tcpdump** | Packet Capture | Lightweight CLI capture, ring buffer support, BPF filtering | https://www.tcpdump.org |
| **ntopng** | Flow / Traffic Analytics | Real-time traffic monitoring, flow visualization, anomaly scoring | https://www.ntop.org |
| **Strelka** | File Analysis | Real-time file analysis: YARA, PE, macros, scripts, archives | https://github.com/target/strelka |
| **RITA** | Behavioral Analytics | Zeek-based beacon/DNS-tunnel/C2 detection and reporting | https://github.com/activecm/rita |
| **SiLK** | Flow Analysis | Query NetFlow/IPFIX/sFlow -- rwfilter, rwstats, rwcount, rwcut | https://tools.netsa.cert.org/silk |
| **nfdump** | Flow Analysis | NetFlow collector (nfcapd) and query tool with aggregation support | https://github.com/phaag/nfdump |
| **JARM** | TLS Fingerprinting | Active server-side TLS fingerprinting (Salesforce open-source) | https://github.com/salesforce/jarm |
| **Scapy** | Packet Crafting | Python library for packet construction, capture, replay, and fuzzing | https://scapy.net |
| **FlowBAT** | Flow Visualization | Browser-based SiLK / NetFlow analysis frontend | https://www.flowbat.com |

---

*See also: [Network Attacks Reference](NETWORK_ATTACKS_REFERENCE.md) | [Packet Analysis Reference](PACKET_ANALYSIS_REFERENCE.md) | [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) | [SIEM Detection Content](SIEM_DETECTION_CONTENT.md)*
