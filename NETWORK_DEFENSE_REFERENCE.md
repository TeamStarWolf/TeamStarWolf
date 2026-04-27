# Network Defense Reference Library

> Comprehensive reference for network defense, monitoring, and security operations.

---

## Table of Contents

1. [Network Defense Architecture](#1-network-defense-architecture)
2. [Suricata IDS/IPS](#2-suricata-idsips)
3. [Zeek Network Analysis Framework](#3-zeek-network-analysis-framework)
4. [Security Onion](#4-security-onion)
5. [Arkime Full Packet Capture](#5-arkime-full-packet-capture)
6. [DNS Security and Monitoring](#6-dns-security-and-monitoring)
7. [nDPI Deep Packet Inspection](#7-ndpi-deep-packet-inspection)
8. [Network Access Control](#8-network-access-control)
9. [DDoS Protection and Traffic Scrubbing](#9-ddos-protection-and-traffic-scrubbing)
10. [Network Defense Operations](#10-network-defense-operations)

---

## 1. Network Defense Architecture

### Defense-in-Depth for Networks

Defense-in-depth is the foundational principle of layered network security — no single control is sufficient; multiple overlapping controls are required so that when one fails, others compensate.

#### Perimeter Layer
- **Firewall (stateful/NGFW):** Enforces ingress and egress policy; blocks unauthorized traffic by port, protocol, and application.
- **IDS/IPS:** Inspects traffic crossing the boundary; alerts on or blocks known malicious signatures and anomalies.
- **Anti-DDoS / Scrubbing:** Upstream volumetric filtering; rate limiting at the edge router.
- **Email & Web Gateway:** Inline scanning of HTTP(S) and SMTP traffic for malware and phishing content.
- **DMZ (Demilitarized Zone):** Isolates externally facing services (web, mail, DNS) from internal networks. Traffic flows: Internet → Firewall → DMZ → Firewall → Internal. Hosts in the DMZ must never be trusted by internal systems.

#### Internal / Core Layer
- **Internal Segmentation Firewall (ISFW):** Micro-segments the internal network by business unit, function, or sensitivity level.
- **VLAN Segregation:** Layer 2 separation of traffic domains (servers, users, IoT, management).
- **Zero-Trust Architecture (ZTA):** "Never trust, always verify" — all sessions authenticated and authorized regardless of network location.
- **East-West Traffic Inspection:** Lateral movement detection between internal segments via taps, NDR, and service mesh telemetry.

#### Endpoint Layer
- **Host-based Firewall:** OS-level packet filtering; prevents unauthorized listening services.
- **EDR / XDR:** Behavioral detection on the host; telemetry fed back to central SIEM.
- **Application Whitelisting:** Prevents execution of unauthorized binaries.

#### Cloud Layer
- **Security Groups / NACLs:** Virtual firewall policy applied per VPC, subnet, or instance.
- **Cloud-native CSPM:** Continuous posture management for misconfigured cloud resources.
- **VPC Flow Logs / NSG Flow Logs:** Native L4 telemetry; equivalent of NetFlow in cloud environments.
- **CASB:** Visibility and control over SaaS application usage.

---

### Network Security Monitoring (NSM) Fundamentals

NSM is the collection, analysis, and escalation of network data to detect and respond to intrusions. Coined by Richard Bejtlich, NSM focuses on **visibility**, **collection**, and **analysis**.

#### NSM Data Types
| Type | Description | Example Tools |
|------|-------------|---------------|
| Full Packet Capture (FPC) | Raw packet data, every byte | Arkime, tcpdump, Wireshark |
| Session / Flow Data | Summarized connection metadata (5-tuple + bytes/packets) | NetFlow, IPFIX, sFlow, Zeek conn.log |
| Alert Data | Signature or anomaly-triggered events | Suricata, Snort |
| Statistical Data | Aggregated traffic patterns over time | ntopng, Grafana dashboards |
| Extracted Content | Files, certificates, credentials extracted from streams | Zeek files.log, NetworkMiner |
| Log Data | Application and infrastructure logs correlated with network | Syslog, Windows Event Log |

#### NSM Sensor Placement
- **Tap (Test Access Point):** Passive optical or copper tap; copies all traffic without introducing latency or single points of failure. Preferred for production environments.
- **SPAN Port (Switch Port Analyzer):** Mirror port on a managed switch; may drop packets under high load. Acceptable for lower-speed links.
- **Inline (Bump-in-the-wire):** Sensor sits in the traffic path; required for IPS blocking. Introduces latency and potential failure point — use bypass NICs with fail-open capability.
- **Agent-based / eBPF:** Host-level packet capture; useful for east-west traffic inside container or VM environments.

#### Traffic Analysis Methodology
1. **Baseline Establishment:** Capture "normal" traffic patterns (protocols, top talkers, bytes/sec, connection frequency) over a 2–4 week period. Document authorized services, expected external connections, and internal communication patterns.
2. **Anomaly Detection:** Compare real-time metrics against baseline; alert on statistically significant deviations.
3. **Signature Matching:** Apply known-bad rules (Suricata/Snort signatures) to identified traffic.
4. **Threat Hunting:** Proactive hypothesis-driven searches through historical traffic data for TTPs not caught by automated alerts.
5. **Incident Investigation:** Pivot from alert → flow data → PCAP to reconstruct attacker actions.

#### Visibility Gaps
| Gap | Description | Mitigation |
|-----|-------------|------------|
| Encrypted Traffic | TLS 1.3 prevents payload inspection | JA3/JA3S fingerprinting; TLS interception (where policy allows); metadata analysis |
| East-West / Lateral | Traffic between internal hosts often unseen | Internal taps; microsegmentation; host-based telemetry |
| Cloud / SaaS | Traffic terminating at cloud provider | VPC Flow Logs; CASB; DNS monitoring |
| Encrypted DNS (DoH/DoT) | DNS bypasses traditional monitoring | Enforce internal DNS resolvers; inspect at proxy; monitor DoH endpoints |
| IPv6 | Often unmonitored on dual-stack networks | Ensure sensor infrastructure supports IPv6 |
| Wireless | 802.11 traffic not on wired taps | Wireless IDS/IPS; WLAN controller logging |

#### Network Security Tool Categories
| Category | Purpose | Examples |
|----------|---------|---------|
| IDS (Intrusion Detection System) | Passive alert on malicious traffic | Suricata (alert mode), Snort |
| IPS (Intrusion Prevention System) | Inline block of malicious traffic | Suricata (drop mode), Palo Alto NGFW |
| NDR (Network Detection & Response) | Behavioral + ML-based network analysis | Corelight, ExtraHop, Vectra AI |
| PCAP / FPC | Full packet recording and retrieval | Arkime, Stenographer |
| Flow Analysis | NetFlow/IPFIX collection and analysis | nProbe, ntopng, SiLK, ElastiFlow |
| DNS Monitoring | DNS query logging, filtering, RPZ | Pi-hole, AdGuard Home, BIND RPZ |
| DPI | Deep packet inspection for protocol ID | nDPI, Zeek |


---

## 2. Suricata IDS/IPS

### Architecture

Suricata (https://suricata.io/) is a high-performance, open-source IDS, IPS, and NSM engine maintained by the Open Information Security Foundation (OISF).

#### Multi-Threaded Design
- **Capture Threads:** Receive packets from the NIC (AF_PACKET, PF_RING, DPDK, or libpcap).
- **Decode Threads:** Parse Ethernet, IP, TCP/UDP/ICMP headers.
- **Detect Threads:** Apply signature rules against decoded traffic; one thread per CPU core is typical.
- **Output Threads:** Write logs (Eve JSON, PCAP, unified2) asynchronously.
- **Flow Engine:** Maintains flow state table for TCP session reassembly and protocol detection.

#### Capture Methods (Performance Order)
| Method | Description |
|--------|-------------|
| DPDK | Kernel-bypass; highest throughput (10–100 Gbps). Requires DPDK-compatible NIC. |
| PF_RING ZC | Zero-copy kernel module; 10+ Gbps with commodity NICs. |
| AF_PACKET | Linux native; cluster mode distributes flows across threads. Most common production method. |
| libpcap | Portable; lower performance. Development/testing only. |

```yaml
# suricata.yaml — AF_PACKET capture example
af-packet:
  - interface: eth0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 131072
```

---

### Rule Syntax

A Suricata rule consists of a **header** and a **body** (options).

#### Header Format
```
action protocol src_ip src_port direction dst_ip dst_port
```

| Field | Values |
|-------|--------|
| action | `alert`, `drop`, `reject`, `pass`, `rejectsrc`, `rejectdst`, `rejectboth` |
| protocol | `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `tls`, `smtp`, `ftp`, `ssh`, `dnp3`, `modbus` |
| src/dst | IP, CIDR, `any`, `$HOME_NET`, `$EXTERNAL_NET`, variable groups |
| ports | Port, port range (`1024:65535`), negation (`!80`), group (`[80,443]`) |
| direction | `->` (unidirectional), `<>` (bidirectional) |

#### Body (Options) — Key Keywords

**Content Matching**
```
content:"malware.exe";          # Case-sensitive byte match
content:"GET"; nocase;          # Case-insensitive
content:"|0d 0a|";              # Hex byte sequence
pcre:"/evil[0-9]+\.com/i";     # Perl-compatible regex
```

**Context Modifiers (Sticky Buffers)**
```
http.uri; content:"/admin/shell.php";
http.header; content:"User-Agent|3a| curl";
http.request_body; content:"cmd=";
dns.query; content:"evil.com";
tls.sni; content:"malicious.";
```

**Metadata / Classification**
```
msg:"ET MALWARE Cobalt Strike Beacon";
classtype:trojan-activity;
sid:2034567;
rev:3;
metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit,
         attack_target Client_Endpoint,
         created_at 2024_01_15,
         deployment Perimeter,
         signature_severity Major,
         tag CobaltStrike;
```

**Flow and State**
```
flow:to_server,established;     # Only match client→server in established TCP session
flow:from_server,established;   # Only match server→client responses
flowbits:set,http.post;         # Set a flag for cross-rule correlation
flowbits:isset,http.post;       # Check flag set by previous rule
```

**Thresholding**
```
threshold: type limit, track by_src, count 1, seconds 60;   # Alert once per src per minute
threshold: type threshold, track by_src, count 10, seconds 5; # Alert after 10 hits in 5s
threshold: type both, track by_src, count 5, seconds 60;    # Limit + threshold combined
detection_filter: track by_src, count 100, seconds 10;      # Post-match rate filter
```

#### Full Example Rule
```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (
    msg:"ET WEB_SERVER PHP Remote Code Execution Attempt";
    flow:established,to_server;
    http.uri;
    content:"/shell.php";
    http.request_body;
    content:"cmd=";
    pcre:"/cmd=(\%20|\+)*(whoami|id|ls|cat|wget|curl|bash|sh|python)/i";
    classtype:web-application-attack;
    sid:9000001;
    rev:1;
)
```

---

### Rule Categories

| Source | Description | URL |
|--------|-------------|-----|
| ET Open | Free Emerging Threats ruleset; community maintained | https://rules.emergingthreats.net/ |
| ET Pro | Commercial subscription; faster updates, broader coverage | https://www.proofpoint.com/us/threat-insight/et-pro-ruleset |
| Snort Community | Community Snort rules (Suricata-compatible) | https://www.snort.org/downloads/#rule-downloads |
| PTRESEARCH | PT Research threat intel rules | https://github.com/ptresearch/AttackDetection |
| ThreatFox | Abuse.ch IOC-based rules | https://threatfox.abuse.ch/ |

---

### Inline IPS Mode

In IPS mode, Suricata sits **inline** (NFQUEUE or AF_PACKET with copy-mode) and can **drop** or **reject** packets matching rules.

```bash
# NFQUEUE mode — redirect kernel traffic to Suricata via iptables
iptables -I FORWARD -j NFQUEUE --queue-num 0
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I OUTPUT -j NFQUEUE --queue-num 0

# Launch Suricata in IPS NFQUEUE mode
suricata -q 0 -c /etc/suricata/suricata.yaml -l /var/log/suricata/
```

**Action Semantics in IPS Mode**
| Action | IDS Mode | IPS Mode |
|--------|----------|----------|
| `alert` | Log event | Log event, pass packet |
| `drop` | Log event (treated as alert) | Log event, drop packet silently |
| `reject` | Log event | Log event, send TCP RST / ICMP unreachable |
| `pass` | Skip remaining rules | Skip remaining rules, pass packet |

---

### Eve JSON Output

Suricata's primary log format is structured JSON (`eve.json`), enabling easy ingestion into ELK, Splunk, or Graylog.

```json
{
  "timestamp": "2025-06-15T14:23:01.123456+0000",
  "flow_id": 1234567890123456,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "203.0.113.42",
  "src_port": 54321,
  "dest_ip": "10.0.0.50",
  "dest_port": 443,
  "proto": "TCP",
  "community_id": "1:abcdef1234567890abcdef1234567890=",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2034567,
    "rev": 3,
    "signature": "ET MALWARE Cobalt Strike Beacon",
    "category": "A Network Trojan was Detected",
    "severity": 1
  },
  "http": {
    "hostname": "malicious.example.com",
    "url": "/jquery.min.js",
    "http_user_agent": "Mozilla/5.0",
    "http_method": "GET",
    "status": 200,
    "length": 4096
  },
  "tls": {
    "sni": "malicious.example.com",
    "version": "TLS 1.3",
    "ja3": {"hash": "a0e9f5d64349fb13191bc781f81f42e1"},
    "ja3s": {"hash": "fd4bc6cea4877646ccd62f0792ec0b62"}
  },
  "app_proto": "http"
}
```

---

### Suricata-Update Rule Management

```bash
# Install suricata-update
pip install suricata-update

# List available rule sources
suricata-update list-sources

# Update source index
suricata-update update-sources

# Enable ET Open (free)
suricata-update enable-source et/open

# Enable additional sources
suricata-update enable-source oisf/trafficid
suricata-update enable-source ptresearch/attackdetection

# Download and merge all enabled rulesets
suricata-update

# Test configuration before applying
suricata -T -c /etc/suricata/suricata.yaml

# Launch Suricata in IDS mode on interface eth0
suricata -i eth0 -c /etc/suricata/suricata.yaml -l /var/log/suricata/

# Disable a specific rule by SID
suricata-update --disable-conf /etc/suricata/disable.conf

# Contents of disable.conf
# re:heartbleed   # disable all rules matching "heartbleed"
# group:emerging-info  # disable entire category
# 2013028          # disable specific SID
```

---

### Performance Tuning

```yaml
# CPU affinity — pin threads to specific cores
threading:
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - receive-cpu-set:
        cpu: [1, 2]
    - worker-cpu-set:
        cpu: [3, 4, 5, 6, 7]
        mode: "exclusive"
        prio:
          default: "high"

# Memory settings
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000

stream:
  memcap: 256mb
  checksum-validation: no  # Disable for SPAN port (checksum may be wrong)
  reassembly:
    memcap: 256mb
    depth: 1mb              # How much data to reassemble per direction
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
```

**Scirius (Stamus Networks):** Web-based rule management GUI for Suricata. Provides rule activation/deactivation, policy management, threshold editing, and performance dashboards. Available at https://github.com/StamusNetworks/scirius.


---

## 3. Zeek Network Analysis Framework

### Architecture

Zeek (formerly Bro) is a passive network analysis framework that transforms raw packet data into structured, high-level logs. Unlike signature-based IDS, Zeek's primary mode is **semantic analysis** — understanding what is happening in network traffic and recording it as rich metadata.

#### Core Components
- **Event Engine:** Parses protocols, assembles TCP streams, and generates events (e.g., `http_request`, `dns_request`, `ssl_client_hello`).
- **Policy Script Interpreter:** Zeek scripts (`.zeek` files) define what happens when events fire — logging, alerting, correlation.
- **Communication Framework (Broker):** Enables distributed Zeek deployments to share events and data in real time.
- **Logging Framework:** Writes structured TSV/JSON logs per protocol.

```
Network Traffic → [Event Engine] → Events → [Policy Scripts] → Logs / Notices / Actions
                       ↓
               Protocol Parsers
               (HTTP, DNS, TLS, SMB, SMTP, SSH, FTP, x509, QUIC...)
```

---

### Log Types

| Log File | Contents |
|----------|---------|
| `conn.log` | All TCP/UDP/ICMP connections: 5-tuple, duration, bytes, state |
| `dns.log` | DNS queries and responses: query, type, answer, TTL, rcode |
| `http.log` | HTTP requests: method, URI, host, user-agent, status, mime-type, response length |
| `ssl.log` | TLS sessions: version, cipher, SNI, cert subject, JA3/JA3S (with package) |
| `x509.log` | Certificate details: subject, issuer, SAN, validity, key bits |
| `files.log` | Files extracted or observed: MIME type, MD5/SHA1/SHA256, source, filename |
| `smtp.log` | Email sessions: from, to, subject, header details |
| `ssh.log` | SSH sessions: client/server version, auth method, direction, compressed |
| `smb_files.log` | SMB file operations: filename, action, size, path |
| `smb_mapping.log` | SMB tree connections: share name, path, native_file_system |
| `notice.log` | Analyst-visible detections triggered by policy scripts |
| `weird.log` | Protocol anomalies and unexpected behavior |
| `pe.log` | Portable Executable metadata (Windows binaries in HTTP/SMB) |
| `rdp.log` | RDP sessions: cookie, result, security_protocol, client_name |
| `kerberos.log` | Kerberos authentication events (AS-REQ/TGS-REQ) |
| `intel.log` | Hits against the Intelligence Framework (IOC matches) |

#### conn.log Key Fields
```
ts          uid             id.orig_h    id.orig_p  id.resp_h    id.resp_p  proto  service
1718456582  CGqH1y3mXXa1j  10.0.1.50    54321      8.8.8.8      53         udp    dns
duration    orig_bytes  resp_bytes  conn_state  missed_bytes  history
0.002341    45          89          SF          0             Dd
```

**conn_state Values:** SF (normal close), S0 (no reply), S1 (established, no close), RSTO/RSTR (reset), SH/SHR (SYN+SYN-ACK only), OTH (other)

---

### Zeek Scripting Language

Zeek scripts are written in a domain-specific language. They respond to events generated by the protocol parsers.

```zeek
# Basic event handler — log all HTTP POSTs to suspicious external hosts
@load base/protocols/http

module DetectSuspiciousPOST;

export {
    redef enum Notice::Type += { Suspicious_POST };
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if (method == "POST" && Site::is_private_addr(c$id$orig_h) &&
        !Site::is_private_addr(c$id$resp_h))
    {
        NOTICE([$note=Suspicious_POST,
                $conn=c,
                $msg=fmt("POST to external host: %s%s", c$http$host, original_URI),
                $identifier=cat(c$id$resp_h)]);
    }
}
```

#### Zeek Data Types
| Type | Example |
|------|---------|
| `addr` | `10.0.0.1`, `::1` |
| `port` | `80/tcp`, `53/udp` |
| `subnet` | `192.168.0.0/16` |
| `string` | `"hello"` |
| `count` | `42` |
| `interval` | `5 min`, `30 sec` |
| `time` | `network_time()` |
| `set[T]` | `set[addr]` |
| `table[K] of V` | `table[addr] of count` |
| `vector of T` | `vector of string` |
| `record` | Named field aggregate |

---

### Intelligence Framework

The Zeek Intelligence Framework allows loading IOC feeds and auto-matching them against all traffic.

```zeek
# /opt/zeek/share/zeek/site/intel/indicators.dat
# Format: indicator  indicator_type  meta.source  meta.desc
203.0.113.42    Intel::ADDR      ThreatFeed-2025  "Known C2 server"
evil.example.com Intel::DOMAIN   OSINT            "Phishing domain"
deadbeef1234    Intel::FILE_HASH  Malware-DB       "Ransomware dropper"
```

```zeek
# local.zeek — load intelligence
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel/indicators.dat" };
```

When a match occurs, Zeek writes to `intel.log` and generates a `Notice`.

---

### Community ID

Community ID (https://github.com/corelight/community-id-spec) is a standardized flow hash enabling correlation across Zeek, Suricata, Arkime, and EDR tools on the same event.

```bash
# Enable in zeek (package: zeek/corelight/zeek-community-id)
zkg install corelight/zeek-community-id
```

The community_id field appears in `conn.log`, `dns.log`, `http.log` etc., and in Suricata's `eve.json`, making cross-tool pivoting seamless.

---

### Key Detection Scripts

```bash
# Install via zkg (Zeek Package Manager)
zkg install zeek/corelight/zeek-spicy-dcerpc    # DCE/RPC protocol analysis
zkg install zeek/corelight/zeek-spicy-ipsec      # IPsec/IKE
zkg install zeek/corelight/zeek-spicy-rdp        # Enhanced RDP analysis
zkg install zeek/salesforce/hassh                # SSH client/server fingerprinting
zkg install zeek/corelight/bro-long-connections  # Detect unusually long connections (beaconing)
zkg install zeek/sethhall/entity-tracking        # Track hosts and services over time
```

**Detect Beaconing (built-in approach):**
```zeek
# Simplified beaconing detector — track connection intervals per dst
global beacon_tracker: table[addr] of vector of interval &default=vector();

event connection_state_remove(c: connection)
{
    local dst = c$id$resp_h;
    if (Site::is_private_addr(c$id$orig_h) && !Site::is_private_addr(dst))
    {
        beacon_tracker[dst] += current_time() - c$start_time;
        if (|beacon_tracker[dst]| >= 10)
        {
            # Statistical jitter analysis would go here
            print fmt("Potential beaconing to %s (%d connections)", dst, |beacon_tracker[dst]|);
        }
    }
}
```

---

### MITRE ATT&CK Zeek Mappings

| ATT&CK Technique | Zeek Detection |
|-----------------|----------------|
| T1046 — Network Service Discovery | Sudden burst of conn.log entries; missing SYN-ACK (S0 state) |
| T1040 — Network Sniffing | Promiscuous mode detection in weird.log |
| T1071 — Application Layer Protocol | http.log/dns.log unusual user-agents, large DNS responses |
| T1572 — Protocol Tunneling | Long-duration DNS sessions; high bytes in dns.log; HTTP CONNECT tunnels |
| T1048 — Exfiltration Over C2 | Large resp_bytes in http.log/ssl.log to rare external IPs |
| T1557 — Adversary-in-the-Middle | arp.log conflicts; certificate anomalies in x509.log |
| T1078 — Valid Accounts | kerberos.log unusual ticket requests; authentication from unexpected src |

---

### Integration with ELK / Splunk

```bash
# Filebeat configuration for Zeek JSON logs
# /etc/filebeat/modules.d/zeek.yml
- module: zeek
  connection:
    enabled: true
    var.paths: ["/opt/zeek/logs/current/conn.log"]
  dns:
    enabled: true
  http:
    enabled: true
  ssl:
    enabled: true
  files:
    enabled: true
  notice:
    enabled: true
```


---

## 4. Security Onion

### Overview

Security Onion (https://github.com/Security-Onion-Solutions/securityonion) is a free and open-source Linux distribution for threat hunting, enterprise security monitoring, and log management. It bundles Suricata, Zeek, Wazuh, Elastic Stack, and numerous other tools into a unified platform with a cohesive web interface.

---

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|---------|
| **Standalone** | All services on a single node | Lab, small orgs (<1 Gbps) |
| **Distributed** | Manager + Search + Sensor nodes | Enterprise, multi-site |
| **Eval (Import)** | Import PCAP files for analysis | Training, incident replay |
| **Cloud** | AWS, Azure, GCP deployment | Cloud-native SOC |

#### Distributed Architecture
```
[Network TAP/SPAN]
        ↓
[Sensor Node(s)]           ← Suricata, Zeek, Steno (PCAP), Wazuh Agent
        ↓ (encrypted pipeline)
[Search Node(s)]           ← Elasticsearch storage and indexing
        ↓
[Manager Node]             ← Security Onion Console (SOC), TheHive, Kibana, Grafana
        ↓
[Analyst Workstation]      ← Browser → https://manager-ip
```

---

### Included Tools

| Tool | Function |
|------|---------|
| Suricata | IDS/IPS; signature-based alert engine |
| Zeek | Protocol analysis; rich metadata logs |
| Wazuh | HIDS; log analysis; file integrity monitoring; OSSEC-based |
| Elastic Stack | Log storage, indexing, and search (Elasticsearch + Kibana) |
| Grafana | Metrics dashboards (network throughput, alert rates) |
| TheHive | Case management and incident tracking |
| MISP | Threat intelligence platform; IOC sharing |
| Osquery | SQL-based host interrogation from the manager |
| CyberChef | In-browser data transformation (decoding, decryption, format conversion) |
| Steno (Stenographer) | High-speed full packet capture (Google's stenographer) |
| FleetDM | Osquery fleet management |
| Playbook | Sigma-based detection rule management |
| Navigator | MITRE ATT&CK Navigator integration |

---

### SOC Workflow in Security Onion Console

The Security Onion Console (SOC) is the primary analyst interface accessible at `https://<manager-ip>`.

#### Alert Triage Interface
1. **Alerts Queue:** Suricata alerts aggregated by signature and severity. Sort by count, severity, or first/last seen.
2. **Alert Detail:** Click alert → view: rule text, 5-tuple, community_id, Eve JSON fields.
3. **PCAP Pivot:** Click the PCAP icon → download full session PCAP → open in Wireshark.
4. **Transcript View:** Inline ASCII/hex session transcript for text protocols (HTTP, SMTP, FTP).
5. **Hunt Pivot:** Click src or dst IP → pivot to Hunt interface for historical investigation.
6. **Case Creation:** Escalate alert directly to TheHive case with enriched context.

#### Hunt Interface (Threat Hunting)
Hunt allows ad-hoc Elasticsearch DSL or SIGMA-style queries across all Zeek and Suricata logs.

```
# Hunt query examples (Elasticsearch DSL via SOC UI)

# Find all DNS lookups for a suspicious domain
event.module:zeek AND event.dataset:dns AND dns.question.name:*evil.com

# Find connections over non-standard ports
event.module:zeek AND event.dataset:conn AND NOT destination.port:(80 OR 443 OR 53 OR 22)

# Find large data transfers outbound
event.module:zeek AND event.dataset:conn AND destination.bytes:>10000000 AND NOT source.ip:10.0.0.0/8

# Find Cobalt Strike JA3 hash
event.module:suricata AND tls.ja3.hash:a0e9f5d64349fb13191bc781f81f42e1
```

---

### PCAP Pivot from Alerts

Security Onion uses **Stenographer** for continuous full packet capture and retrieval.

```bash
# Query Stenographer directly (from sensor node)
stenoread 'host 10.0.1.50 and port 443 and after 2h ago and before 1h ago' | tcpdump -r - -w session.pcap

# Via SOC interface: Alerts → click PCAP icon → auto-queries Stenographer for session
```

---

### Case Management with TheHive

```
Alert Triggered → Analyst Reviews → Creates Case in TheHive
                                          ↓
                                   Adds Observables (IPs, domains, hashes)
                                          ↓
                                   Assigns tasks to analysts
                                          ↓
                                   Enriches via Cortex analyzers (VirusTotal, Shodan, etc.)
                                          ↓
                                   Documents response actions
                                          ↓
                                   Closes case with disposition
```

---

### Updating Rules and Components

```bash
# Update Security Onion itself (run as soremote or via SOC admin panel)
sudo soup   # Security Onion Update

# Update Suricata rules via so-rule-update
sudo so-rule-update

# Reload Suricata rules without restart
sudo so-suricata-reload

# Zeek policy updates
sudo so-zeek-restart

# Check service status
sudo so-status
```


---

## 5. Arkime Full Packet Capture

### Overview

Arkime (formerly Moloch, https://arkime.com/) is an open-source, large-scale full packet capture and indexing system. It stores raw PCAP and provides a searchable web interface for session-level analysis, with deep integration into OpenSearch/Elasticsearch for scalable storage.

---

### Architecture

```
[Network TAP/SPAN]
        ↓
[Arkime Capture]  → Raw PCAP files → [NFS / Local Storage]
        ↓
   Session metadata, extracted fields
        ↓
[OpenSearch / Elasticsearch]  ← Searchable index
        ↓
[Arkime Viewer]  ← Web UI (https://arkime-host:8005)
        ↓
[Analyst Browser]
```

#### Components
| Component | Function |
|-----------|---------|
| `capture` | C-based packet capture daemon; writes PCAP and indexes session metadata |
| `viewer` | Node.js web UI; session search, PCAP download, SPI (Session Profile Index) view |
| `parliament` | Multi-cluster manager; overview of multiple Arkime deployments |
| `wise` | Threat intelligence lookup service; enriches sessions with external data |
| OpenSearch | Document store for session metadata and field indexes |

---

### Deployment Sizing

| Traffic Volume | PCAP Storage (90-day retention) | Elasticsearch Nodes |
|---------------|--------------------------------|---------------------|
| 100 Mbps | ~1 TB | 1 node (small) |
| 1 Gbps | ~10 TB | 2–3 nodes |
| 10 Gbps | ~100 TB | 5–10 nodes |
| 40 Gbps | ~400 TB | 20+ nodes |

**Rule of thumb:** ~100 GB/day per Gbps of average traffic. Adjust based on compression ratio and protocol mix (encrypted traffic compresses poorly).

---

### Configuration

```ini
# /etc/arkime/config.ini — key settings

[default]
elasticsearch=http://localhost:9200
rotateIndex=daily          # Create new ES index daily
# Packet capture settings
interface=eth0;eth1        # Comma-separated capture interfaces
pcapDir=/opt/arkime/raw    # PCAP storage directory; use fast local disk
maxFileSizeG=4             # Max PCAP file size before rotation (GB)
maxFileTimeM=60            # Rotate files every 60 minutes regardless of size
tcpSaveTimeout=720         # Save TCP sessions after 720 seconds idle
udpSaveTimeout=30
icmpSaveTimeout=10

# Performance
packetThreads=4            # Packet processing threads per interface
dbBulkSize=300000          # Batch size for ES writes
compressES=true            # Compress data sent to Elasticsearch

# Authentication
passwordSecret=CHANGE_THIS_RANDOM_SECRET_32CHARS
httpRealm=Arkime
```

---

### Packet Capture Performance Tuning

```bash
# Use AF_PACKET with multiple threads in config.ini
tpacketv3=true
tpacketv3BlockSize=1048576    # 1MB blocks
tpacketv3NumThreads=2         # Per-interface kernel threads

# Increase network ring buffer (system-level)
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.rmem_default=134217728
sysctl -w net.core.netdev_max_backlog=250000

# CPU affinity via numactl
numactl --cpunodebind=0 --membind=0 /opt/arkime/bin/capture -c /etc/arkime/config.ini
```

---

### Session Search and Filtering

Arkime uses a custom query language in the web UI, similar to Wireshark display filters but session-oriented.

```
# Arkime search examples
ip == 203.0.113.42                          # Sessions involving this IP
ip.src == 10.0.0.0/8 && ip.dst == !10.0.0.0/8  # Outbound from internal
port == 4444 || port == 1234               # Common malware ports
protocols == http && http.method == POST   # HTTP POST sessions
http.uri == *shell.php*                    # URI pattern match
tls.cipher contains CHACHA20               # Specific TLS cipher
dns.host == *.evil.com                     # DNS wildcard match
tags == suspicious                         # Custom tags
bytes.src > 10000000                       # Large outbound transfers (10 MB)
node == sensor01                           # Specific capture node
starttime >= 2025-06-01 00:00:00          # Time range
```

---

### PCAP Export and Replay

```bash
# Download PCAP from Arkime Viewer (API)
curl -u admin:password "https://arkime:8005/sessions.pcap?expression=ip%3D%3D203.0.113.42"      -o session.pcap

# Replay PCAP for re-analysis with Suricata
suricata -r session.pcap -c /etc/suricata/suricata.yaml -l /tmp/replay/

# Replay with tcpreplay for testing
tcpreplay --intf1=eth0 --mbps=100 session.pcap
```

---

### Arkime API for SIEM Integration

```bash
# REST API — query sessions as JSON
curl -u admin:password   "https://arkime:8005/api/sessions?expression=protocols%3D%3Dhttp&fields=ip.src,ip.dst,port,bytes&length=100"   | jq '.data[] | {src: .["ip.src"], dst: .["ip.dst"], bytes: .bytes}'

# SPI (Session Profile Index) data view — enriched field extraction
curl -u admin:password   "https://arkime:8005/api/spi?spi=ip.dst:10,dns.host:10&expression=starttime%3E1h+ago"
```

---

### Integration with Zeek for Enrichment

WISE (With Intelligence See Everything) can query Zeek-derived data:

```ini
# wise.ini
[file:md5]
file=/opt/arkime/etc/md5.txt

[file:domain]
file=/opt/arkime/etc/domains.txt

# Custom WISE source pointing to Threat Intel API
[wiseService]
port=8081
[source:threatintel]
type=url
url=https://threatintel.internal/arkime
```

---

### Retention Policies

```bash
# Arkime manages PCAP retention automatically via freeSpaceG setting
# config.ini:
freeSpaceG=10%    # Keep at least 10% free space; delete oldest PCAP files

# ES index retention — use ILM (Index Lifecycle Management) in OpenSearch
# Or use arkime's built-in db.pl purge
/opt/arkime/db/db.pl http://localhost:9200 prune --maxIndices 90
```


---

## 6. DNS Security and Monitoring

### DNS as a Visibility Goldmine

Nearly every network connection — malware C2, data exfiltration, phishing, lateral movement — begins with a DNS query. DNS monitoring provides:
- **Pre-connection visibility:** See what hosts are trying to reach before TCP sessions are established.
- **Threat intel matching:** Block known-bad domains at resolution time.
- **Beaconing detection:** Periodic DNS queries to the same domain with slight variation.
- **Tunneling detection:** Data hidden in DNS query/response fields.
- **Asset tracking:** Map internal IP addresses to hostnames over time.

---

### Pi-hole Deployment

Pi-hole (https://github.com/pi-hole/pi-hole) is a network-wide DNS sinkhole and logger.

```bash
# Install Pi-hole
curl -sSL https://install.pi-hole.net | bash

# Key configuration paths
/etc/pihole/adlists.list    # Blocklist sources
/etc/pihole/whitelist.txt   # Always-allow domains
/etc/pihole/blacklist.txt   # Always-block domains
/var/log/pihole.log         # Query log

# Pi-hole admin UI: http://pi.hole/admin

# Add threat intel blocklist
pihole -a adlist add https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Update lists
pihole -g

# Query log analysis
pihole -t   # Live tail
pihole -q evil.com   # Query specific domain status
```

#### Pi-hole as SOC Sensor
- Forward Pi-hole logs to SIEM: configure rsyslog to forward `/var/log/pihole.log`.
- Use Pi-hole's FTL (Faster Than Light) API for real-time data: `GET http://pi.hole/api/queries?domain=evil.com`.

---

### AdGuard Home

AdGuard Home (https://github.com/AdguardTeam/AdGuardHome) is a more feature-rich alternative to Pi-hole, adding DoH/DoT upstream support, per-client rules, and parental controls.

```bash
# Install AdGuard Home
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v

# Configure upstream DNS with DoH
# AdGuardHome.yaml:
upstream_dns:
  - https://1.1.1.1/dns-query
  - https://8.8.8.8/dns-query
bootstrap_dns:
  - 1.1.1.1:53
  - 8.8.8.8:53

# Enable DNSSEC validation
enable_dnssec: true

# Rewrite rules for internal split-horizon
rewrites:
  - domain: "*.internal.corp"
    answer: 10.0.0.5
```

---

### RPZ (Response Policy Zones)

RPZ is a DNS firewall standard (RFC 8198 / ISC BIND extension) allowing DNS resolvers to rewrite or block responses based on threat intel feeds.

```bash
# BIND9 RPZ configuration (/etc/bind/named.conf.local)
zone "rpz.threatintel" {
    type master;
    file "/etc/bind/db.rpz.threatintel";
    allow-query { none; };
};

options {
    response-policy {
        zone "rpz.threatintel" policy NXDOMAIN;
    } break-dnssec yes;
};

# /etc/bind/db.rpz.threatintel
$TTL 300
@   SOA  rpz.threatintel. admin.corp. ( 2025061501 3600 900 86400 300 )
    NS   localhost.

; Block known C2 domains
malware-c2.example.com.rpz.threatintel. IN CNAME .
*.malware-c2.example.com.rpz.threatintel. IN CNAME .
```

---

### DNS over HTTPS / TLS Security Implications

| Protocol | Port | Implication |
|----------|------|-------------|
| Plain DNS | UDP/TCP 53 | Visible to all monitoring tools; no encryption |
| DNS over TLS (DoT) | TCP 853 | Encrypted but distinguishable by port; monitorable at firewall |
| DNS over HTTPS (DoH) | TCP 443 | Blends with HTTPS traffic; bypasses traditional DNS monitoring |
| DNS over QUIC (DoQ) | UDP 853 | Emerging; even harder to detect |

#### Monitoring DoH
```bash
# Block known DoH providers at firewall (force internal DNS use)
# Block Cloudflare DoH
iptables -I FORWARD -d 1.1.1.1 -p tcp --dport 443 -j DROP
iptables -I FORWARD -d 1.0.0.1 -p tcp --dport 443 -j DROP

# Block Google DoH
iptables -I FORWARD -d 8.8.8.8 -p tcp --dport 443 -j DROP
iptables -I FORWARD -d 8.8.4.4 -p tcp --dport 443 -j DROP

# Suricata rule to detect DoH (HTTP/2 to known DoH endpoints)
alert tls any any -> $DNS_OVER_HTTPS_SERVERS 443 (
    msg:"Potential DNS over HTTPS Usage";
    tls.sni; content:"cloudflare-dns.com";
    classtype:policy-violation; sid:9100001; rev:1;
)
```

---

### DNSSEC Validation

```bash
# Verify DNSSEC validation is working
dig +dnssec dnssec-failed.org  # Should return SERVFAIL if validation is on
dig +dnssec google.com | grep -E "ad|RRSIG"  # AD bit = validated

# Test your resolver
dig @your-resolver.ip dnssec-failed.org  # Should fail
dig @your-resolver.ip dnssec.works       # Should succeed
```

---

### Detecting DNS Tunneling

DNS tunneling encodes data in DNS query/response fields (subdomains, TXT records) to exfiltrate data or establish C2 channels over DNS.

**Indicators:**
- High-entropy subdomain labels (random-looking strings: `a1b2c3d4e5f6.evil.com`)
- Unusually long subdomain names (>50 characters)
- High query rate to a single domain
- Large TXT record responses (>512 bytes)
- NXDOMAIN rate anomaly (many failed lookups)
- Non-standard query types (TXT, NULL, CNAME for data delivery)

```bash
# Zeek dns.log analysis for tunneling indicators (using zeek-cut)
zeek-cut ts query qtype_name answers < dns.log |   awk '$3 == "TXT" && length($2) > 50 {print $0}' |   sort | uniq -c | sort -rn | head -20

# Calculate subdomain entropy with Python
python3 -c "
import math, re
from collections import Counter

def entropy(s):
    if not s: return 0
    c = Counter(s)
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in c.values())

domains = ['a1b2c3d4e5f6g7h8.evil.com', 'www.google.com', 'legitimate.corp.com']
for d in domains:
    sub = d.split('.')[0]
    print(f'{d}: entropy={entropy(sub):.2f}')
"
# High entropy (>3.5 bits/char) suggests encoding/tunneling
```

**dnstwist for Typosquatting Detection:**
```bash
pip install dnstwist
dnstwist --registered corp.com          # Find registered lookalike domains
dnstwist --format json corp.com > typosquats.json
```

---

### DNS Log Analysis Queries

```sql
-- Elasticsearch/OpenSearch (via Kibana/SOC Hunt)

-- Top queried external domains (Pi-hole or Zeek dns.log)
GET zeek-*/_search
{
  "aggs": {"top_domains": {"terms": {"field": "dns.question.name", "size": 20}}},
  "query": {"bool": {"must_not": [{"term": {"dns.resolved_ip": "0.0.0.0"}}]}}
}

-- NXDOMAIN rate by source (potential DGA or reconnaissance)
GET zeek-*/_search
{
  "query": {"term": {"dns.response_code": "NXDOMAIN"}},
  "aggs": {"by_src": {"terms": {"field": "source.ip", "size": 10}}}
}

-- Large DNS responses (potential tunneling)
GET zeek-*/_search
{
  "query": {"range": {"dns.answers.data": {"gte": 200}}},
  "sort": [{"@timestamp": "desc"}]
}
```


---

## 7. nDPI Deep Packet Inspection

### Overview

nDPI (https://github.com/ntop/nDPI) is an open-source deep packet inspection library developed by ntop. It identifies 250+ protocols and applications within network traffic, enabling application-aware security policies and behavioral analytics.

---

### Protocol Detection Capabilities

nDPI classifies traffic into:
- **Layer 7 protocols:** HTTP, HTTPS, DNS, FTP, SMTP, SSH, RDP, VoIP (SIP/RTP), SMB, NFS
- **Applications:** Netflix, YouTube, Spotify, BitTorrent, Zoom, Teams, Skype, WhatsApp
- **Tunneling:** Tor, VPN (OpenVPN, WireGuard, IPsec), DNS tunneling, HTTP tunneling
- **P2P:** BitTorrent, eDonkey, Gnutella, DC++
- **Malware-associated:** Cobalt Strike, Metasploit, custom protocols detected by heuristics
- **Industrial:** Modbus, DNP3, IEC 60870-5-104, EtherNet/IP, BACnet

```c
// Basic nDPI usage in C
#include <ndpi_api.h>

struct ndpi_detection_module_struct *ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);
ndpi_finalize_initialization(ndpi_struct);

// Process packet
ndpi_protocol detected_protocol = ndpi_detection_process_packet(
    ndpi_struct, flow, packet_data, packet_len, timestamp, NULL
);

printf("Protocol: %s / %s
",
    ndpi_get_proto_name(ndpi_struct, detected_protocol.master_protocol),
    ndpi_get_proto_name(ndpi_struct, detected_protocol.app_protocol));
```

---

### JA3 / JA3S TLS Fingerprinting

JA3 creates an MD5 fingerprint of TLS Client Hello parameters; JA3S fingerprints the Server Hello. These fingerprints identify TLS clients and servers regardless of the destination IP/domain.

**JA3 is computed from:**
`SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

```
JA3 string:  771,49195-49199-49196-49200-52393-52392,0-23-65281-10-11-16-5-13,23-24,0
JA3 hash:    a0e9f5d64349fb13191bc781f81f42e1  ← Cobalt Strike default
```

**Notable JA3 Hashes (Malware):**
| Hash | Malware / Tool |
|------|----------------|
| `a0e9f5d64349fb13191bc781f81f42e1` | Cobalt Strike default beacon |
| `6734f37431670b3ab4292b8f60f29984` | Cobalt Strike (variant) |
| `51c64c77e60f3980eea90869b68c58a8` | Metasploit Meterpreter |
| `c35b0c1dbc64e55f8e1cfd4bb3c2f03b` | AsyncRAT |
| `b386946a5a44d1ddcc843bc75336dfce` | njRAT |

**JA3 Databases:** https://sslbl.abuse.ch/ja3-fingerprints/ | https://github.com/salesforce/ja3

```bash
# Zeek JA3 (requires zeek-ja3 package)
zkg install zeek/salesforce/ja3

# Suricata JA3 detection rule
alert tls any any -> any any (
    msg:"Known Cobalt Strike JA3 Fingerprint";
    ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1";
    classtype:trojan-activity; sid:9200001; rev:1;
)
```

**JARM** is an active TLS fingerprinting tool that probes a server with specific TLS Client Hellos and fingerprints the server's response pattern. Useful for identifying C2 server infrastructure.

```bash
# JARM fingerprinting
pip install jarm
python jarm.py malicious-server.example.com

# JARM hash identifies server TLS stack/configuration
# Known malware JARM hashes listed at https://github.com/salesforce/jarm
```

---

### ntopng Traffic Visualization

ntopng (https://github.com/ntop/ntopng) is a web-based network traffic monitoring application built on nDPI.

```bash
# Install ntopng (Ubuntu/Debian)
apt-get install ntopng

# /etc/ntopng/ntopng.conf
-i=eth0
-w=3000          # Web interface port
-F=es;           # Export to Elasticsearch
--elastic-url=http://localhost:9200
--community      # Community edition

# Access: http://localhost:3000 (default admin/admin)
```

**ntopng capabilities:**
- Real-time top talkers, top protocols, top applications
- Historical flow data with nProbe integration
- Host scoring and anomaly detection
- Malware detection via nDPI risk categories
- SNMP-based interface monitoring

---

### nProbe for NetFlow Export

nProbe bridges raw packet capture (via nDPI) with NetFlow/IPFIX consumers.

```bash
# nProbe exporting to ntopng
nprobe --interface eth0        --zmq "tcp://*:5556"        --ndpi-protocols        --export-to-ntopng

# nProbe exporting IPFIX to SIEM
nprobe --interface eth0        --collector-port 2055        --ndpi-protocols        -n 192.168.1.100:4739    # SIEM IPFIX collector
```

---

### nDPI in Suricata (Protocol-Aware Rules)

Suricata uses its own application layer detection engine (not nDPI directly), but nDPI can be integrated via the community's `suricata-ndpi` patch or by using Suricata's built-in app-layer protocols with rules targeting detected application types.

```
# Suricata built-in app-layer protocol targeting
alert http any any -> any any (msg:"HTTP traffic"; app-layer-protocol:http; ...)
alert tls any any -> any any (msg:"TLS traffic"; app-layer-protocol:tls; ...)
alert ssh any any -> any any (msg:"SSH traffic"; app-layer-protocol:ssh; ...)

# Detect BitTorrent (app-layer detection)
alert tcp any any -> any any (
    msg:"BitTorrent Protocol Detected";
    app-layer-protocol:bittorrent;
    classtype:policy-violation; sid:9300001; rev:1;
)
```

---

### Detecting Tor and VPN Usage

```bash
# Zeek: detect Tor by known relay IPs (update via Tor consensus)
wget https://check.torproject.org/exit-addresses -O /tmp/tor-exits.txt
# Convert to Zeek intel format and load via Intel Framework

# Suricata: ET rules for Tor detection
suricata-update enable-source et/open
# Rules in et/open include: emerging-tor.rules

# nDPI flags: NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_OPENVPN, NDPI_PROTOCOL_WIREGUARD

# ntopng alert on detected Tor usage
# Flows flagged with protocol category "VPN" or "TOR" generate alerts
```

---

### Flow-Based Anomaly Detection

```python
# Python script to detect port scan using NetFlow/IPFIX data from Elasticsearch
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

es = Elasticsearch(['http://localhost:9200'])

def detect_port_scans(window_minutes=5, threshold=100):
    """Find source IPs connecting to many unique destination ports."""
    query = {
        "query": {
            "range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}
        },
        "aggs": {
            "by_src": {
                "terms": {"field": "source.ip", "size": 1000},
                "aggs": {
                    "unique_dst_ports": {
                        "cardinality": {"field": "destination.port"}
                    }
                }
            }
        },
        "size": 0
    }
    result = es.search(index="netflow-*", body=query)
    for bucket in result['aggregations']['by_src']['buckets']:
        if bucket['unique_dst_ports']['value'] >= threshold:
            print(f"Port scan detected: {bucket['key']} → {bucket['unique_dst_ports']['value']} unique ports")

detect_port_scans()
```


---

## 8. Network Access Control

### Overview

Network Access Control (NAC) enforces security policy for devices connecting to the network — ensuring only authorized, compliant devices gain access, and placing non-compliant or unknown devices in restricted VLANs.

---

### 802.1X EAP Authentication

IEEE 802.1X is the port-based network access control standard. It uses the Extensible Authentication Protocol (EAP) transported over LAN (EAPOL) to authenticate devices before granting network access.

```
[Supplicant]  ←EAPOL→  [Authenticator (Switch/AP)]  ←RADIUS→  [Authentication Server (RADIUS)]
  (Endpoint)                  (Network Device)                         (FreeRADIUS / ISE)
```

**EAP Methods:**
| Method | Auth Type | Security | Use Case |
|--------|-----------|---------|---------|
| EAP-TLS | Client certificate | Highest | Corp devices with PKI |
| PEAP-MSCHAPv2 | Username/password inside TLS tunnel | High | AD-joined devices |
| EAP-TTLS | Various inner methods inside TLS | High | Mixed environments |
| EAP-MD5 | Password (challenge-response) | Low | Legacy; avoid |
| MAB | MAC address as credential | None | IoT, printers, HVAC |

---

### FreeRADIUS Configuration

```bash
# Install FreeRADIUS
apt-get install freeradius freeradius-ldap freeradius-utils

# Key configuration files
/etc/freeradius/3.0/clients.conf       # NAS (switch) shared secrets
/etc/freeradius/3.0/users              # Local user database (for testing)
/etc/freeradius/3.0/mods-enabled/ldap # AD/LDAP integration
/etc/freeradius/3.0/sites-enabled/default
```

```
# clients.conf — register switches as RADIUS clients
client core-switch-01 {
    ipaddr = 10.0.1.1
    secret = CHANGE_THIS_SHARED_SECRET
    nastype = cisco
    shortname = core-sw-01
}

# mods-available/ldap — Active Directory integration
ldap {
    server = 'ad.corp.com'
    port = 636
    tls { ... }
    base_dn = 'dc=corp,dc=com'
    user {
        base_dn = "${..base_dn}"
        filter = "(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})"
    }
    group {
        base_dn = "${..base_dn}"
        filter = "(objectClass=Group)"
        membership_attribute = 'memberOf'
    }
}
```

---

### Dynamic VLAN Assignment

After successful authentication, the RADIUS server returns VLAN assignment attributes, placing the device in the appropriate segment based on identity.

```
# FreeRADIUS post-auth configuration (sites-available/default)
post-auth {
    if (&LDAP-Group == 'Domain Computers') {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-Id = 100   # Corporate VLAN
        }
    }
    elsif (&LDAP-Group == 'IoT-Devices') {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-Id = 200   # IoT VLAN (restricted)
        }
    }
    else {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-Id = 999   # Quarantine VLAN
        }
    }
}
```

**Cisco switch 802.1X port configuration:**
```
interface GigabitEthernet0/1
 description User Port - 802.1X Enabled
 switchport mode access
 switchport access vlan 999          ! Default to quarantine
 authentication port-control auto
 authentication host-mode multi-auth
 authentication order dot1x mab     ! Try 802.1X first, then MAB
 authentication priority dot1x mab
 dot1x pae authenticator
 spanning-tree portfast
 ip access-group ACL-PRE-AUTH in    ! Restrict pre-auth traffic
```

---

### MAC Authentication Bypass (MAB)

MAB uses the device MAC address as both username and password with RADIUS. Used for devices that cannot support 802.1X (IoT, printers, IP phones).

```
# FreeRADIUS users file for MAB
# Format: MAC_ADDRESS (lowercase, no separators) Cleartext-Password := "MAC_ADDRESS"
aabbccddeeff Cleartext-Password := "aabbccddeeff"
    Reply-Message = "IoT Device Authenticated",
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = 200

# Security note: MAB provides zero authentication security — any device
# can spoof a known MAC. Use it only for devices truly incapable of 802.1X,
# and apply strict ACLs to MAB-authenticated VLAN.
```

---

### Rogue Device Detection

```python
# Python script to detect MAC addresses not in RADIUS accounting / DHCP leases
import subprocess, json

def get_arp_table():
    """Get current ARP table from router via SNMP."""
    # Simplified — use pysnmp or netmiko for real implementation
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    return result.stdout

def get_authorized_macs():
    """Load MAC addresses from NAC database / DHCP server."""
    with open('/etc/nac/authorized_macs.json') as f:
        return set(json.load(f)['macs'])

def detect_rogue_devices():
    arp = get_arp_table()
    authorized = get_authorized_macs()
    for line in arp.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mac = parts[3].replace(':', '').lower()
            if mac not in authorized:
                print(f"ROGUE DEVICE DETECTED: {line}")
```

---

### Open-Source NAC: PacketFence

PacketFence (https://www.packetfence.org/) is a fully supported open-source NAC solution with:
- 802.1X, MAB, captive portal authentication
- VLAN assignment, inline enforcement
- Device profiling and fingerprinting
- Vulnerability scan integration (OpenVAS, Nessus)
- Compliance checking
- Security event-triggered remediation (quarantine)

```bash
# PacketFence deployment (RHEL/CentOS)
yum localinstall https://packetfence.org/downloads/PacketFence/RHEL8/packetfence-release-11.0.0-1.rpm
yum install packetfence
systemctl enable --now packetfence-config
# Access: https://management-ip:1443
```

---

### Post-Admission Control (Continuous Compliance)

Initial authentication is not enough — devices must remain compliant throughout their session.

**Continuous compliance checks via:**
- **Osquery:** SQL queries to verify endpoint health (patch level, AV status, disk encryption)
- **SNMP Traps:** Switch notifies NAC of new MAC on authenticated port
- **Periodic RADIUS re-authentication:** Force re-auth every N minutes; apply updated policy
- **EDR Integration:** XDR platforms can trigger CoA (Change of Authorization) RADIUS packets to quarantine compromised endpoints

```bash
# RADIUS CoA (Change of Authorization) — quarantine a live session
echo "User-Name=baddevice@corp.com,Cisco-AVPair=subscriber:command=reauthenticate" |   radclient -x 10.0.1.1:3799 coa SHARED_SECRET
```


---

## 9. DDoS Protection and Traffic Scrubbing

### DDoS Attack Taxonomy

#### Volumetric Attacks (Layer 3/4)
Overwhelm bandwidth capacity. Measured in Gbps or Mpps.
- **UDP Flood:** Random UDP packets to random ports; exhausts bandwidth.
- **ICMP Flood (Ping Flood):** Overloads with ICMP Echo requests.
- **Amplification Attacks:** Spoof victim IP as source; receive amplified response.
  - DNS amplification: 28-byte query → 3,000-byte response (107x amplification)
  - NTP amplification (monlist): 234-byte query → 48KB response (556x)
  - SSDP amplification: 30-byte query → 3,000-byte response (100x)
  - Memcached amplification: 15-byte query → 750KB response (50,000x)

#### Protocol Attacks (Layer 3/4)
Exhaust state tables on firewalls, load balancers, or servers.
- **SYN Flood:** Sends thousands of SYN packets without completing handshake; exhausts server connection table.
- **TCP State Exhaustion:** Established connections sent garbage data; keeps state alive.
- **Fragmentation Attack:** Malformed fragments exhaust reassembly buffers.
- **Ping of Death:** Oversized ICMP packets (historical; patched).

#### Application-Layer Attacks (Layer 7)
Mimic legitimate requests; bypass volumetric detection.
- **HTTP Flood (GET/POST):** Floods web server with valid HTTP requests.
- **Slowloris:** Opens many connections and sends headers slowly; exhausts connection pool without bandwidth.
- **Slow POST (RUDY):** Sends POST requests at 1 byte/second; keeps threads occupied.
- **ReDoS:** Crafted regex input causes catastrophic backtracking in vulnerable apps.
- **SSL/TLS Exhaustion:** Forces expensive handshakes; exhausts CPU.
- **DNS Query Flood:** Overwhelms authoritative DNS server with random subdomains (NXDOMAIN flood).

---

### BGP Blackhole Routing (RTBH)

Remote Triggered Black Hole (RTBH) routing allows ISP to drop traffic destined for victim IP at the provider edge — before it enters the customer network.

```
# RTBH — advertise victim IP with special community to upstream ISP
# Victim prefix: 203.0.113.100/32

# Junos configuration
policy-statement RTBH-EXPORT {
    term match-rtbh {
        from community RTBH;
        then accept;
    }
}
community RTBH members 65535:666;  # Standard RTBH community

# Inject /32 into BGP with RTBH community (triggers null-routing at provider)
routing-options {
    static {
        route 203.0.113.100/32 {
            discard;
            community [65535:666];
        }
    }
}

# Destination-based RTBH: drops ALL traffic to victim (stops attack + legitimate)
# Source-based RTBH: drops traffic from specific source ASes (requires ISP support)
```

---

### Upstream Scrubbing Centers

For volumetric DDoS, the only effective mitigation is scrubbing at or near the source:

**Commercial Cloud Scrubbing:**
| Provider | Capacity | Method |
|----------|---------|--------|
| Cloudflare Magic Transit | 100+ Tbps | Anycast BGP; automatic mitigation |
| Akamai Prolexic | 20+ Tbps | BGP re-route to scrubbing PoPs |
| AWS Shield Advanced | Regional | Integration with AWS services |
| Fastly DDoS Protection | Multiple Tbps | Anycast CDN |
| Radware DefensePro | On-prem + cloud | Hybrid scrubbing |

**BGP Re-routing to Scrubbing:**
```
Under attack:
[Attacker]  →  [Internet]  →  [Customer Edge Router]  →  [Server - overwhelmed]

With scrubbing:
[Attacker]  →  [Internet]  →  [Scrubbing Center]  →  [GRE Tunnel]  →  [Server - clean traffic only]

BGP advertisement changes:
Normal: Customer announces 203.0.113.0/24 from AS64496
DDoS:   Customer withdraws; Scrubbing provider announces 203.0.113.0/24 with shorter AS path
        Clean traffic tunneled back via GRE/MPLS
```

---

### SYN Cookies

SYN cookies prevent SYN flood attacks from exhausting the server's connection state table.

```bash
# Enable SYN cookies (Linux)
sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

# Additional SYN flood mitigations
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.ipv4.tcp_synack_retries=2   # Reduce retries for half-open connections
sysctl -w net.ipv4.tcp_syn_retries=2

# iptables rate limiting for SYN packets
iptables -A INPUT -p tcp --syn -m limit --limit 1000/s --limit-burst 3000 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
```

---

### Rate Limiting at Network Edge

```bash
# Cisco IOS — rate limiting ICMP (anti-ICMP flood)
ip access-list extended RATE-LIMIT-ICMP
 permit icmp any any
!
class-map match-all ICMP-TRAFFIC
 match access-group name RATE-LIMIT-ICMP
!
policy-map ANTI-DDOS
 class ICMP-TRAFFIC
  police rate 1000 pps burst 2000 pps
   conform-action transmit
   exceed-action drop
!
interface GigabitEthernet0/0
 service-policy input ANTI-DDOS

# Linux tc (traffic control) — ingress rate limiting
tc qdisc add dev eth0 ingress
tc filter add dev eth0 parent ffff: protocol ip prio 1    u32 match ip protocol 17 0xff    police rate 100mbit burst 1mb drop flowid :1
```

---

### Application-Layer DDoS Defense

```nginx
# Nginx — rate limiting (Slowloris / HTTP flood)
http {
    limit_req_zone $binary_remote_addr zone=per_ip:10m rate=100r/m;
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    server {
        limit_req zone=per_ip burst=50 nodelay;
        limit_conn conn_limit 20;           # Max 20 concurrent connections per IP
        client_body_timeout 10s;            # Kill slow POST attacks
        client_header_timeout 10s;
        keepalive_timeout 5s 5s;
        send_timeout 10s;

        # Block known bad user agents
        if ($http_user_agent ~* (nikto|sqlmap|nmap|masscan|zgrab)) {
            return 444;
        }
    }
}
```

```
# HAProxy — connection rate limiting
frontend web-in
    bind :80
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc_conn_rate(0) gt 100 }
    tcp-request connection reject if { sc_sess_rate(0) gt 50 }
    default_backend web-servers

backend web-servers
    stick-table type ip size 100k expire 30s store conn_rate(10s),sess_rate(10s)
```

---

### BCP38 Anti-Spoofing

BCP38 (RFC 2827) requires ISPs to filter outgoing traffic with source addresses not belonging to their allocated ranges, preventing IP spoofing used in amplification attacks.

```bash
# Linux — ingress filtering (drop packets with private src IPs arriving from Internet)
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 169.254.0.0/16 -j DROP  # Link-local
iptables -A INPUT -i eth0 -s 0.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 240.0.0.0/4 -j DROP     # Reserved

# Verify with spoofer.net test or CAIDA Spoofer project
```

---

### WAF Rate Limiting Integration

```yaml
# ModSecurity (WAF) rate limiting rules
# Detect HTTP flood: >100 requests per IP per 10 seconds
SecRule IP:REQUEST_COUNTER "@gt 100"     "id:900001,      phase:1,      t:none,      deny,      status:429,      msg:'HTTP Flood Detected - Too Many Requests',      setvar:IP.block=1,      expirevar:IP.block=300"

# Increment per-IP counter
SecAction     "id:900002,      phase:1,      t:none,      setvar:IP.REQUEST_COUNTER=+1,      expirevar:IP.REQUEST_COUNTER=10,      nolog,      pass"
```


---

## 10. Network Defense Operations

### Network Security Monitoring Workflow

```
[Detection]        [Triage]           [Investigation]     [Response]
    │                  │                    │                  │
Alert fires  →  Classify:           Collect evidence:   Contain:
(Suricata/       True Positive?      - Full PCAP         - Block IP/domain
 Zeek/NDR)       False Positive?     - Flow data         - Quarantine host
    │            Benign?             - DNS logs          - Null-route prefix
    │                │               - Endpoint logs         │
    │           Assign               - Timeline          Eradicate:
    │           Priority:            reconstruction      - Remove malware
    │            P1/P2/P3                │               - Patch vuln
    │                │            Determine:                 │
    │           Create TheHive      - Initial access     Recover:
    │           Case                - Persistence        - Restore service
    │                               - Lateral movement   - Monitor for
    │                               - Exfiltration         recurrence
    │                                    │
    │                              ATT&CK mapping
    │                              + IOC extraction
    │                              + Threat intel sharing
```

---

### Threat Hunting in Network Data

#### Beaconing Detection

C2 malware typically communicates on a periodic schedule (beacon interval). Detection uses statistical analysis of connection frequency.

```python
#!/usr/bin/env python3
"""Beacon detector using Zeek conn.log data."""
import json, math
from collections import defaultdict
from datetime import datetime

def load_zeek_conn(filepath):
    """Load Zeek conn.log (JSON format)."""
    connections = defaultdict(list)
    with open(filepath) as f:
        for line in f:
            if line.startswith('#'): continue
            try:
                record = json.loads(line)
                key = (record.get('id.orig_h'), record.get('id.resp_h'), record.get('id.resp_p'))
                connections[key].append(record.get('ts', 0))
            except json.JSONDecodeError:
                pass
    return connections

def detect_beacons(connections, min_count=10, max_jitter_pct=15):
    """
    Identify beaconing: connections with regular intervals and low jitter.
    Jitter % = (stddev / mean) * 100
    """
    candidates = []
    for (src, dst, port), timestamps in connections.items():
        if len(timestamps) < min_count:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals: continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 5: continue  # Ignore sub-5-second intervals (likely streaming)

        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        stddev = math.sqrt(variance)
        jitter_pct = (stddev / mean_interval) * 100 if mean_interval > 0 else 999

        if jitter_pct <= max_jitter_pct:
            candidates.append({
                'src': src, 'dst': dst, 'port': port,
                'count': len(timestamps),
                'mean_interval_sec': round(mean_interval, 1),
                'jitter_pct': round(jitter_pct, 1)
            })

    return sorted(candidates, key=lambda x: x['jitter_pct'])

# Usage
conns = load_zeek_conn('/opt/zeek/logs/current/conn.log')
beacons = detect_beacons(conns)
for b in beacons[:20]:
    print(f"{b['src']} → {b['dst']}:{b['port']} | "
          f"count={b['count']} interval={b['mean_interval_sec']}s jitter={b['jitter_pct']}%")
```

#### C2 Protocol Identification Hunts

```bash
# Hunt 1: Long-duration low-byte connections (C2 keep-alive)
# Zeek conn.log: sessions > 1 hour with < 10KB transferred
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log |   awk '$6 > 3600 && $7 < 10000 && $8 < 10000 {print $0}' | sort -k6 -rn | head -20

# Hunt 2: Rare external destinations (long tail analysis)
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -n | head -20
# Low-count destinations that are external IPs may be C2

# Hunt 3: Encrypted traffic to non-standard ports
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log |   awk '$3 != 443 && $3 != 8443 && $4 == "ssl" {print $0}' | sort | uniq -c | sort -rn | head -20

# Hunt 4: DNS tunneling indicators
zeek-cut ts id.orig_h query qtype_name < dns.log |   awk 'length($3) > 50 {print $0}' | head -30
```

---

### Network Forensics

#### PCAP Preservation and Chain of Custody

```bash
# Capture evidence-grade PCAP with timestamps and checksums
tcpdump -i eth0 -w evidence-$(date +%Y%m%d-%H%M%S).pcap         -G 3600 -W 24 \        # Rotate hourly, keep 24 files
        host 203.0.113.42

# Calculate SHA256 hash immediately after capture (chain of custody)
sha256sum evidence-20250615-143022.pcap | tee evidence-20250615-143022.pcap.sha256

# Verify integrity later
sha256sum -c evidence-20250615-143022.pcap.sha256

# Store: original PCAP + hash file + analyst notes in incident folder
# Document: who captured, when, from which interface, collection method

# PCAP analysis with Wireshark CLI (tshark)
tshark -r evidence.pcap -T json > evidence-analysis.json
tshark -r evidence.pcap -q -z conv,tcp      # TCP conversation summary
tshark -r evidence.pcap -q -z io,phs        # Protocol hierarchy
tshark -r evidence.pcap -Y "http.request" -T fields        -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri
```

---

### Network Segmentation Audit Methodology

A quarterly network segmentation audit verifies that firewall rules and VLAN boundaries are enforced as designed.

**Audit Steps:**
1. **Document intended architecture:** Obtain network diagrams, VLAN assignments, firewall rule tables.
2. **Map actual traffic flows:** Use Zeek conn.log to identify all unique src→dst VLAN pairs.
3. **Test firewall rules:**
   ```bash
   # Use nmap from test host in VLAN A to verify VLAN B is inaccessible
   nmap -p 1-65535 --open -Pn 10.20.0.0/24   # Should be blocked
   # Document results in segmentation test matrix
   ```
4. **Compare flows to policy:** Flag any cross-segment traffic not in the approved rule base.
5. **Remediate gaps:** Tighten overly permissive rules; investigate unauthorized flows.
6. **Document residual risk:** Approved exceptions documented with business justification and owner.

---

### Firewall Rule Review Process

Stale firewall rules accumulate over time, creating unnecessary attack surface.

**Quarterly Firewall Hygiene:**
```
For each rule in ruleset:
  1. Check last hit timestamp (most NGFWs track this)
  2. Rules with 0 hits in 90 days → mark for decommission review
  3. Rules with ANY source/destination/port → document business justification
  4. Rules without expiry dates → add review date
  5. Shadow rules (never reached due to earlier match) → identify and remove
  6. Overly broad rules → narrow scope to minimum required

Palo Alto (PAN-OS) — identify unused rules:
Device > Policy > Hit Count > Sort by Hit Count (ascending)
Filter: Last Hit = Never

Fortinet — rule analysis:
diagnose firewall policy match count all
```

---

### Unauthorized Device Detection

```bash
# Detect new MAC addresses on network (compare to DHCP lease database)

# Method 1: Zeek weird.log for ARP anomalies
zeek-cut ts id.orig_h name < weird.log | grep arp | head -20

# Method 2: Compare current ARP table to known-good baseline
arp -a | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | sort > /tmp/current-macs.txt
diff /etc/security/known-macs.txt /tmp/current-macs.txt

# Method 3: Passive asset discovery via Zeek
# Zeek software.log tracks observed software (OS fingerprints, user agents, server banners)
zeek-cut ts host software_type name version < software.log |   grep -v known | sort -u | head -30

# Method 4: Continuous monitoring via Security Onion Hunt
# Hunt query: devices seen for first time today
event.module:zeek AND event.dataset:conn AND NOT source.ip:known_assets
```

---

### ATT&CK Network-Relevant Technique Detection Table

| ATT&CK ID | Technique | Zeek Detection | Suricata Detection | Arkime |
|-----------|-----------|---------------|-------------------|--------|
| T1046 | Network Service Scanning | conn.log: many S0/RSTO states from single src in short window | ET SCAN rules; threshold on connection attempts | Session count spike per src IP |
| T1040 | Network Sniffing | weird.log: promiscuous mode; unusual ARP behavior | — | Monitor for pcap software on network |
| T1557 | Adversary-in-the-Middle | arp.log: IP→MAC mapping conflicts; ssl.log: cert issuer anomaly | JA3 mismatch; cert validation failures | x509 certificate changes per IP |
| T1090 | Proxy (Connection Proxy) | conn.log: CONNECT method in http.log; SOCKS detection | ET Proxy rules; CONNECT tunnel detection | High-volume relay sessions |
| T1095 | Non-Application Layer Protocol | conn.log: raw IP protocols (non-TCP/UDP/ICMP) | Protocol mismatch signatures; tunnel detection | Custom protocol sessions |
| T1071.001 | Web Protocols C2 | http.log: low-volume periodic POSTs; beacon intervals | ET CnC rules; JA3 hash matching | Beaconing session patterns |
| T1071.004 | DNS C2 | dns.log: high-entropy subdomains; large TXT records; consistent CNAME chain | DNS anomaly rules; long label detection | DNS query volume spikes |
| T1572 | Protocol Tunneling | dns.log: large response bytes; http.log: CONNECT tunnels; long sessions | Tunnel detection signatures | Extended session duration; byte asymmetry |
| T1571 | Non-Standard Port | ssl.log: TLS on non-443 ports; http.log on non-80/8080 | App-layer on non-standard port rules | Port-protocol mismatch sessions |
| T1048 | Exfiltration Over C2 | conn.log: high orig_bytes to rare external IPs | Large upload signatures; data loss rules | Outbound byte volume anomalies |
| T1041 | Exfiltration Over C2 Channel | ssl.log: large upload bytes; files.log: outbound binaries | Exfil signatures; large POST rules | Upload volume by destination |
| T1110 | Brute Force | conn.log: many connections to same port (22/3389/5985) from single src | ET SCAN brute force rules per service | High session count to auth ports |

---

### Network Change Management

```bash
# Detect unauthorized network devices via SNMP ARP polling
# Run nightly and compare to CMDB

#!/bin/bash
# nightly-arp-check.sh
SNMP_COMMUNITY="readonly_community"
ROUTER_IP="10.0.0.1"

# Poll ARP table from router via SNMP
snmpwalk -v2c -c $SNMP_COMMUNITY $ROUTER_IP 1.3.6.1.2.1.4.22.1.2 2>/dev/null |   grep -oE '([0-9A-F]{2}:){5}[0-9A-F]{2}' |   tr '[:upper:]' '[:lower:]' | sort > /tmp/arp-$(date +%Y%m%d).txt

# Compare to previous day
if [ -f /tmp/arp-$(date -d yesterday +%Y%m%d).txt ]; then
    NEW_DEVICES=$(diff /tmp/arp-$(date -d yesterday +%Y%m%d).txt                        /tmp/arp-$(date +%Y%m%d).txt | grep '^>' | awk '{print $2}')
    if [ -n "$NEW_DEVICES" ]; then
        echo "NEW DEVICES DETECTED: $NEW_DEVICES" |           mail -s "Network: New MAC addresses detected" soc@corp.com
    fi
fi
```

---

## References and Further Reading

- **Suricata:** https://suricata.io/documentation/ | https://docs.suricata.io/
- **Zeek:** https://docs.zeek.org/ | https://github.com/zeek/zeek
- **Security Onion:** https://docs.securityonion.net/ | https://github.com/Security-Onion-Solutions/securityonion
- **Arkime:** https://arkime.com/faq | https://github.com/arkime/arkime
- **Pi-hole:** https://docs.pi-hole.net/ | https://github.com/pi-hole/pi-hole
- **AdGuard Home:** https://github.com/AdguardTeam/AdGuardHome/wiki
- **nDPI:** https://github.com/ntop/nDPI | https://www.ntop.org/ndpi/
- **FreeRADIUS:** https://wiki.freeradius.org/
- **PacketFence:** https://www.packetfence.org/documentation/
- **The Practice of Network Security Monitoring** — Richard Bejtlich
- **MITRE ATT&CK:** https://attack.mitre.org/
- **Cloudflare DDoS Resources:** https://www.cloudflare.com/learning/ddos/
- **BCP38 / RFC 2827:** https://www.rfc-editor.org/rfc/rfc2827
- **JA3 Fingerprints:** https://github.com/salesforce/ja3 | https://sslbl.abuse.ch/ja3-fingerprints/
- **Community ID Spec:** https://github.com/corelight/community-id-spec
- **Arkime Wiki:** https://github.com/arkime/arkime/wiki

---

*Last updated: 2026-04-26 | TeamStarWolf Cybersecurity Reference Library*
