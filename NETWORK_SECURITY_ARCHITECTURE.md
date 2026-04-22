# Network Security Architecture Reference

A practitioner reference for designing, evaluating, and defending enterprise networks.
Covers defense-in-depth architecture patterns with real configuration examples, mapped to
NIST 800-53 SC family, CIS Controls 12-13, and MITRE ATT&CK.

---

## Defense-in-Depth Network Architecture

### Traditional DMZ Architecture

The classic three-zone model places public-facing services in a demilitarized zone between
two firewall boundaries, preventing direct Internet-to-internal traffic.

```
Internet
    |
[Perimeter FW / NGFW]
    |
  [DMZ] ── Web servers, email gateways, reverse proxies, VPN concentrators, WAF
    |
[Internal FW]
    |
[Internal LAN] ── Workstations, file servers, print servers
    |
[Core / Data Tier] ── Databases, domain controllers, sensitive servers
```

**DMZ purpose**: expose services to the Internet while preventing direct Internet-to-internal
reachability. A compromise of a DMZ host does not automatically yield internal access.

**Services placed in the DMZ**:
- Web servers (reverse-proxy to internal application servers — DMZ host never runs the app itself)
- Email gateways (MTA relay, spam/malware filtering, DKIM signing)
- Public-facing DNS resolvers (authoritative or recursive with split-DNS)
- VPN concentrators (terminate remote access tunnels here, not internally)
- Web Application Firewall (WAF) appliances or virtual instances
- SMTP, SFTP, and other partner-facing services

**Communication rules**:
| Source | Destination | Verdict | Notes |
|---|---|---|---|
| Internet | DMZ | Restricted ports only | TCP/443, TCP/25, etc. — deny all others |
| DMZ | Internal LAN | Only required flows | Proxy-to-app-server, LDAP auth, DB queries via app tier |
| Internal LAN | DMZ | Admin access, monitoring | SSH/RDP from jump server, SNMP, syslog |
| Internet | Internal LAN | NEVER | Default deny — no direct path |
| DMZ | Internet | Egress-filtered | Only required (SMTP out, NTP, cert validation) |

**ATT&CK relevance**: T1190 Exploit Public-Facing Application is mitigated by limiting blast
radius of DMZ compromises. T1021 (lateral movement) is slowed by internal firewall between zones.

---

### Modern Segmented Architecture

Flat networks were the norm in the 1990s. Modern architecture layers segmentation, micro-
segmentation, and zero-trust overlays:

```
Internet
    |
[ISP Edge Router / BGP]
    |
[DDoS Scrubbing / Upstream protection]
    |
[Perimeter NGFW Cluster] (Active/Passive HA)
    |              |
  [DMZ]     [Remote Access Zone]
    |
[Core Switching - Layer 3]
    |        |         |         |
[VLAN 10] [VLAN 20] [VLAN 30] [VLAN 40]
  Users     Servers   OT/IoT   Management
    |
[Micro-segmentation / East-West Firewall]
    |
[Database Tier]
```

Key differences from classic DMZ:
- **DDoS scrubbing** upstream of perimeter firewall (on-prem or cloud-based)
- **HA firewall cluster** — no single point of failure at perimeter
- **Layer 3 core switching** — routing between VLANs enforced with ACLs at the distribution layer
- **Management VLAN** — completely separate path for device administration (out-of-band)
- **East-west firewall** — micro-segmentation between server workloads, not just north-south

---

### Network Zones (Security Tiers)

| Zone | Purpose | Trust Level | Allowed Inbound | Allowed Outbound |
|---|---|---|---|---|
| Internet | Untrusted external | 0 | N/A | N/A |
| DMZ / Perimeter | Public-facing services | 1 | Internet (specific ports) | Internal (proxied only) |
| Guest / Wireless | BYOD, visitor Wi-Fi | 2 | DNS, Internet only | Internet only |
| User / Workstation | Employee endpoints | 3 | Management from Mgmt zone | Internal resources |
| Server | Application servers | 4 | From User zone (apps), DMZ (reverse proxy) | Database tier, Mgmt |
| Database | Data tier | 5 | From Server zone only | Replication peers only |
| Management | Out-of-band network | 6 | Privileged users only | All zones (management) |
| OT / IoT | Industrial / IoT devices | 3 | Specific control protocols only | Very restricted |
| Security | SIEM, security tools | 5 | Log/event collection from all zones | Threat intel, updates |

**NIST 800-53**: SC-7 (Boundary Protection), SC-32 (Information System Partitioning)
**CIS Control 12**: Network Infrastructure Management, **CIS Control 13**: Network Monitoring

---

## Firewall Architecture and Policy

### NGFW Policy Design

Next-generation firewalls add application awareness, user identity, and threat prevention
on top of traditional stateful packet inspection.

**Zone-based policy**: traffic classified by source/destination security zone, not just
IP address and port number. A policy entry reads as:
"Allow users in the User zone to reach servers in the Server zone on application HTTPS."

**Application-ID (App-ID)**: Palo Alto's App-ID identifies the actual application
regardless of the port it runs on, detecting evasion techniques (e.g., malware tunneling
over TCP/80). Cisco's NBAR performs similar classification.

**Policy hierarchy**: security zones → address groups → application groups → user groups
(via User-ID / AD integration). Policies evaluated top-down; first match wins.

**Default deny**: an implicit deny-all rule at the bottom of the ruleset catches all
unmatched traffic. Log all denied traffic — denied connections are a key detection signal
(ATT&CK T1046 Network Service Scanning, T1571 Non-Standard Port).

**Rule naming convention**:
```
[Action]-[SourceZone]-[DestZone]-[App/Service]-[Purpose]
```
Example: `ALLOW-USER-SERVER-HTTPS-CorporateApps`

---

### Perimeter Firewall Rules (Example Policy)

```
# Rule 1 — Allow internal clients to reach internal DNS servers only
ALLOW   INTERNAL        DNS_SERVERS     UDP/53          Internal DNS queries

# Rule 2 — Allow web browsing via explicit proxy (users must go through proxy)
ALLOW   USER            PROXY           TCP/8080        Web browsing via proxy

# Rule 3 — Allow outbound SMTP from email gateway only
ALLOW   DMZ_EMAIL       INTERNET        TCP/25          Outbound email relay

# Rule 4 — Allow inbound HTTPS to WAF / web servers in DMZ
ALLOW   INTERNET        DMZ_WEB         TCP/443         Public web services

# Rule 5 — Allow HTTPS from WAF to internal app servers (proxied)
ALLOW   DMZ_WEB         SERVER          TCP/8443        Backend app servers

# Rule 6 — Allow privileged access from jump server to all devices
ALLOW   MGMT_JUMP       ANY             TCP/22,3389     Admin access (MFA required)

# Rule 7 — Block and log all other traffic
DENY    ANY             ANY             ANY             Default deny — log all
```

**Operational notes**:
- Audit rules quarterly — remove rules that have not matched in 90+ days
- Document business justification for every allow rule (change control)
- Log all traffic including allowed — not just denies — for full visibility
- Separate management access rules into their own policy section

---

### High Availability Firewall Design

**Active/Passive failover**:
- Primary processes all traffic; standby syncs state but does not forward
- On failure: standby takes over within seconds (sub-second with preemption disabled)
- State sync includes: session table, NAT translation table, routing table
- VRRP or proprietary HA protocol used for gateway IP failover

**Active/Active**:
- Both units process traffic simultaneously (higher throughput)
- Requires careful handling of asymmetric routing or full session sync
- More complex to troubleshoot — each unit must handle sessions it did not initiate

**First Hop Redundancy Protocols (FHRP)**:
- **HSRP** (Cisco proprietary): one active gateway, one standby, virtual IP shared
- **VRRP** (RFC 5798): open standard equivalent to HSRP, supported across vendors
- **GLBP** (Cisco): load-balancing FHRP — multiple routers share gateway load

**State synchronization checklist**:
- [ ] Session table synced between HA peers
- [ ] NAT/PAT translation table synced
- [ ] Routing table (adjacencies re-established or synced)
- [ ] VPN tunnel state (IKE/IPsec SAs)
- [ ] DHCP bindings (if DHCP served by firewall)

---

## IDS/IPS Placement and Configuration

### IDS/IPS Deployment Points

```
Internet
    |
[Perimeter IPS — inline, block mode]
    |
  [DMZ]
    |
[Internal IDS — passive tap, detect mode]
    |
[User VLAN]            [Server VLAN]
    |                        |
          [East-West IDS/IPS]
```

**Perimeter IPS (inline / blocking)**:
- Positioned between edge router and DMZ
- High-confidence signature rules in block mode (known exploit signatures, CVE-matched rules)
- Signature update frequency: daily minimum, emergency updates on critical CVEs
- Integrated into NGFW (Palo Alto Threat Prevention, Cisco Firepower / TALOS, Fortinet IPS)

**Internal IDS (passive tap / detection only)**:
- Monitoring east-west traffic for lateral movement (ATT&CK TA0008)
- Passive — receives a copy of traffic via SPAN port or hardware TAP
- Higher false-positive rate initially — tune for 30-60 days before any blocking
- Particularly valuable for detecting: credential dumping across network, SMB exploitation,
  LDAP reconnaissance (BloodHound), Kerberoasting traffic

**Cloud-based IPS**:
- AWS: GuardDuty (anomaly detection) + AWS Network Firewall (stateful IPS rules)
- Azure: Azure Firewall Premium (IDPS), Microsoft Defender for Cloud
- GCP: Cloud IDS (Palo Alto-powered), Cloud Armor (perimeter)

---

### Suricata Inline IPS Configuration

```yaml
# /etc/suricata/suricata.yaml — inline IPS mode via AF_PACKET
af-packet:
  - interface: eth0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
    copy-mode: ips               # IPS mode — drop matching packets
    copy-iface: eth1             # Forward non-matching traffic out eth1

# Alert output (JSON for SIEM ingestion)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      rotate-interval: day
      types:
        - alert:
            metadata: yes
            tagged-packets: yes
        - flow
        - dns
        - http:
            extended: yes
        - tls:
            extended: yes

# Performance tuning
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
```

**Key Suricata rule categories and deployment mode**:
| Category | Recommended Mode | Rationale |
|---|---|---|
| ET EXPLOIT | Block | High confidence, known CVE exploits |
| ET MALWARE | Block | C2 communications, malware downloads |
| ET TROJAN | Block | Specific trojan signatures, high specificity |
| ET HUNTING | Detect/Alert | Suspicious patterns — tune before blocking |
| ET SCAN | Detect/Alert | Scanning is not always malicious; context needed |
| ET POLICY | Detect/Alert | Policy violations — depends on org policy |

**Suricata rule example (custom)**:
```
# Detect Cobalt Strike default HTTPS certificate CN
alert tls any any -> $HOME_NET any (
  msg:"CobaltStrike Default Certificate Detected";
  tls.cert_subject; content:"Major Browsers Intermediate CA";
  classtype:trojan-activity;
  sid:9000001; rev:1;
)
```

---

## Network Segmentation Implementation

### VLAN Design for Enterprise

Recommended VLAN numbering scheme for a medium-to-large enterprise:

| VLAN | Name | Subnet | Purpose |
|---|---|---|---|
| 1 | Native | N/A | Never use — change native VLAN to 999 |
| 10 | Management | 10.10.10.0/24 | Network device management (OOB) |
| 20 | Servers | 10.20.0.0/22 | Server farm (1,022 hosts) |
| 30 | Users | 10.30.0.0/21 | Workstations (2,046 hosts) |
| 40 | Printers | 10.40.0.0/24 | Print devices (isolated) |
| 50 | VoIP | 10.50.0.0/24 | IP phones (QoS required) |
| 60 | Guest | 10.60.0.0/24 | Guest Wi-Fi (Internet only, isolated) |
| 70 | DMZ | 10.70.0.0/24 | DMZ services |
| 80 | IoT | 10.80.0.0/24 | IoT devices (no LAN access) |
| 88 | Remediation | 10.88.0.0/24 | Non-compliant endpoints (NAC quarantine) |
| 99 | Blackhole | N/A | Unused switch ports |
| 999 | Native Trunk | N/A | Non-routable native VLAN (trunk ports) |

**Cisco IOS-XE switch configuration**:

```
! Create VLANs
vlan 10
 name Management
vlan 20
 name Servers
vlan 30
 name Users
vlan 88
 name Remediation
vlan 99
 name Blackhole
vlan 999
 name NativeTrunk

! Access port — user workstation
interface GigabitEthernet1/0/1
 description UserWorkstation
 switchport mode access
 switchport access vlan 30
 switchport nonegotiate          ! Disable DTP — prevent VLAN hopping
 spanning-tree portfast          ! Skip STP listening/learning (endpoints only)
 spanning-tree bpduguard enable  ! Shutdown port if BPDU received (rogue switch)
 ip dhcp snooping limit rate 15  ! DHCP rate-limit — prevent starvation
 ip arp inspection limit rate 100 ! DAI rate-limit
 storm-control broadcast level 20.00 10.00
 storm-control action shutdown
 no shutdown

! Access port — unused (blackhole)
interface GigabitEthernet1/0/48
 description UNUSED
 switchport mode access
 switchport access vlan 99
 shutdown

! Trunk port — to distribution switch
interface GigabitEthernet1/0/49
 description UptrunkToDistribution
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 999  ! Non-routable native VLAN
 switchport trunk allowed vlan 10,20,30,40,50,60,88
 spanning-tree guard root           ! Protect root bridge position
```

**Layer 2 attack mitigations built into this config**:
- **VLAN hopping prevention**: `switchport nonegotiate` disables DTP; native VLAN changed from 1
- **Rogue DHCP server prevention**: DHCP snooping (only trust uplink ports)
- **ARP spoofing prevention**: Dynamic ARP Inspection (DAI) validates ARP against DHCP bindings
- **STP manipulation prevention**: PortFast + BPDUGuard; Root Guard on trunk ports
- **MAC flooding prevention**: port security or 802.1X (see NAC section)

---

### Micro-segmentation

Micro-segmentation enforces per-workload or per-application east-west traffic policy,
reducing the blast radius of a compromised host to a single workload rather than an
entire VLAN.

**Implementation approaches**:

| Approach | Tool | Enforcement Point | Best For |
|---|---|---|---|
| Host-based agent | Illumio Core, Guardicore (Akamai) | OS firewall per host | Bare metal + VM |
| Hypervisor-based | VMware NSX-T Distributed Firewall | vNIC (kernel bypass) | VMware environments |
| CNI-based | Calico, Cilium NetworkPolicy | eBPF / iptables | Kubernetes |
| NGFW-based | Palo Alto Panorama + DAGs | Physical/virtual NGFW | Legacy environments |
| Cloud-native | AWS Security Groups, Azure NSGs | SDN layer | Cloud workloads |

**Micro-segmentation implementation workflow**:
1. **Discover**: map all application dependencies (Illumio illumination, NSX Network Insight)
2. **Model**: build allow-list based on observed flows — 30-day learning period
3. **Test**: simulate policy enforcement in test mode, validate applications still function
4. **Enforce**: switch to enforcement mode, enable default-deny east-west
5. **Monitor**: alert on denied flows, investigate anomalies, update policy for new applications

**Calico NetworkPolicy example (Kubernetes)**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: webapp
      ports:
        - protocol: TCP
          port: 5432
  egress: []  # No egress from database pods
```

---

### Software-Defined Networking (SDN) Security

**Control plane separation**:
- SDN controller (OpenFlow, ONOS, OpenDaylight) manages the control plane centrally
- Data plane (forwarding ASICs) executes flow rules pushed by the controller
- Controller is the single point of failure and highest-value target — harden aggressively
- Controller hardening: dedicated management network, MFA, audit logging, HA deployment

**OpenFlow protocol security**:
- TLS 1.2+ required between controller and all switches (OpenFlow 1.3+)
- Certificate pinning on switch side — reject controller cert changes without reconfig
- Separate management plane for controller API (HTTPS/REST) from data plane (OpenFlow)

**SD-WAN security considerations**:
- Traffic steering policy controls which applications use which WAN transport (MPLS vs Internet)
- WAN link encryption: IPsec with IKEv2 between SD-WAN edge nodes
- Security service chaining: route traffic through cloud-hosted SSE/ZTNA before reaching apps
- SD-WAN vendors and security posture:
  - **Cisco Catalyst SD-WAN (Viptela)**: Umbrella integration, Snort IPS, Secure Internet Gateway
  - **VMware SD-WAN (VeloCloud)**: third-party SSE integration via Cloud Security Service
  - **Palo Alto Prisma SD-WAN**: native integration with Prisma Access (SSE/ZTNA)
  - **Fortinet Secure SD-WAN**: NGFW capabilities built into SD-WAN edge (FortiGate)

---

## Network Access Control (NAC)

### 802.1X Implementation

802.1X provides port-based authentication: a device cannot send or receive traffic until
successfully authenticated. The three-component model:

```
Supplicant (endpoint)  →  Authenticator (switch/AP)  →  Authentication Server (RADIUS / ISE)
     EAP-TLS                    RADIUS                      AD / Certificate Authority
```

**EAP method comparison**:
| EAP Method | Auth Factor | Certificate Required | Security Level | Recommended Use |
|---|---|---|---|---|
| EAP-TLS | Certificate | Both sides | Highest | Corporate devices (PKI) |
| PEAP-MSCHAPv2 | Password + server cert | Server only | Medium | Where PKI unavailable |
| EAP-TTLS | Password + server cert | Server only | Medium | Non-Windows devices |
| MAB | MAC address | No | Low | Printers, IoT (fallback) |

**Cisco IOS-XE 802.1X configuration**:

```
! AAA configuration
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius

! Enable 802.1X globally
dot1x system-auth-control

! RADIUS server (Cisco ISE)
radius server ISE_PRIMARY
 address ipv4 10.10.10.100 auth-port 1812 acct-port 1813
 key 0 RadiusSharedSecret123!
 timeout 5
 retransmit 3

radius server ISE_SECONDARY
 address ipv4 10.10.10.101 auth-port 1812 acct-port 1813
 key 0 RadiusSharedSecret123!

aaa group server radius ISE_GROUP
 server name ISE_PRIMARY
 server name ISE_SECONDARY
 load-balance method least-outstanding

! Interface configuration
interface GigabitEthernet1/0/1
 authentication port-control auto
 authentication host-mode multi-auth        ! Multiple devices (phone + PC on same port)
 authentication order dot1x mab             ! Try 802.1X first, fall back to MAB
 authentication priority dot1x mab
 authentication event fail action next-method
 authentication event server dead action reinitialize vlan 30  ! Fail-open to user VLAN
 authentication event server alive action reinitialize
 authentication periodic                    ! Re-authenticate periodically
 authentication timer reauthenticate 3600   ! Re-auth every hour
 dot1x pae authenticator
 dot1x timeout tx-period 10
 mab                                        ! MAC Auth Bypass for non-802.1X devices
 spanning-tree portfast
```

---

### Dynamic VLAN Assignment

Cisco ISE assigns VLAN dynamically based on device identity, user identity, and posture:

| Condition | Assigned VLAN | Access Level |
|---|---|---|
| Domain computer + valid AD user + compliant | 30 (Users) | Full corporate access |
| Domain computer + valid user + non-compliant (missing patches) | 88 (Remediation) | Patch server only |
| Non-domain device + valid user credentials | 60 (Guest) | Internet only |
| Unknown MAC address (MAB fallback) | 99 (Blackhole) | No access |
| VoIP phone (CDP/LLDP identified) | 50 (VoIP) | Call manager only |
| IoT / OT device (profiled) | 80 (IoT) | Specific protocol, specific server |

**ISE posture checks (pre-admission)**:
- Antivirus signature age < 7 days
- OS patches: Windows Update within 30 days or latest cumulative applied
- Disk encryption (BitLocker / FileVault) enabled
- Host-based firewall active
- Corporate EDR agent running and reporting

**Post-admission (continuous)**:
- ISE Change of Authorization (CoA): dynamically reassign VLAN on policy violation
- MDM/EMM integration (Intune, Jamf): compliance state updated in real time
- Quarantine trigger: EDR alert → SOAR → ISE CoA → endpoint isolated to VLAN 88

---

## Secure Remote Access

### VPN Architecture

**Site-to-Site VPN (IPsec)**:

```
Site A                          Site B
[Internal LAN]──[Edge FW]══[IPsec Tunnel]══[Edge FW]──[Internal LAN]
               10.1.1.1    Internet    10.2.2.1
```

IKEv2 is the current standard (IKEv1 is deprecated per RFC 9395).

Phase 1 (IKE_SA — protect control channel):
- Authentication: RSA certificates (preferred) or pre-shared key
- Key exchange: Diffie-Hellman Group 20 (384-bit ECC) minimum; Group 21 (521-bit ECC) for high-security
- Encryption: AES-256-GCM
- PRF/Integrity: SHA-384 or SHA-512

Phase 2 (Child_SA — protect data traffic):
- Protocol: ESP (Encapsulating Security Payload) — provides confidentiality + integrity
- Encryption: AES-256-GCM (AEAD — no separate integrity algorithm needed)
- PFS: Enabled (DH Group 20) — new key for each Child_SA
- Lifetime: 1 hour (3600 seconds) / 1 GB — whichever comes first

**Remote Access VPN**:
- **Full tunnel**: all endpoint traffic routed through VPN — maximum visibility, higher bandwidth
- **Split tunnel**: only RFC1918/corporate traffic through VPN; Internet traffic goes direct
  - Split tunnel risk: compromised endpoint has simultaneous access to corporate and Internet,
    increasing C2/exfiltration surface (ATT&CK T1572, T1048)
- **Always-on VPN**: enforce VPN connection before any network access (GlobalProtect, Cisco AnyConnect
  with pre-logon, Intune + MDE integration)

**ZTNA replacing traditional VPN**:
- Application-level access — endpoint connects to a specific application, not a network segment
- Device posture evaluated before every access decision (not just at connection time)
- Least-privilege: endpoint can reach the app, not adjacent hosts on the same segment
- Vendors: Zscaler ZPA, Palo Alto Prisma Access, Cloudflare Access, CrowdStrike Falcon ZTNA

---

### VPN Security Hardening

**Cisco IOS-XE IKEv2 hardened configuration**:

```
! Strong IKEv2 proposal
crypto ikev2 proposal STRONG_PROPOSAL
 encryption aes-cbc-256
 integrity sha384
 group 20

! IKEv2 policy — only accept STRONG_PROPOSAL
crypto ikev2 policy STRICT_POLICY
 proposal STRONG_PROPOSAL

! IKEv2 keyring (certificate-based auth)
crypto ikev2 keyring CERT_AUTH
 peer REMOTE_SITE
  address 203.0.113.10
  pre-shared-key local  ThisIsOnlyForLab
  pre-shared-key remote ThisIsOnlyForLab

! Use PKI instead of PSK in production:
! crypto ikev2 profile SITE_PROFILE
!  match identity remote fqdn domain partner.example.com
!  authentication remote rsa-sig
!  authentication local rsa-sig
!  pki trustpoint MY_CA

! IPsec transform set (AES-GCM = AEAD, no separate integrity)
crypto ipsec transform-set STRONG_TS esp-aes 256 esp-sha384-hmac
 mode tunnel

! Enable PFS
crypto ipsec profile STRONG_PROFILE
 set transform-set STRONG_TS
 set pfs group20
 set security-association lifetime seconds 3600
 set security-association lifetime kilobytes 1048576

! Apply to tunnel interface
interface Tunnel0
 ip address 192.168.100.1 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel destination 203.0.113.10
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile STRONG_PROFILE
```

**VPN hardening checklist**:
- [ ] IKEv2 only (disable IKEv1)
- [ ] DH Group 20+ (ECC 384-bit)
- [ ] AES-256-GCM for all encryption
- [ ] Certificate-based authentication (no PSK in production)
- [ ] PFS enabled on all tunnels
- [ ] MFA required for remote access VPN
- [ ] Split tunnel policy documented and approved, or full tunnel enforced
- [ ] VPN gateway patched — track CVEs for vendor (Ivanti, Cisco, Palo Alto have had critical ones)

---

## Load Balancing and High Availability

### Load Balancer Security

**TLS termination models**:
| Model | Description | Inspection | Backend Encryption |
|---|---|---|---|
| SSL Offloading | TLS terminated at LB, plaintext to backend | Full | No (trusted internal segment) |
| SSL Bridging | TLS terminated at LB, re-encrypted to backend | Full | Yes |
| SSL Passthrough | TLS passes through to backend unchanged | None | Yes (backend handles) |

**Security recommendation**: SSL Bridging — decrypt at load balancer, inspect (WAF, DLP),
re-encrypt to backend. SSL Passthrough prevents security inspection.

**WAF integration**:
- Deploy WAF on or before the load balancer — reverse proxy architecture
- WAF inspects decrypted HTTP/S traffic for OWASP Top 10 attacks
- WAF products: F5 AWAF, Imperva, Cloudflare WAF, AWS WAF, ModSecurity (open source)
- OWASP CRS: Core Rule Set for ModSecurity — 90+ rules covering SQLi, XSS, RFI, LFI

**Health check configuration (F5 BIG-IP example)**:
```
ltm monitor http WEBAPP_MONITOR {
    defaults-from http
    interval 10
    timeout 31
    send "GET /health HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
    recv "200 OK"
    recv-disable "5[0-9][0-9]"  # Remove from pool on 5xx
}
```

---

### DDoS Protection Architecture

```
Internet
    |
[Upstream scrubbing — Cloudflare Magic Transit / Akamai Prolexic]
    |   (BGP anycast redirects traffic to scrubbing centers during attack)
    |
[ISP-level filtering — null routing / rate limiting on request]
    |
[On-premises anti-DDoS appliance — Radware DefensePro / Arbor APS]
    |
[Perimeter NGFW]
    |
[Edge CDN — Cloudflare / CloudFront for origin shielding]
    |
[Application Servers]
```

**Protection layers**:
1. **Upstream scrubbing** (cloud): absorbs volumetric attacks before they reach your pipe
   - Cloudflare Magic Transit, Akamai Prolexic, AWS Shield Advanced (BGP anycast)
   - Effective against 100+ Gbps attacks — pipe saturation avoided
2. **ISP-level**: request null routing (blackhole) of attack source CIDRs from your ISP
   - BGP blackhole communities: RFC 7999 (`BLACKHOLE` community 65535:666)
   - Remote Triggered Black Hole (RTBH): advertise victim prefix with no-export community
3. **On-premises appliance**: Radware DefensePro, Netscout/Arbor APS
   - Volumetric: rate limiting, geo-blocking, RTBH triggers
   - Protocol: SYN proxy, challenge-response (SYN cookies)
   - Application: HTTP rate limiting, bot detection, behavioral analysis
4. **Edge CDN**: Cloudflare, CloudFront — absorb application-layer floods, cache static content

---

### DDoS Attack Types and Defenses

| DDoS Type | Layer | Example Attacks | Defense Mechanisms |
|---|---|---|---|
| Volumetric | L3/L4 | UDP flood, ICMP flood, random-source flood | Upstream scrubbing, BCP38 source validation, RTBH |
| Protocol | L4 | SYN flood, ACK flood, fragmented packets | SYN cookies (RFC 4987), rate limiting, stateful FW |
| Amplification | L3/L4 | DNS (50x), NTP (556x), SSDP (30x), memcached (50,000x) | Disable open resolvers, BCP38, block UDP/11211 |
| Application | L7 | HTTP GET/POST flood, Slowloris, slow POST, R.U.D.Y | WAF rate limiting, CAPTCHA, bot detection, connection limits |
| SSL/TLS | L6 | SSL renegotiation flood, handshake flood | Session rate limiting, SSL hardware offload, DTLS protection |
| DNS | L7 | NXDOMAIN flood, random subdomain (water torture) | Response rate limiting (DNS RRL), anycast DNS, query filtering |

**BCP38 (Network Ingress Filtering)**: ISPs should filter traffic from customer-facing interfaces
where source IP does not match the allocated prefix — prevents spoofed-source amplification attacks.
Internal implementation: filter outbound traffic where source IP is not within your allocated ranges.

**SYN cookie implementation** (Linux kernel):
```bash
# Enable SYN cookies globally
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Persist via sysctl
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-ddos.conf
sysctl -p /etc/sysctl.d/99-ddos.conf

# Also tune backlog and connection limits
echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.d/99-ddos.conf
echo "net.core.somaxconn = 65535" >> /etc/sysctl.d/99-ddos.conf
```

---

## Network Monitoring and Visibility

### NetFlow / IPFIX

NetFlow captures metadata about network flows (not full packets): source/destination IP,
ports, protocol, bytes, packets, start/end time. Enables traffic analysis, capacity
planning, and threat detection without full packet storage cost.

**Cisco IOS-XE NetFlow v9 configuration**:

```
! Define exporter
ip flow-export destination 10.10.10.50 9996   ! SIEM/collector IP and port
ip flow-export version 9
ip flow-export source Loopback0               ! Use stable loopback as source

! Tune cache timers
ip flow-cache timeout active 5               ! Export active flows every 5 min
ip flow-cache timeout inactive 15            ! Export idle flows after 15 sec

! Enable on interfaces (both directions)
interface GigabitEthernet0/0/0
 ip flow ingress
 ip flow egress
interface GigabitEthernet0/0/1
 ip flow ingress
 ip flow egress
```

**IPFIX (NetFlow v10 — IETF standard)**:
- Recommended over proprietary NetFlow v9 for multi-vendor environments
- Flexible template system — export custom fields
- Supported by most modern routers/switches and cloud providers (VPC Flow Logs, Azure NSG Flow)

**Flow analysis tools**:
| Tool | Type | Strengths |
|---|---|---|
| ntopng | OSS | Real-time flow visualization, protocol analysis |
| Elastic (with flow ingest) | OSS | Full-text search, SIEM integration, dashboards |
| SolarWinds NTA | Commercial | Enterprise flow analysis, capacity planning |
| Stamus Networks SELKS | OSS | Suricata + Elasticsearch + Kibana stack |
| Kentik | SaaS | Cloud-scale flow analysis, DDoS detection |
| Darktrace | Commercial | AI anomaly detection on flow data |

**ATT&CK detection via NetFlow**:
- T1046 Network Service Scanning: high connection count to many destination ports from single source
- T1071.001 Web Protocols (C2): unusual persistent HTTP/S beaconing at regular intervals
- T1048 Exfiltration over alternative protocol: large outbound flows on non-standard ports
- T1110 Brute Force: many authentication failures to single destination from single source

---

### Out-of-Band Management Network

A dedicated management network (OOB) provides access to network devices even when
production network is unreachable (DDoS, misconfiguration, network outage).

**OOB network architecture**:
```
[Management Workstation]
        |
[Management Switch — VLAN 10 only]
        |
[Serial Console Server — Opengear CM7100 / Lantronix]
    |     |     |     |
  FW1   SW1   SW2   Router1    (console cables to each device)
```

**Components**:
- **Console server**: provides serial console access (RS-232) to all network devices
  - Vendors: Opengear CM7100, Lantronix SLB, Cisco Terminal Server
  - Access via SSH to console server → select device console port
  - Cellular backup modem for access when Internet link is down
- **Jump server (bastion host)**:
  - Hardened OS (minimal packages, CIS hardened)
  - MFA required for all sessions (hardware key preferred)
  - Session recording (CyberArk PSM, Teleport, StrongDM)
  - No Internet access from jump server — air-gapped from production traffic
- **Management ACLs**: all device management interfaces (SSH, HTTPS, SNMP) only accept
  connections from the management subnet — deny all other sources

**Cisco IOS management ACL**:
```
ip access-list standard MGMT_HOSTS
 permit 10.10.10.0 0.0.0.255
 deny   any log

line vty 0 15
 access-class MGMT_HOSTS in
 transport input ssh
 login local
 exec-timeout 10 0

ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
no ip http server           ! Disable HTTP management
ip http secure-server       ! HTTPS only
ip http access-class MGMT_HOSTS
```

---

### Network Security Monitoring Tools

**Full Packet Capture**:
- **Moloch / Arkime**: index full packets, searchable by IP, port, protocol, community ID
  - Storage requirement: 1 Gbps sustained = ~400 GB/day uncompressed
  - Retention depends on budget; typically 7-30 days at perimeter
  - PCAP-based: enables retrospective analysis of alerts

**Network Detection and Response (NDR)**:
| Tool | Detection Approach | Key Capability |
|---|---|---|
| Darktrace | Unsupervised ML (self-learning) | Detects novel threats without signatures |
| ExtraHop Reveal(x) | ML + protocol dissection | Wire-data at line rate, encrypted traffic analysis |
| Corelight | Zeek-based, rules + ML | Deep protocol logs, JA3/JA4 fingerprinting |
| Vectra AI | ML behavioral detection | Attacker behavior modeling, ATT&CK mapped |
| Stamus Networks | Suricata + ML | Signature + ML, open source foundation |

**Zeek (formerly Bro)**:
Zeek generates structured log files from network traffic — not signatures, but protocol state.
Key log files for threat detection:

| Log File | Contents | Use Cases |
|---|---|---|
| conn.log | All connections: IPs, ports, bytes, duration | Baseline, anomaly detection, flow analysis |
| http.log | HTTP requests: URI, method, user-agent, response | Web exfil, C2 beaconing, user-agent anomalies |
| dns.log | DNS queries and responses | C2 via DNS, DGA detection, data exfiltration |
| ssl.log | TLS handshakes: JA3/JA4, cert, version | Encrypted C2, self-signed certs, bad TLS |
| x509.log | Certificate details | Expired certs, suspicious CNs, Let's Encrypt C2 |
| files.log | File transfers (HTTP, SMTP, FTP) | Malware download, exfiltration |
| smb_files.log | SMB file operations | Lateral movement, ransomware file writes |
| kerberos.log | Kerberos authentication events | Kerberoasting, AS-REP roasting |

**Zeek deployment for C2 detection**:
```zeek
# zeek/scripts/detect-c2-beaconing.zeek
# Flag connections with regular intervals (beaconing behavior)
@load base/protocols/conn

event connection_state_remove(c: connection)
    {
    if ( c$duration < 0.5 sec && c$resp_bytes < 100 )
        {
        # Short, small connection — possible beacon
        NOTICE([$note=Weird::Short_Beacon,
                $conn=c,
                $msg=fmt("Possible C2 beacon: %s -> %s every ~%.1f seconds",
                         c$id$orig_h, c$id$resp_h, c$duration)]);
        }
    }
```

**SPAN ports vs hardware TAPs**:
| Characteristic | SPAN Port | Hardware TAP |
|---|---|---|
| Cost | Free (built into switch) | $500-$5,000 per link |
| Reliability | May drop packets under load | Always captures — passive |
| Injection risk | Can inject traffic | Cannot — physically passive |
| Duplex | May merge TX/RX | Separate TX/RX streams |
| Recommended for | Low-traffic links, budget constrained | Critical links, compliance |

---

## Architecture Evaluation Checklist

Use this checklist when evaluating or designing an enterprise network security architecture.

### Segmentation
- [ ] Network divided into security zones with defined trust levels
- [ ] DMZ hosts isolated from internal LAN — no direct Internet-to-internal paths
- [ ] VLAN native VLAN changed from 1; DTP disabled on all access ports
- [ ] DHCP snooping and Dynamic ARP Inspection enabled on all user VLANs
- [ ] Management plane separated from production traffic (OOB management)

### Perimeter Controls
- [ ] NGFW with App-ID / application inspection at perimeter
- [ ] Inline IPS with up-to-date signatures at Internet edge
- [ ] Default-deny rule at bottom of firewall policy; all denied traffic logged
- [ ] Egress filtering: outbound traffic restricted, not just inbound
- [ ] Firewall HA deployed (Active/Passive or Active/Active with session sync)

### Remote Access
- [ ] IKEv2 for all site-to-site VPN (IKEv1 disabled)
- [ ] DH Group 20+ and AES-256-GCM enforced
- [ ] Certificate-based VPN authentication (no PSK in production)
- [ ] MFA required for all remote access VPN connections
- [ ] ZTNA evaluated or deployed for application-level access

### Network Access Control
- [ ] 802.1X deployed on all wired access ports
- [ ] EAP-TLS or PEAP-MSCHAPv2 with NPS/ISE
- [ ] MAB fallback configured for non-802.1X devices (printers, IoT)
- [ ] Dynamic VLAN assignment based on identity and posture
- [ ] Non-compliant devices automatically quarantined (VLAN 88 or equivalent)

### Monitoring and Visibility
- [ ] NetFlow/IPFIX exported from all edge and distribution routers
- [ ] Zeek or equivalent deployed on mirrored traffic
- [ ] Full packet capture at Internet perimeter (30-day retention minimum)
- [ ] NDR or SIEM with network anomaly detection in place
- [ ] Hardware TAPs on critical links (not SPAN-only)

### DDoS Resilience
- [ ] Upstream scrubbing service contracted or evaluated
- [ ] ISP escalation contact documented for null route requests
- [ ] SYN cookies enabled on all Internet-facing Linux servers
- [ ] Anycast DNS deployed for authoritative DNS resilience
- [ ] CDN / origin shielding in place for web properties

---

## Framework Mappings

### NIST 800-53 (SC Family — System and Communications Protection)
| Control | Description | Architecture Element |
|---|---|---|
| SC-5 | Denial of Service Protection | DDoS scrubbing, rate limiting, SYN cookies |
| SC-7 | Boundary Protection | Perimeter firewall, DMZ, zone architecture |
| SC-8 | Transmission Confidentiality and Integrity | IPsec VPN, TLS everywhere |
| SC-10 | Network Disconnect | Session timeouts, VPN idle disconnect |
| SC-20 | Secure Name/Address Resolution | DNSSEC, DNS-over-TLS, split-DNS |
| SC-22 | Architecture and Provisioning for DNS | Redundant DNS, DMZ resolvers |
| SC-29 | Heterogeneity | Diverse vendor stack reduces monoculture risk |
| SC-32 | Information System Partitioning | VLAN segmentation, micro-segmentation |
| SC-39 | Process Isolation | Hypervisor isolation, container namespaces |

### CIS Controls (v8)
| Control | Description | Architecture Element |
|---|---|---|
| CIS 12 | Network Infrastructure Management | Switch hardening, VLAN design, trunk security |
| CIS 13 | Network Monitoring and Defense | NetFlow, NDR, IDS/IPS, Zeek deployment |

### MITRE ATT&CK Techniques Addressed
| Technique | ID | Defense |
|---|---|---|
| Exploit Public-Facing Application | T1190 | WAF, patch management, DMZ isolation |
| Valid Accounts (remote services) | T1078 | MFA on VPN/ZTNA, 802.1X, behavioral analytics |
| Network Service Scanning | T1046 | East-west firewall, micro-segmentation, IDS alerts |
| Lateral Movement (SMB, RDP) | T1021 | VLAN segmentation, micro-segmentation, EDR |
| Data Exfiltration | T1048 | Egress filtering, DLP, NetFlow anomaly detection |
| C2 Beaconing | T1071 | IPS signatures, Zeek beaconing detection, DNS monitoring |
| DDoS | T1498/T1499 | Upstream scrubbing, SYN cookies, rate limiting |
| ARP Spoofing | T1557.002 | Dynamic ARP Inspection, 802.1X |

---

*Last updated: April 2026 — mapped to NIST 800-53 Rev 5, CIS Controls v8, MITRE ATT&CK v15*
