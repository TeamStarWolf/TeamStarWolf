# Networking Architecture

> **In one minute:** Networking architecture is the deliberate design of how packets, flows, names, and trust move across an enterprise — campus, branch, data center, cloud, and the edges between them. A good network is not an accident of accreted VLANs; it is a layered system with an explicit addressing plan, a routed-or-switched fabric chosen on purpose, segmentation that maps to business risk, resolvable names, predictable performance, and telemetry you can actually query. This reference covers the reference topologies (spine-leaf/Clos, hub-and-spoke, hybrid interconnect), the overlay/underlay split (VXLAN/EVPN), segmentation and zero-trust network architecture, SD-WAN and SASE/SSE, the core services (DNS/DHCP/IPAM, load balancing/ADC), IPv6 and QoS, and observability — with security designed in at every layer rather than bolted on. It is vendor-neutral; named products appear only as examples. Pair it with **NETWORK_SECURITY_ARCHITECTURE** (controls and enforcement) and **SECURITY_ARCHITECTURE** (the enterprise-wide trust model).

| Read this when… | Start at |
|---|---|
| You are greenfielding a data-center fabric | [Reference architectures](#2-reference-architectures--patterns) → Spine-leaf / Clos |
| You inherited a flat network and need to segment it | [Segmentation & ZTNA](#34-segmentation-micro-segmentation--zero-trust) · [Anti-patterns](#7-anti-patterns--pitfalls) |
| You are connecting multiple sites or clouds | [SD-WAN & SASE](#35-wan-sd-wan-sase--sse) · [Hybrid/cloud interconnect](#37-hybrid--cloud-interconnect) |
| You are making a specific topology/overlay call | [Key design decisions (ADRs)](#4-key-design-decisions--trade-offs) |
| You need to tie design to controls & threats | [Security-by-design](#5-security-by-design-integration) |
| You want to score an existing network | [Maturity / checklist](#8-maturity--checklist) |
| You need the authoritative sources | [Standards](#6-standards--frameworks) · [Tools & further reading](#9-tools--further-reading) |

---

## 1. Principles & drivers

Networking architecture exists to serve application and data-flow requirements, not the other way around. Every durable design decision traces back to a small set of drivers and a smaller set of principles.

### 1.1 Drivers

- **Application topology.** East-west (server-to-server, microservices) traffic now dwarfs north-south (client-to-server) in most data centers. This single fact is why Clos fabrics displaced the old three-tier core/aggregation/access model.
- **Location dispersion.** Users, apps, and data are everywhere — HQ, branch, home, SaaS, multiple clouds. NIST SP 800-215 names this explicitly: multiple clouds, geographic spread, and microservices have dissolved the clean perimeter. The architecture must assume no single choke point.
- **Scale & elasticity.** Cloud and container platforms churn endpoints by the second. Addressing, naming, and policy must be automatable, not hand-configured.
- **Latency & experience.** Real-time media, trading, and interactive apps turn jitter and loss into revenue and safety problems.
- **Regulation & sovereignty.** Data-residency and segmentation mandates (PCI DSS, HIPAA, NIS2, sector rules) constrain where traffic may flow and how it must be isolated.
- **Threat landscape.** Lateral movement, DNS abuse, BGP hijacks, and encrypted-C2 are design inputs, not afterthoughts.

### 1.2 Principles

1. **Design for flows, not for boxes.** Start from a flow matrix (who talks to whom, in what direction, at what volume), then choose topology.
2. **Hierarchy and modularity.** Build in repeatable modules (a "pod", a "landing zone", a "branch profile") with clean boundaries so you can scale by replication, not redesign.
3. **Separate the overlay from the underlay.** Keep the physical/routed transport simple and stable; express tenancy, policy, and mobility in an overlay. Changing one must not force a change in the other.
4. **One authoritative source of truth per concern.** IPAM owns addresses; a routing design owns reachability; a policy model owns who-may-talk. Spreadsheets are not a source of truth.
5. **Default-deny between zones, least-privilege within.** The network should express business trust boundaries, not merely connect everything.
6. **Make it observable.** If you cannot measure a flow, you cannot secure, troubleshoot, or capacity-plan it. Telemetry is a first-class requirement.
7. **Automate the lifecycle.** Config as code, intent-based provisioning, and drift detection. Hand-cut configs are the dominant root cause of outages and of the misconfigurations attackers exploit.
8. **Fail predictably.** Blast radius, convergence time, and graceful degradation are design outputs you test, not hopes.
9. **Dual-stack by default.** IPv6 is not optional for new builds; design addressing and security for both stacks from day one.
10. **Security is a property of the design, not a product you add.** Segmentation, encryption-in-transit, resolver control, and route validation are architectural, not bolt-on.

---

## 2. Reference architectures & patterns

### 2.1 Spine-leaf (Clos / folded-Clos) data-center fabric

The dominant modern DC pattern. Every leaf connects to every spine; no leaf connects to another leaf, no spine to another spine. Any endpoint is exactly two hops from any other (leaf → spine → leaf), giving deterministic latency and non-blocking (or known-oversubscription) east-west capacity. Scale out by adding spines (more bandwidth) or leaves (more ports).

```
                 +---------+   +---------+   +---------+   +---------+
   SPINE  -->    | Spine 1 |   | Spine 2 |   | Spine 3 |   | Spine 4 |
                 +----+----+   +----+----+   +----+----+   +----+----+
                      |  \   /  |  \   /  |  \   /  |
                      |   \ /   |   \ /   |   \ /   |     (full mesh:
                      |    X    |    X    |    X    |      every leaf to
                      |   / \   |   / \   |   / \   |      every spine)
                 +----+----+   +----+----+   +----+----+
   LEAF   -->    | Leaf 1  |   | Leaf 2  |   | Leaf N  |   (ToR / border)
                 +----+----+   +----+----+   +----+----+
                   | | | |       | | | |       | | | |
   HOSTS  -->    servers       servers       border/
                                             services
```

- **Underlay:** a simple, stable routed fabric. The common choice is eBGP per device (unique ASN per leaf, shared ASN per spine tier) or an IGP (OSPF/IS-IS); ECMP spreads flows across all spines. The underlay's only job is to carry loopbacks and VTEP reachability.
- **Overlay:** VXLAN with a BGP EVPN control plane (see §3.3) carries tenant L2/L3 on top. Border leaves attach to the WAN/DC edge and to services (firewalls, load balancers).
- **Why it wins:** horizontal scale, uniform latency, no spanning-tree-dependent L2 core, and a clean overlay/underlay split that lets you automate tenancy without touching transport.

### 2.2 Three-tier hierarchical (campus) — core / distribution / access

Still the right pattern for **campus** (wired + wireless user access), where north-south and policy enforcement at the distribution layer dominate.

```
        [ Core ]  <- fast, routed, no policy; redundant pair/fabric
         /    \
  [ Distribution ]  <- L3 boundary, first-hop redundancy, ACL/QoS/policy,
         |              route summarization, VRF/segmentation enforcement
     [ Access ]  <- user/edge ports, 802.1X/NAC, PoE, wireless APs,
         |              port security, storm control
   endpoints / APs / IoT
```

Modern campus increasingly runs an **EVPN/VXLAN or SD-Access-style fabric** with an overlay for identity-based segmentation (group tags/SGT, VRFs) so a user's policy follows them regardless of where they plug in.

### 2.3 Hub-and-spoke WAN (and its SD-WAN evolution)

Branches (spokes) connect to one or more regional hubs. Classic MPLS hub-and-spoke is being overlaid or replaced by **SD-WAN** (§3.5), which builds an encrypted overlay across any transport (MPLS, broadband, LTE/5G) and steers application traffic by policy.

### 2.4 Cloud landing-zone / hub-spoke VNet/VPC topology

The cloud analogue of hub-and-spoke: a central **hub VPC/VNet** holds shared services (inspection firewalls, DNS resolvers, egress NAT, transit) and connects to **spoke VPCs/VNets** (one per app/environment) via a transit construct (transit gateway / vWAN hub / NCC hub) and to on-prem via private interconnect.

```
      on-prem / other clouds
              |
     (private interconnect / VPN)
              |
        +-----------+
        |  HUB VPC  |  shared: egress firewall, DNS, NAT, transit
        +-----+-----+
       /      |      \
  +------+ +------+ +------+
  |Spoke | |Spoke | |Spoke |   (prod / nonprod / shared-data,
  | app  | | app  | | data |    each its own blast-radius boundary)
  +------+ +------+ +------+
```

### 2.5 Zero-trust network access (ZTNA) overlay

A logical pattern, not a topology: no implicit trust from network location. A policy engine authenticates and authorizes each session (user + device posture + context) and brokers a connection to a *single application*, never exposing the network. See §3.4.

---

## 3. Building blocks / domains

### 3.1 Addressing & IPAM

- **IP addressing plan.** A hierarchical, summarizable plan is the foundation of routing scalability and of meaningful ACLs. Carve blocks by region → site → function so a single prefix describes a security zone.
- **IPAM as source of truth.** DNS/DHCP/IPAM ("DDI") tooling should own every allocation; manual tracking guarantees overlap and shadow networks.
- **IPv4 exhaustion & NAT.** RFC 1918 space, overlapping address domains after mergers, and carrier-grade NAT complexity are all symptoms of IPv4 scarcity — a driver toward IPv6.
- **IPv6 (§3.8).** Plan a global addressing hierarchy with room to summarize; do not transliterate IPv4 habits.

### 3.2 Routing & switching

- **Switching (L2):** VLANs (IEEE 802.1Q) for segmentation within a broadcast domain; keep L2 domains small — large L2 = large failure/flood domain = large attack surface for ARP/MAC abuse. Modern fabrics push the L2/L3 boundary to the leaf and carry L2 only inside an overlay.
- **Routing (L3):**
  - **IGP** — OSPF or IS-IS for intra-domain reachability (IS-IS is common in large fabrics/SP networks for its topology independence and scalability).
  - **BGP (RFC 4271)** — the inter-domain protocol and, increasingly, the fabric underlay/overlay control plane (eBGP underlay + BGP EVPN overlay).
  - **ECMP** for load distribution; **BFD** for sub-second failure detection; **first-hop redundancy** (VRRP) at L3 edges.
- **Routing hygiene is security:** prefix filters, max-prefix limits, authentication (BGP TCP-AO / keychains), and route origin validation (RPKI, §5) prevent hijack and leak.

### 3.3 Overlay / underlay & network virtualization

The core abstraction of modern DC and campus fabrics.

- **Underlay** — the physical, routed transport (loopbacks + ECMP). Stable, simple, rarely changes.
- **Overlay** — tenant networks tunneled over the underlay so L2/L3 adjacency and policy are decoupled from physical location (supports VM/container mobility).

**VXLAN (RFC 7348)** encapsulates L2 frames in UDP/IP, giving a 24-bit VNI (≈16M segments vs. VLAN's 4094). **BGP EVPN (RFC 7432; EVPN-VXLAN in RFC 8365)** is the scalable control plane: it distributes MAC/IP reachability and VTEP information via BGP, replacing flood-and-learn and enabling ARP suppression, distributed anycast gateways, and multi-tenancy. The NVO3 framework (RFC 7364/7365) is the architectural reference for this whole class.

```
  Tenant A VM  --frame-->  [VTEP/Leaf]  --VXLAN(UDP/IP)-->  [VTEP/Leaf]  --frame-->  Tenant A VM
                               ^  BGP EVPN control plane advertises MAC/IP + VNI  ^
   Underlay (eBGP/IS-IS + ECMP) carries only VTEP loopback reachability.
```

Alternatives/relatives: **Geneve** (extensible encap used by some SDN/NSX and cloud gateways), **MPLS/SR / Segment Routing (SRv6)** in provider and large-enterprise cores, **NVGRE** (legacy).

### 3.4 Segmentation, micro-segmentation & zero-trust

Segmentation is the single highest-leverage security property of a network design.

- **Macro-segmentation (zones):** VRFs, separate fabrics/VNets, or firewalled zones separating trust tiers (e.g., user / server / OT/ICS / DMZ / management / PCI). Enforced at routed boundaries with default-deny.
- **Micro-segmentation:** policy at the workload level — host-based firewalls, identity/attribute-based policy, hypervisor or CNI (Kubernetes NetworkPolicy, service mesh) enforcement — so compromise of one workload does not grant reachability to its neighbors. This is the architectural counter to **lateral movement (ATT&CK TA0008)**.
- **Zero-Trust Network Architecture (NIST SP 800-207):** access decisions are per-session, based on identity, device posture, and context; a **Policy Decision Point (PDP)** evaluates policy and a **Policy Enforcement Point (PEP)** brokers the connection. Network location grants nothing. ZTNA/SDP (per SP 800-215) replaces broad VPN access with app-specific brokered sessions, shrinking the attack surface and hiding infrastructure from unauthenticated clients.

```
  user+device --(authn/posture/context)--> [ PDP: policy engine ]
                                                   |
                                              decision
                                                   v
  user session <===== brokered, app-specific =====[ PEP ]=====> single app
                     (no network-level reachability; infra not exposed)
```

**Management-plane segmentation** (out-of-band management network / jump hosts, separate from data plane) is non-negotiable: it is the plane attackers target to pivot fabric-wide.

### 3.5 WAN, SD-WAN, SASE & SSE

- **SD-WAN** builds a secure overlay across heterogeneous transports (MPLS, internet, 5G), centrally orchestrated, with application-aware path selection (steer, replicate, or fail over per app SLA). It decouples WAN policy from carrier plumbing.
- **SASE (Secure Access Service Edge)** converges SD-WAN networking with cloud-delivered security (SWG, CASB, ZTNA, FWaaS) at distributed PoPs near users. Gartner now frames the single-vendor category as **"SASE Platforms"** (verify current naming); multi-vendor equivalents are "SASE alternatives."
- **SSE (Security Service Edge)** is the *security half* of SASE (SWG + CASB + ZTNA + FWaaS as a cloud platform) without the SD-WAN networking component — useful when you keep your own WAN but want cloud-delivered security for web/SaaS/private-app access.

| Term | Scope | Core components |
|---|---|---|
| SD-WAN | WAN transport & path policy | Overlay, app-aware routing, central orchestration |
| SSE | Security edge only | SWG, CASB, ZTNA, FWaaS |
| SASE (Platform) | SD-WAN **+** SSE, converged | All of the above, single policy/management plane |

### 3.6 DNS, DHCP & IPAM (DDI) and name resolution

- **DNS** is both a critical dependency and a prime attack vector. Architect it deliberately: authoritative vs. recursive separation, split-horizon (internal vs. external views), anycast for resolver resilience, and forwarders that enforce policy.
- **Protective/secure DNS:** controlled recursive resolvers with RPZ/threat-intel filtering counter **C2 over DNS and DNS-based exfiltration (ATT&CK T1071.004, T1048, T1568 dynamic resolution)**. **DNSSEC** provides origin authentication/integrity for records. **DoT (RFC 7858)** and **DoH (RFC 8484)** encrypt resolver traffic — architect them to go to *your* resolver, not to bypass your controls.
- **DHCP** with snooping, and **DAI (Dynamic ARP Inspection)** + **IP Source Guard** at the access layer, counter rogue-DHCP and ARP-spoofing (ATT&CK T1557 adversary-in-the-middle).
- **IPAM** ties it together as the allocation source of truth.

### 3.7 Load balancing & application delivery (ADC)

- **L4 vs L7:** L4 (connection) load balancing for raw throughput; L7 (ADC) for content/HTTP-aware routing, TLS termination/re-encryption, header normalization, and as a WAF host.
- **Patterns:** global server load balancing (GSLB, often DNS-based) for geo/DR; anycast VIPs; direct-server-return for high throughput; service mesh sidecar LB for east-west microservices.
- **Health checking & graceful drain** are reliability features; **TLS policy, WAF, and rate limiting** at the ADC are security features — design them together.

### 3.8 IPv6

- **IPv6 (RFC 8200)** is mandatory architecture for new builds (and for government per numerous mandates — verify your jurisdiction's deadline). Plan a hierarchical global addressing scheme; avoid NAT as a crutch.
- **Security parity:** every control you have for IPv4 (ACLs, segmentation, firewall rules, logging, RA Guard, DHCPv6 Guard, ND inspection) must exist for IPv6 — an unmonitored IPv6 stack running by default on hosts is a classic blind spot and covert path.

### 3.9 QoS & performance

- **Classify, mark (DSCP), queue, shape/police** consistently end-to-end; a QoS policy is only as good as its weakest trust boundary (re-mark at untrusted edges).
- Match QoS classes to application needs (real-time/voice/video vs. bulk vs. scavenger) and to WAN/SD-WAN path selection.

### 3.10 Observability & telemetry

- **Flow data** (NetFlow/IPFIX/sFlow) for who-talked-to-whom; **streaming telemetry** (gNMI/model-driven) for device state; **packet brokers/TAPs** for deep inspection; **synthetic probes** for active SLA measurement.
- Telemetry feeds capacity planning, troubleshooting, **and** detection — flow records are a primary data source for detecting lateral movement, beaconing, and exfiltration. Observability is a security control, not just an ops convenience.

---

## 4. Key design decisions & trade-offs

ADR-style: each decision states the choice, the context, and the trade-off. Record these for your own network.

### ADR-1 — DC fabric: spine-leaf vs. three-tier

- **Choose spine-leaf/Clos** when east-west traffic and horizontal scale dominate (virtualized/containerized DC). Trade-off: more uplinks/optics, requires routing + overlay competence and automation.
- **Keep three-tier** only for small, north-south-dominant sites where a fabric is overkill. Trade-off: STP-bounded L2, poor east-west scaling, larger failure domains.

### ADR-2 — Underlay control plane: eBGP vs. IGP

- **eBGP underlay** scales to very large fabrics, offers explicit per-hop policy and easy multivendor interop; verbose config without automation.
- **IGP (IS-IS/OSPF)** is simpler for moderate fabrics and converges fast; less granular policy, can be noisier at extreme scale. **Decide once, automate always.**

### ADR-3 — Overlay: VXLAN/EVPN vs. none vs. provider SR/MPLS

- **VXLAN + BGP EVPN** for multi-tenant DC/campus with mobility and large segment counts. Trade-off: operational complexity, VTEP/MTU planning (watch encap overhead — size jumbo MTU in the underlay).
- **No overlay** for small single-tenant networks (don't add complexity you won't use).
- **SR-MPLS / SRv6** in large enterprise cores and SP networks for traffic engineering at scale.

### ADR-4 — Segmentation enforcement: network-based vs. host/identity-based

- **Network/firewall zones** are easy to reason about and audit; coarse, and east-west inside a zone is unprotected.
- **Micro-segmentation (host/identity/mesh)** gives least-privilege down to the workload and follows identity; higher operational and policy-lifecycle cost. **Target: zones at the macro level, micro-segmentation for crown-jewel and PCI/OT estates.**

### ADR-5 — Remote/branch access: VPN vs. ZTNA/SASE

- **Traditional VPN** grants network-level reachability (broad blast radius; a compromised client is inside). Simple, well-understood.
- **ZTNA/SASE** grants app-specific brokered access with posture checks; smaller attack surface, better UX at distance, but a new control plane and a dependency on the provider's PoPs. **Direction of travel is ZTNA/SASE; migrate VPN to app-brokered access.**

### ADR-6 — DNS resolution: centralized protective DNS vs. permissive/split

- **Centralized protective resolvers** (with RPZ/threat intel, logging, DoH/DoT to your resolver) give control and detection; a dependency and potential choke point (make it anycast/HA).
- **Permissive/host-chosen DNS** is simple but blinds you and lets endpoints bypass policy via public DoH. **Prefer controlled resolvers; block/redirect unauthorized DoH.**

### ADR-7 — Cloud connectivity: private interconnect vs. VPN vs. public + ZTNA

- **Private interconnect (Direct Connect / ExpressRoute / Cloud Interconnect)** — predictable latency/throughput, private path; cost and lead time.
- **IPsec VPN over internet** — fast to stand up, cheaper; variable performance, bandwidth ceilings.
- **Public endpoints + ZTNA/private-link** — no transit network at all for SaaS-style access; depends on identity-centric controls. **Many estates use all three by tier.**

### ADR-8 — IPv6: dual-stack vs. IPv6-only (+ translation) vs. defer

- **Dual-stack** — pragmatic, universal compatibility; you operate (and must secure) two planes.
- **IPv6-only + NAT64/DNS64** — simplifies the long run, needed at hyperscale; app/tooling gaps remain. **Defer is not a strategy — unmanaged IPv6 is already on your hosts.**

---

## 5. Security-by-design integration

This is a security library: the network is a control surface, and good architecture measurably reduces vulnerability exposure. Map each design choice to controls and to the threats it defeats.

### 5.1 How architecture reduces exposure (threat → design control)

| Threat (MITRE ATT&CK) | Architectural control | Framework mapping |
|---|---|---|
| Lateral movement (TA0008), Remote Services (T1021) | Micro-segmentation, VRF/zone default-deny, east-west firewalling, service mesh mTLS | NIST CSF 2.0 **PR.AA/PR.IR**; CIS v8.1 **Control 12** (Network Infrastructure Mgmt), **13** (Network Monitoring & Defense); SP 800-207 ZTA |
| Adversary-in-the-Middle (T1557), ARP/DHCP spoofing | DAI, DHCP snooping, IP Source Guard, 802.1X/NAC, MACsec (802.1AE), RA Guard | CSF **PR.DS/PR.IR**; CIS **12**; ATT&CK mitigation M1037/M1035 |
| C2 & exfil over DNS (T1071.004, T1568, T1048) | Protective/centralized DNS, RPZ, DNSSEC, DoH/DoT to controlled resolver, egress filtering | CSF **DE.CM/PR.IR**; CIS **9** (Email & Web), **13** |
| Network sniffing / data in transit (T1040, T1557) | Encryption-in-transit everywhere: MACsec (L2), IPsec (L3), TLS 1.3 (RFC 8446) at app, mTLS in mesh | CSF **PR.DS**; CIS **3** (Data Protection) |
| Routing abuse — BGP hijack/leak (T1200-adjacent, infra targeting) | RPKI ROV (RFC 6480/6811), prefix/max-prefix filters, BGP TCP-AO, peer authentication | CSF **PR.IR/PR.AA**; CIS **12** |
| Exploitation of network devices / management plane (T1542, T1601, T1556) | Out-of-band mgmt network, jump hosts, hardened device configs, config-as-code drift detection, MFA to control plane | CSF **PR.AA/PR.PS**; CIS **4** (Secure Config), **12** |
| Perimeter/VPN over-reach (initial access via T1133 External Remote Services) | ZTNA/SDP replacing broad VPN; app-specific brokered sessions; posture checks | SP 800-207; SP 800-215; CSF **PR.AA** |
| DDoS / availability (T1498/T1499) | Anycast, scrubbing, rate limiting, ADC health/drain, capacity + QoS scavenger class | CSF **PR.IR/RS**; CIS **13** |
| Discovery via unmonitored flows (TA0007) | Flow telemetry (IPFIX) + analytics as a detection source; least-privilege reachability | CSF **DE.CM**; CIS **13** |

> **Currency note:** ATT&CK technique IDs are stable across versions, but the framework is versioned — the latest confirmed release is **v18 (October 2025)**, which restructured detections into *Detection Strategies* + *Analytics*; a v19 was reported in development. Re-verify technique names and any tactic relabeling against the live source (attack.mitre.org) before publishing downstream, per this library's currency convention.

### 5.2 Design rules that bake in security

1. **Default-deny between zones; least-privilege within.** The flow matrix *is* the firewall policy.
2. **Encrypt in transit at the right layer** — MACsec for L2 links, IPsec for site/cloud, TLS 1.3 / mTLS for apps and mesh. Assume the wire is hostile (zero trust).
3. **Isolate the management plane** (out-of-band) and gate it with MFA + jump hosts. Fabric compromise almost always comes through the control/management plane.
4. **Control name resolution** — one blessed resolver path, protective filtering, logging, and no silent DoH bypass.
5. **Validate routing** — RPKI ROV, prefix filtering, authenticated peering. Treat the routing system as attackable infrastructure.
6. **Segment OT/ICS and IoT** hard (reference the Purdue model / IEC 62443 zones-and-conduits); these estates are fragile and high-impact.
7. **Make egress explicit.** Default-deny outbound with inspected, logged egress points defeats a large fraction of C2 and exfil.
8. **Config as code + drift detection.** Misconfiguration is the top network vulnerability class; automation and review (secure config, CIS Control 4) remove it.
9. **Telemetry feeds detection.** Wire flow/telemetry into the SOC; an invisible network cannot be defended.

### 5.3 Tie-in to the sibling references

This document is the *design* half. Enforcement specifics — firewall architectures (L3/L7/NGFW), IDS/IPS placement, NAC, TLS inspection, DDoS scrubbing, secure service edge policy — live in **NETWORK_SECURITY_ARCHITECTURE**. The enterprise trust model, identity fabric, and how network zones map to data classification and the overall zero-trust strategy live in **SECURITY_ARCHITECTURE**. Keep the three consistent: a zone defined here must have an enforcement point there and a trust tier in the enterprise model.

---

## 6. Standards & frameworks

| Area | Standard / framework | Notes (verify versions against the source) |
|---|---|---|
| Zero trust | **NIST SP 800-207** (Zero Trust Architecture) | The canonical ZTA reference (PDP/PEP model) |
| Enterprise network | **NIST SP 800-215** (Guide to a Secure Enterprise Network Landscape, Nov 2022) | Perimeter dissolution, ZTNA/SDP/micro-seg/SASE |
| Control catalog | **NIST SP 800-53** Rev. 5 | SC (System & Comms Protection) / AC control families |
| Cyber framework | **NIST CSF 2.0** (Feb 2024) | Adds the **Govern** function; map network controls to functions/categories |
| Controls | **CIS Critical Security Controls v8.1** (Jun 2024) | **12** Network Infra Mgmt, **13** Network Monitoring & Defense, **4** Secure Config |
| Threat model | **MITRE ATT&CK** (Enterprise/ICS/Mobile) | Latest confirmed **v18 (Oct 2025)**; verify current version |
| OT/ICS | **IEC 62443**; Purdue reference model | Zones-and-conduits segmentation for OT |
| Payment | **PCI DSS v4.0.1** | Network segmentation to reduce scope; verify current point release |
| EU regulation | **NIS2** | Network/infra security obligations (EU); verify applicability |
| Overlay / fabric | **RFC 7348** (VXLAN), **RFC 7432** (BGP EVPN), **RFC 8365** (EVPN-VXLAN), **RFC 7364/7365** (NVO3) | Data-center overlay control plane |
| Routing | **RFC 4271** (BGP-4), **RFC 6480/6811** (RPKI / origin validation) | Inter-domain routing + route-origin validation |
| Encryption in transit | **IEEE 802.1AE** (MACsec), **IPsec** (RFC 4301 family), **TLS 1.3** (RFC 8446) | L2 / L3 / L7 respectively |
| Access control (L2) | **IEEE 802.1X** (port-based NAC), **802.1Q** (VLAN) | Access-layer identity + segmentation |
| IPv6 | **RFC 8200** | Core IPv6 spec |
| Secure DNS | **DNSSEC** (RFC 4033–4035), **DoT (RFC 7858)**, **DoH (RFC 8484)** | Integrity + encrypted resolution |
| Design methodology | Cisco/vendor validated designs, **AWS/Azure/GCP Well-Architected** (networking pillars) | Vendor-specific but useful reference designs |

---

## 7. Anti-patterns & pitfalls

- **The flat network.** One big L2 domain / VLAN where everything can reach everything. Guarantees unimpeded lateral movement; the single most common root cause of ransomware spread.
- **Perimeter-only / "crunchy outside, soft inside."** Hard edge firewall, no internal segmentation. Fails the moment one endpoint is compromised.
- **VLAN sprawl as segmentation.** VLANs are broadcast-domain tools, not security boundaries — without enforced inter-VLAN policy they segment nothing.
- **Spreadsheet IPAM / tribal addressing.** Overlaps, shadow subnets, and merger collisions. No automation can rest on a spreadsheet.
- **Flat, overlapping routing without summarization.** Huge routing tables, slow convergence, ACLs that can't express zones cleanly.
- **Management plane on the data plane.** In-band management means one data-plane compromise owns the fabric. Always out-of-band.
- **Snowflake configs / no config-as-code.** Hand-cut device configs drift, can't be audited, and are where exploitable misconfigurations live.
- **Unmanaged IPv6.** IPv6 enabled by default on hosts with no ACLs, no logging, no RA Guard — a wide-open covert path alongside a locked IPv4 door.
- **Permissive egress.** "Allow any outbound" — the open door for C2 and exfiltration.
- **Overlay without MTU planning.** VXLAN/Geneve encap overhead ignored → fragmentation, black-holed flows, maddening intermittent failures.
- **VPN as the only remote access.** Broad network reachability for every remote endpoint; migrate to ZTNA.
- **DNS as an afterthought.** Single resolver, no protective filtering, uncontrolled DoH bypass, no logging — blind to a huge class of attacks.
- **No telemetry.** You can't secure, size, or troubleshoot what you can't see. Flow + state telemetry is table stakes.
- **Chasing "single pane of glass" over correctness.** Tooling convergence is good; don't let a product roadmap dictate a topology your flows don't need.
- **Resilience by hope.** Redundancy never tested under failure; untested failover is a planned outage.

---

## 8. Maturity / checklist

Use as a scorecard. **Level 1** = reactive/ad hoc, **Level 3** = defined & automated, **Level 5** = optimizing (intent-based, continuously verified).

| Domain | L1 (ad hoc) | L3 (defined/automated) | L5 (optimizing) |
|---|---|---|---|
| Topology | Accreted, flat spots | Documented reference designs per site type | Intent-based, replicated pods/landing zones |
| Addressing/IPAM | Spreadsheet | DDI as source of truth, hierarchical plan | Fully automated allocation + reconciliation |
| Fabric/overlay | STP-bound L2 | Clos + VXLAN/EVPN where warranted | Automated multi-tenant provisioning |
| Segmentation | Perimeter only | Macro zones, default-deny between | Micro-segmentation + ZTNA on crown jewels/OT |
| Remote access | VPN, broad reach | Posture-checked VPN + some ZTNA | ZTNA/SASE app-brokered default |
| DNS | Host-chosen, no filtering | Centralized protective resolvers + logging | Threat-intel RPZ, DoH control, anycast HA |
| Routing security | None | Prefix filters + peer auth | RPKI ROV + continuous validation |
| Encryption in transit | Edge only | IPsec site/cloud + TLS to apps | MACsec + mTLS mesh, pervasive |
| Management plane | In-band | Out-of-band + jump hosts | OOB + MFA + just-in-time, audited |
| Config lifecycle | Hand-cut | Config as code + review | Drift detection + auto-remediation |
| Observability | SNMP up/down | Flow + streaming telemetry | Telemetry → SOC detection + capacity analytics |
| IPv6 | Unmanaged/default | Dual-stack with parity controls | IPv6-first with full security parity |
| Resilience | Untested | Tested failover, known convergence | Chaos-tested, measured blast radius |

**Fast triage checklist (answer honestly):**

- [ ] Can you produce a current flow matrix and a single-source-of-truth address plan?
- [ ] Is the management plane out-of-band and MFA-gated?
- [ ] Is there default-deny between trust zones, and micro-segmentation on crown jewels / PCI / OT?
- [ ] Is egress default-deny with inspected, logged exits?
- [ ] Is there one controlled resolver path with protective filtering and logging (and is unauthorized DoH blocked)?
- [ ] Is routing authenticated and origin-validated (RPKI)?
- [ ] Is traffic encrypted in transit at the appropriate layer end-to-end?
- [ ] Are device configs code, reviewed, and drift-detected?
- [ ] Does flow/telemetry reach the SOC as a detection source?
- [ ] Is IPv6 secured to the same standard as IPv4?
- [ ] Have you tested failover and measured blast radius and convergence?

---

## 9. Tools & further reading

**Categories (vendor-neutral; examples are illustrative, not endorsements):**

- **DDI (DNS/DHCP/IPAM):** Infoblox, BlueCat, EfficientIP, open-source (ISC BIND/Kea, NetBox as IPAM/source-of-truth).
- **Fabric / SDN / overlay:** EVPN/VXLAN on any merchant-silicon switching; Cisco ACI, Arista EOS/CVP, Juniper Apstra, VMware NSX, Nokia SR Linux — compare on automation and overlay model.
- **SD-WAN / SASE / SSE:** evaluate against the Gartner **SASE Platforms** and **SSE** market definitions; score on convergence, PoP coverage, and single policy plane (verify current reports/positions).
- **Network automation / config-as-code:** Ansible, Nornir, Terraform (cloud networking), Batfish (config analysis / pre-change validation), Git-driven CI.
- **Observability:** flow (IPFIX/NetFlow/sFlow collectors), streaming telemetry (gNMI), packet brokers, synthetic monitoring, and NDR platforms that turn flow into detection.
- **Micro-segmentation / ZTNA:** host-agent segmentation, Kubernetes NetworkPolicy + CNI (Cilium/Calico), service mesh (mTLS), identity-aware proxies.
- **Routing security:** RPKI validators (Routinator, rpki-client), IRR tooling, BGP monitoring.
- **Testing/validation:** network emulation (Containerlab, GNS3/EVE-NG), chaos/failure injection, pre-deployment config analysis.

**Authoritative reading (fetch current versions):**

- NIST **SP 800-207** Zero Trust Architecture; **SP 800-215** Guide to a Secure Enterprise Network Landscape; **SP 800-53** Rev. 5.
- **NIST CSF 2.0** and **CIS Critical Security Controls v8.1**.
- **MITRE ATT&CK** (Enterprise / ICS) — map your network controls to techniques; verify current version.
- IETF RFCs: **7348** (VXLAN), **7432/8365** (EVPN), **7364/7365** (NVO3), **4271** (BGP), **6480/6811** (RPKI), **8200** (IPv6), **8446** (TLS 1.3), **7858/8484** (DoT/DoH), **4033–4035** (DNSSEC).
- **IEC 62443** + Purdue model for OT/ICS segmentation.
- Cloud networking well-architected / landing-zone guidance (AWS, Azure, GCP).

**Sibling references in this library:** **NETWORK_SECURITY_ARCHITECTURE** (enforcement: firewalls, IDS/IPS, NAC, TLS inspection, DDoS, secure service edge policy), **SECURITY_ARCHITECTURE** (enterprise trust model, identity fabric, data-classification-to-zone mapping), and the **CLOUD_ARCHITECTURE** / **AI_ARCHITECTURE** references for domain-specific network considerations.

---

*Vendor-neutral reference. Named products are examples, not endorsements. Verify all framework versions, standard numbers, and vendor/market naming against the authoritative source before relying on them — the networking and security framework landscape moves faster than any static document.*
