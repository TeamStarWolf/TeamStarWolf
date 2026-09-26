# Edge & Network Device Security Reference

> **The network edge is where mass exploitation now happens — and the playbook for defending it is public.** [CISA](https://www.cisa.gov/resources-tools/resources/guidance-and-strategies-protect-network-edge-devices) and its international partners have built a guidance stack specifically for the device class that keeps producing emergency directives: [BOD 23-02](https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02) (get management interfaces off the internet), a four-publication joint edge-device series (February 2025), NSA's Network Infrastructure Security Guide, KEV-driven patch prioritization under [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), and end-of-support replacement guidance. This reference assembles that material into a defensive program for VPN concentrators, firewalls, load balancers, routers, and mail/file-transfer gateways.

Edge devices are the rare asset class where the attacker's advantages are **structural**, not situational: internet-facing by definition, unable to run EDR, opaque to their owners, and positioned where all the traffic and credentials flow. The 2023–2026 record — Ivanti, Citrix, Cisco, Fortinet, Palo Alto, F5, MOVEit-class transfer appliances — is not a run of bad luck at individual vendors; it is what happens when a whole device class combines high privilege with low observability. The defensive answer is likewise structural: shrink what is exposed, isolate the management plane, patch to KEV on a real SLA, demand integrity evidence, log off-box, replace what is end-of-support, and instrument the network *around* the box you cannot instrument.

Attacker behavior here is described in the language public advisories use; defender actions are described concretely. Exploitation mechanics belong to the advisories, not this document.

**Related:** [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [CVE Reference](CVE_REFERENCE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) · [Network Monitoring](NETWORK_MONITORING_REFERENCE.md) · [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md)

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **Segmentation, DMZ design, firewall policy** | [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) |
| **KEV/EPSS/CVSS mechanics and patch prioritization** | [CVE Reference](CVE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) |
| **NetFlow, Zeek, beaconing and DNS analytics** | [Network Monitoring](NETWORK_MONITORING_REFERENCE.md) · [Network Defense](NETWORK_DEFENSE_REFERENCE.md) |
| **Incident response procedure when a device is compromised** | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |
| **Embedded/firmware threat modeling below the appliance OS** | [Firmware & IoT Security](FIRMWARE_IOT_SECURITY_REFERENCE.md) · [EMB3D Reference](EMB3D_REFERENCE.md) |
| **The edge-device program itself** — exposure, isolation, SLAs, integrity, logging, EOL, detection, procurement | **This document** |

"Edge device" here follows the definitions the guidance uses. BOD 23-02 scopes **routers, switches, firewalls, VPN concentrators, proxies, load balancers, and out-of-band server management interfaces** (iLO, iDRAC). CISA's 2025 edge-guidance landing page adds **VPN gateways, IoT devices, internet-facing servers, and internet-facing OT systems**. Practitioner shorthand: anything that terminates untrusted traffic and cannot run your endpoint agent.

---

## Why edge devices are structurally attractive targets

Every property below is inherent to the device class — which is why the fixes are architectural and programmatic, not per-CVE.

| Structural property | Why it favors the attacker | Program answer (below) |
|---|---|---|
| **Internet-facing by definition** | The device exists to accept connections from anywhere; reconnaissance is trivial and continuous | Inventory/EASM; expose only what must be exposed |
| **No EDR, no agents** | Closed appliance OS; the defender's best telemetry source cannot be installed on the asset most under attack | Off-box logging; egress and adjacent-network monitoring |
| **Opaque platform** | Owners cannot list processes, inspect the filesystem, or verify binaries; vendor tooling is the only lens | Integrity checking; forensic readiness; procurement pressure |
| **Privileged position** | Terminates VPNs and TLS, holds credentials/certificates/session tokens, sits on the path to everything internal | Management-plane isolation; credential/session revocation plans |
| **Identity shortcut** | A compromised VPN/SSO-integrated gateway yields authenticated access without malware on any endpoint | Phishing-resistant MFA; session monitoring downstream |
| **Patching friction** | Maintenance windows, HA pairs, and "it's the firewall" caution stretch exposure windows for exactly the CVEs attackers automate | KEV-keyed SLAs; emergency-directive-speed playbooks |
| **Long, quiet lifespans** | Devices run for years past end-of-support, unpatched and forgotten | EOL replacement policy |

Two advisory-record observations frame the urgency. First, [AA24-317A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-317a) (November 2024) found that the **majority of 2023's most routinely exploited vulnerabilities were first exploited as zero-days** — up from less than half in 2022 — and its 15 top plus 32 additional CVEs include repeat entries for the edge vendors Citrix, Cisco, Fortinet, and Ivanti — though mainstream software vendors such as Atlassian and Microsoft appear just as often. (No official CISA statistic breaks KEV down by "edge device" as a class, and the advisory's product mix shows edge products as prominent, not dominant; the concentration is clearest in the emergency-directive record below, and should be cited that way.) Second, zero-day-majority exploitation means **patch speed alone cannot be the whole program** — the architecture has to assume a window in which the device is exploitable and nobody knows yet.

---

## The exploitation record, 2023–2026

Advisory-level only: what CISA directives, joint advisories, and the KEV catalog documented, with no exploit mechanics. Full citations in [Sources](#sources).

### Timeline of headline edge CVEs (KEV `dateAdded`, official feed)

| KEV added | CVE | Product | Documented in |
|---|---|---|---|
| **2023-07-19** | CVE-2023-3519 | Citrix NetScaler ADC/Gateway | KEV |
| **2023-10-16** | CVE-2023-20198 | Cisco IOS XE web UI | KEV (4-day due date) |
| **2023-10-18** | CVE-2023-4966 | Citrix NetScaler ("Citrix Bleed") | AA23-325A (LockBit 3.0 affiliates) |
| **2023-10-31** | CVE-2023-46747 | F5 BIG-IP | KEV |
| **2024-01-10** | CVE-2023-46805 · CVE-2024-21887 | Ivanti Connect Secure / Policy Secure | ED 24-01, AA24-060B |
| **2024-04-12** | CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect | KEV + Palo Alto PSIRT (no AA-series advisory) |
| **2024-04-24** | CVE-2024-20353 · CVE-2024-20359 | Cisco ASA ("ArcaneDoor") | KEV |
| **2024-10-23** | CVE-2024-47575 | Fortinet FortiManager | KEV + Fortinet PSIRT |
| **2025-01-08** | CVE-2025-0282 | Ivanti Connect Secure | KEV |
| **2025-01-14** | CVE-2024-55591 | Fortinet FortiOS | KEV + Fortinet PSIRT (no AA-series advisory) |
| **2025-04-04** | CVE-2025-22457 | Ivanti Connect Secure | KEV |
| **2025-09-25** | CVE-2025-20333 · CVE-2025-20362 | Cisco ASA/Firepower | ED 25-03 (**1-day** KEV due date) |

(Dates are the official feed's `dateAdded` values. The MOVEit Transfer campaign — CVE-2023-34362, exploitation beginning May 27, 2023 — predates this table's window of headline *appliance* entries and is covered in the case studies below.)

### Case studies the directives wrote for you

**Ivanti Connect Secure, January–February 2024 — the "assume compromise" template.** [ED 24-01](https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities) (January 19, 2024) ordered FCEB mitigation of CVE-2023-46805/CVE-2024-21887. [Supplemental Direction V1](https://www.cisa.gov/news-events/directives/supplemental-direction-v1-ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure) (January 31) went further than any prior appliance directive: **disconnect every instance by 11:59 PM on February 2, 2024**; before reconnection, factory-reset and rebuild on a supported version, and **revoke and reissue all certificates, keys, and passwords** on or connected to the device; assume connected domain accounts were compromised (double password reset by March 1, 2024). Supplemental V2 followed February 9. Then [AA24-060B](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b) (February 29, 2024; CISA, FBI, MS-ISAC, ACSC, NCSC-UK, CCCS, NCSC-NZ, CERT-NZ) documented the deeper problem: actors **deceived Ivanti's internal and external Integrity Checker Tool (ICT)** and, in lab conditions, could retain root-level persistence **through factory resets**. That advisory is the definitive public case study on the limits of vendor integrity checking.

**MOVEit Transfer, mid-2023 — the file-transfer-appliance business model.** [AA23-158A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) (June 7, 2023): CL0P/TA505 exploited a SQL-injection zero-day (CVE-2023-34362) in Progress MOVEit Transfer beginning May 27, 2023, deploying the LEMURLOOT web shell for mass data theft — extortion without encryption, at internet scale, against a device whose entire job is holding other organizations' files. The same pattern (internet-facing managed file transfer as a data-theft one-stop) is why transfer appliances belong in the edge program even though they are "servers".

**Citrix Bleed, late 2023 — the session-token lesson.** [AA23-325A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) (November 21, 2023): LockBit 3.0 affiliates exploited CVE-2023-4966 on NetScaler ADC/Gateway to steal legitimate session tokens, **bypassing passwords and MFA via session hijacking**. Defender consequence: after patching a session-theft CVE, unpatched-window sessions remain live weapons until terminated — patch, then **kill and reissue sessions**, then hunt for reuse.

**Volt Typhoon — why the telemetry gap matters.** [AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) (February 7, 2024) documents PRC state-sponsored actors maintaining access to U.S. critical infrastructure for **at least five years**, living off the land, with compromised edge and SOHO devices among the footholds and proxies. Five years of dwell is what "the appliance can't tell you anything" looks like at national scale.

**ArcaneDoor and ED 25-03 — persistence below the OS.** [ED 25-03](https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices) (September 25, 2025) addressed CVE-2025-20333/CVE-2025-20362 on Cisco ASA/Firepower — a campaign Cisco links to ArcaneDoor, including **ROM manipulation that persists through reboot and system upgrade**. Agencies had to inventory all in-scope devices and **transmit memory/core dumps to CISA for forensic analysis by September 26** — a one-day forensic tasking, which only organizations with prior appliance-forensics readiness could meet calmly.

**F5 and ED 26-01 — the vendor itself as edge risk.** [ED 26-01](https://www.cisa.gov/news-events/directives/ed-26-01-mitigate-vulnerabilities-f5-devices) (October 15, 2025) responded to F5's disclosure that a nation-state actor had **long-term persistent access to its BIG-IP development environment** and exfiltrated source code and information about undisclosed vulnerabilities. Agencies had to inventory in-scope F5 products (F5OS, BIG-IP TMOS and Virtual Edition, BIG-IP Next, BIG-IQ, BNK/CNF), check whether management interfaces were internet-accessible, apply updates by October 22, 2025 (October 31 for remaining in-scope F5 devices), and report by October 29 and December 3. The supply chain of the edge device is part of its attack surface.

**Flax Typhoon / "Raptor Train" — where end-of-life devices go.** The September 18, 2024 joint advisory (FBI, CNMF, NSA and allies) describes a botnet operated through China-based Integrity Technology Group comprising **260,000+ compromised SOHO routers, firewalls, NAS, and IoT devices as of June 2024**. Unmanaged and end-of-support edge devices do not just endanger their owners — they become attack infrastructure aimed at everyone else.

> **What the record teaches, compressed:** exploitation is fast (1–4 day KEV due dates), often zero-day first (AA24-317A), reaches below the OS (ED 25-03), survives factory resets in the worst case (AA24-060B), defeats MFA by stealing what MFA already blessed (AA23-325A), and extends into the vendor's own network (ED 26-01). Every program section below exists because one of these happened.

---

## The guidance stack

| Instrument | Issued / current | One-line role |
|---|---|---|
| **[BOD 23-02](https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02)** — Mitigating the Risk from Internet-Exposed Management Interfaces | June 13, 2023 (in force) | Management interfaces: off the internet or behind a Zero Trust policy enforcement point, within 14 days of identification |
| **[BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)** — Prioritizing Security Updates Based on Risk | June 10, 2026 (supersedes BOD 22-01 and BOD 19-02) | Current FCEB remediation-SLA model: four risk factors, 3-day worst-case tier; KEV carries forward |
| **[Joint edge-device guidance series](https://www.cisa.gov/resources-tools/resources/guidance-and-strategies-protect-network-edge-devices)** (4 publications) | February 4, 2025 | Threats, mitigations, and forensics/logging expectations for edge devices — operator and manufacturer editions |
| **[NSA Network Infrastructure Security Guide](https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003018261/)** (CTR) | Ver. 1.2, October 2023 update | Hardening reference: architecture/segmentation, centralized AAA, remote logging, remote-administration hardening, routing, interface/port security |
| **[Reducing the Attack Surface for End-of-Support Edge Devices](https://www.cisa.gov/resources-tools/resources/reducing-attack-surface-end-support-edge-devices)** | February 5, 2026 (CISA with FBI and NCSC-UK) | Inventory with support-timeline review; replace end-of-support devices promptly |
| **[Secure by Design pledge](https://www.cisa.gov/securebydesign/pledge)** | Announced May 2024 | Voluntary manufacturer commitments (seven goals) — procurement leverage, not compliance |
| **Emergency directives** (ED 24-01, ED 25-03, ED 26-01) | 2024–2025 | Incident-driven orders; read them as rehearsal scripts for your own worst week |

### The February 2025 four-publication series

Announced [February 4, 2025](https://www.cisa.gov/news-events/alerts/2025/02/04/cisa-partners-asds-acsc-cccs-ncsc-uk-and-other-international-and-us-organizations-release-guidance) by CISA with ASD's ACSC, CCCS, NCSC-UK, and other partners — the first coordinated international guidance aimed at edge devices as a class:

| Publication | Lead | Audience & content |
|---|---|---|
| **Security Considerations for Edge Devices** (ITSM.80.101) | CCCS (Canada) | Real-world edge compromises, threat overview, mitigations for administrators, secure-by-design recommendations for manufacturers |
| **Guidance on digital forensics and protective monitoring specifications for producers of network devices and appliances** | NCSC-UK | What producers should ship: security logging **by default** (authentication attempts, process creation/termination, configuration and firmware changes, DNS queries), near-real-time standards-based remote logging over TLS, and volatile + non-volatile forensic data collection **without extra licenses** |
| **Mitigation Strategies for Edge Devices: Executive Guidance** | ASD ACSC | Board/executive framing of the edge problem |
| **Mitigation Strategies for Edge Devices: Practitioner Guidance** | ASD ACSC | Seven mitigation strategies detailed for operational, procurement, and cybersecurity staff |

(Title note: CISA's announcement lists the NCSC-UK document under a variant title, "Digital Forensics Monitoring Specifications for Products of Network Devices and Applications"; the title above is NCSC-UK's own.)

**How to use the stack:** BOD 23-02 and BOD 26-04 bind only U.S. FCEB agencies — but they are free, evidence-driven policy templates. Adopt their requirements as internal policy with your own dates, and use the ED series as tabletop scenarios.

---

## Program: inventory and attack-surface management of the edge

You cannot isolate, patch, or replace what you have not enumerated — and BOD 23-02's enforcement mechanism is the model: **CISA scans FCEB agencies for in-scope interfaces and notifies them**, starting the 14-day clock. Run the same loop against yourself before someone else does.

**Do**
- Maintain a dedicated **edge inventory**: every internet-facing or traffic-terminating device with vendor, product, version, serial, physical/cloud location, owner, support/EOS date, management-interface address, and exposure status. This is the working set for every section below and the input to your [CTEM](CTEM_REFERENCE.md) scoping.
- Run **external attack-surface scanning (EASM)** continuously against your own ranges and cloud tenants; alert on any newly reachable management port, admin panel, or API. Compare against the inventory — a hit with no inventory entry is a shadow device, the worst kind.
- Enumerate the **out-of-band interfaces** (iLO, iDRAC, and equivalents) — BOD 23-02 scopes them explicitly because they are full device control and routinely forgotten.
- Include **third-party-hosted and MSP-managed** devices; BOD 23-02 applies to FCEB systems hosted by third parties, and your policy should too.
- Diff the inventory against the **KEV feed** (see the [CVE Reference](CVE_REFERENCE.md)) and against vendor PSIRT feeds for your specific products automatically.
- Treat an ED-style inventory tasking as a drill: ED 26-01 gave agencies days to inventory all F5 devices and report. Time yourself.

**Don't**
- Trust the network team's spreadsheet as the inventory of record without external-scan validation.
- Scope only "firewalls and VPNs" — transfer appliances, mail gateways, load balancers, and internet-facing OT gear carry the same structural properties.
- Let discovery findings age: a management interface visible from the internet is a 14-day-clock item under the BOD 23-02 model, not a backlog ticket.

---

## Program: management-plane isolation

BOD 23-02 defines the target precisely. A **networked management interface** is a dedicated device interface, reachable over network protocols, meant exclusively for authorized users to perform administrative activities on a device, group of devices, or the network itself. The directive gives two compliant end-states, due **within 14 days** of CISA notification or agency discovery:

1. **Remove the interface from the internet** — reachable only from an internal enterprise network (CISA recommends an isolated management network); or
2. **Protect it with Zero Trust capabilities** that enforce access control **through a policy enforcement point separate from the interface itself** — aligned with OMB M-22-09, NIST SP 800-207, TIC 3.0, and CISA's Zero Trust Maturity Model.

Note what is *not* compliant on its own: a strong password, MFA on the appliance's own login page, or an ACL evaluated by the vulnerable device itself. The enforcement point must be **separate**, because the lesson of the exploitation record is that the interface's own code is the thing being exploited.

### Reference topology

```
  INTERNET                        DATA PLANE                        INTERNAL
     │                                                              NETWORKS
     │        ┌──────────────┐        ┌──────────────┐
     ├───────►│ VPN gateway / ├──────►│  Firewall /   ├──────►  users, servers
     │        │ load balancer │       │  router       │
     │        └──────┬───────┘        └──────┬───────┘
     │               │ mgmt NIC              │ mgmt NIC
     x  (no route)   ▼                       ▼
        ┌─────────────────────────────────────────────────┐
        │        OUT-OF-BAND MANAGEMENT NETWORK           │
        │  dedicated VLAN/VRF or physical net — no route  │
        │  to/from the internet or the general user LAN   │
        │                                                 │
        │   jump host (PAW) ── MFA ── PEP/bastion         │
        │   AAA (TACACS+/RADIUS ×2) · syslog/SIEM ·       │
        │   config backup · NTP                           │
        └─────────────────────────────────────────────────┘
```

This matches NSA's Network Infrastructure Security Guide (Ver. 1.2, October 2023), which pairs segmentation with **centralized AAA (at least two AAA servers)**, remote logging, and hardened remote administration for network devices.

**Do**
- Put every appliance management interface on a **dedicated management VLAN/VRF** (or physically separate network) with no default route to the internet and no reachability from the general user LAN.
- Front administrative access with a **bastion/jump host or ZTNA policy enforcement point**, with phishing-resistant MFA, per-admin accounts via centralized AAA (TACACS+/RADIUS against at least two servers per the NSA guide), and full session logging.
- Disable management protocols on data-plane interfaces where vendors allow it; restrict source addresses where they don't.
- Prefer **out-of-band** management paths that survive a compromise or misconfiguration of the data plane — the ED 25-03 forensic tasking assumed you could still reach the device safely.
- Apply the same rules to **cloud-hosted virtual appliances**: a management interface on a public IP with a security-group hole is exactly the BOD 23-02 finding, in cloud form.

**Don't**
- Count "HTTPS admin page with a strong password and MFA" as isolation — the PEP must be separate from the interface.
- Leave vendor cloud-management planes and phone-home channels out of scope: inventory them, restrict them, and log them.
- Allow admin workstations that browse the web and read email to also SSH into the management VLAN; use privileged access workstations ([IAM Reference](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)).
- Forget that BOD 23-02 also scopes **switches and proxies** — "edge" isolation habits belong on internal network devices too.

---

## Program: patch SLAs keyed to KEV (BOD 26-04 risk tiers)

The [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities) is the floor for edge patching: every entry has an assigned CVE, **reliable evidence of active exploitation**, and clear remediation guidance. As of catalog version **2026.09.24** it holds **1,723 entries, 361 of them flagged as known ransomware-campaign use**.

Since **June 10, 2026**, the FCEB SLA model is [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) — it superseded and revoked BOD 22-01 (and BOD 19-02), while the KEV catalog and its criteria carry forward. BOD 26-04 replaces the flat "KEV = fix by due date" scheme with four risk factors:

| Factor | Question |
|---|---|
| **Asset exposure** | Is the asset publicly exposed? |
| **KEV status** | Is the vulnerability in the KEV catalog? |
| **Exploit automation** | Is exploitation automatable at scale? |
| **Technical impact** | Partial or total control of the asset? |

Worst case — **publicly exposed + KEV + automatable + total control** — requires remediation in **3 days plus forensic triage**; the remaining tiers run 3, 14, or 60 days down to "fix on system upgrade". Implementation is phased: policy and KEV-monitoring updates take effect immediately (Phase I), process updates are due within 60 days (Phase II), and the full Table 1 remediation timelines apply within 180 days (Phase III, by December 7, 2026).

**Read the table as an edge-device verdict.** An internet-facing VPN gateway or firewall with a KEV-listed RCE hits every factor: it *is* publicly exposed, exploitation of this class is routinely automated (AA24-317A), and control is total. Edge devices land in the fastest tier almost by definition — and the directive's "plus forensic triage" codifies the other lesson of the record: at edge speed, **patching is also a compromise-assessment trigger**, never just maintenance. Emergency directives compress even this: CVE-2025-20333/20362 carried a **1-day** KEV due date; CVE-2023-20198 got 4 days.

**Do**
- Adopt BOD 26-04's factors as your internal tiering even if you are not FCEB; pre-approve emergency change paths so a 3-day (or 1-day) fix does not need a CAB meeting.
- Track **KEV-flagged, internet-facing, ransomware-flagged** as your top queue — the 361-entry ransomware subset is the highest-signal slice (see [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md)).
- Subscribe to vendor PSIRT feeds for your exact products; PAN-OS CVE-2024-3400 and FortiOS CVE-2024-55591 were documented through KEV plus vendor PSIRT advisories, with no AA-series joint advisory to wait for.
- Pair every emergency patch on an edge device with the vendor's compromise-assessment steps and session/credential hygiene (Citrix Bleed: patch, then terminate sessions).
- Measure **MTTR for KEV-listed edge CVEs** as its own metric ([Security Metrics](SECURITY_METRICS_REFERENCE.md)).

**Don't**
- Key SLAs to CVSS base scores; KEV membership plus exposure beats severity arithmetic for this device class.
- Cite BOD 22-01's due-date scheme as current policy — it has been revoked; KEV due dates still appear in the feed, but the FCEB clock is BOD 26-04's.
- Treat vendor mitigations ("disable feature X") as the finish line; they are dwell-time reducers until the fixed version is on.

### KEV vendor counts — context, with a caveat

Per-vendor KEV entry counts, computed from the official feed at version 2026.09.24, **across all product lines** — Cisco's figure includes IOS/switch CVEs, Ivanti's includes Endpoint Manager, and so on. There is **no official CISA breakdown of KEV by device class**; this table shows why edge-heavy vendors dominate your patching calendar, not an "edge CVE count".

| Vendor | KEV entries | Vendor | KEV entries |
|---|---|---|---|
| **Cisco** | 99 | **Zyxel** | 13 |
| **Ivanti** | 35 | **Progress** | 9 |
| **Fortinet** | 30 | **F5** | 8 |
| **D-Link** | 26 | **Juniper** | 8 |
| **Citrix** | 24 | **Sophos** | 7 |
| **SonicWall** | 19 | **Check Point** | 5 |
| **Palo Alto Networks** | 15 | **Cleo** | 2 |

---

## Program: integrity checking and compromise assessment

An appliance cannot host your EDR, so "is this device still ours?" has exactly three answer sources: vendor integrity tooling, off-box forensics, and behavioral evidence from the surrounding network. Plan for all three, because the first one has documented limits.

**The category example: Ivanti's ICT.** Ivanti ships internal and external Integrity Checker Tools for Connect Secure — the most prominent vendor-provided appliance integrity mechanism. AA24-060B documents that threat actors **deceived both the internal and external ICT**, and that root-level persistence could survive factory resets; Ivanti responded in February 2024 with an [enhanced external ICT](https://www.ivanti.com/blog/enhanced-external-integrity-checking-tool-to-provide-additional-visibility-and-protection-for-customers-against-evolving-threat-actor-techniques-in-relation-to-previously-disclosed-vulnerabilities). Both facts matter: **run the vendor's integrity tooling** (it raises attacker cost and catches real compromises), and **never let a clean result be your only evidence** (a negative from a tool the advisory record shows being evaded is weak evidence of absence).

**Do**
- For every edge product you own, write down *before you need it*: what integrity/compromise-assessment tooling the vendor provides, how to run it safely, what a clean vs. dirty result looks like, and the vendor PSIRT/support escalation path.
- Run vendor integrity checks on a schedule and after every relevant advisory — not only when compromise is suspected.
- Adopt the **ED 24-01 Supplemental V1 rebuild standard** as your worst-case playbook: disconnect; factory-reset and rebuild on a supported version; **revoke and reissue every certificate, key, and password** on or connected to the device; assume credentials that transited it are compromised and reset them (double reset for domain accounts, per the directive).
- Plan for **below-the-OS persistence**: ED 25-03's ArcaneDoor-linked campaign included ROM manipulation persisting through reboot **and upgrade** — meaning "we upgraded it" is not eradication evidence for the worst cases. Know your vendor's guidance for firmware-level verification and when the answer is hardware replacement.
- Capture forensic artifacts (memory/core dumps, logs, config) **before** rebuilding, per the forensic readiness section below — the rebuild destroys the evidence.

**Don't**
- Equate "factory reset" with "clean" — AA24-060B is the counterexample.
- Skip credential/session revocation after rebuild; the device's secrets outlive the device's compromise.
- Accept a vendor integrity tool that only runs on-box: the external/offline variant exists precisely because a compromised OS can lie about itself.

---

## Program: logging and forensic readiness for appliances

The NCSC-UK-led forensics publication in the February 2025 series tells **producers** what to ship: security logging on by default (authentication attempts, process creation/termination, configuration and firmware changes, DNS queries), near-real-time standards-based remote logging over TLS, and collection of volatile and non-volatile forensic data without additional licenses. Until your vendors deliver all of that, the operator's job is to capture everything the platform *can* emit — **off the box, immediately** — because on a compromised appliance, local logs are attacker-editable and often lost at reboot.

| Readiness element | Concretely |
|---|---|
| **Remote syslog for everything** | All appliance log streams (admin auth, VPN/session events, config audit, system/crash) to the SIEM over TLS in near-real time; alert on the stream going quiet |
| **Config change capture** | Automated config backup and diff on every change; alert on out-of-window changes — configuration history is both detection signal and forensic timeline |
| **AAA command accounting** | Per-admin accounts through centralized AAA with command accounting (NSA guide: at least two AAA servers); local accounts are break-glass only, vaulted and alarmed |
| **Session/tunnel metadata** | VPN and admin session records (who, from where, when, how long) retained long enough to answer a Citrix-Bleed-style "which sessions were stolen?" question months later |
| **Crash/core dump procedure** | Documented, rehearsed steps to capture memory/core dumps per vendor guidance — ED 25-03 gave agencies about one day to produce them |
| **Time sync** | NTP across every device; unsynchronized clocks quietly destroy cross-device forensic timelines |
| **Evidence-first IR order** | For a suspected-compromised appliance: isolate (don't power off), capture volatile data per vendor/[DFIR](DIGITAL_FORENSICS_REFERENCE.md) guidance, preserve logs off-box, *then* remediate |

**Retention note:** edge compromises are discovered late — Volt Typhoon's documented dwell was years, not days. Size appliance-log retention to a long-dwell assumption, not a 30-day default.

---

## Program: end-of-support replacement policy

The current reference is [Reducing the Attack Surface for End-of-Support Edge Devices](https://www.cisa.gov/resources-tools/resources/reducing-attack-surface-end-support-edge-devices) (February 5, 2026, published by CISA with the FBI and NCSC-UK): maintain an asset inventory with **support-timeline review**, **replace end-of-support edge devices promptly**, and keep devices that cannot yet be replaced on the latest supported software — because end-of-support devices no longer receive patches and are actively targeted, including by nation-state actors. The Flax Typhoon botnet advisory is the same point from the attacker's side: 260,000+ compromised routers, firewalls, NAS, and IoT devices, drawn heavily from the unmanaged and aging end of the ecosystem.

**Do**
- Record **end-of-sale, end-of-support, and end-of-security-maintenance dates** in the edge inventory the day a device is deployed; review the timeline column quarterly and budget replacements 12–18 months ahead of EOS.
- Treat KEV's remediation logic as policy: for end-of-life products, KEV's own guidance is **removal**, not mitigation.
- For devices that genuinely cannot be replaced on schedule: latest supported software, management-plane isolation, tightened exposure, compensating monitoring — documented as a time-boxed, owner-signed risk acceptance, not a quiet default.
- Extend the policy to the small stuff: SOHO-class routers at branch offices and home offices of privileged users are exactly the Raptor Train recruitment pool.

**Don't**
- Let "it still passes traffic" defer replacement — the device's job is not the risk; its patchability is.
- Buy a refurbished/gray-market appliance without verifying its support entitlement and firmware provenance.
- Decommission without ceremony: wipe configs and credentials, revoke its certificates, and remove it from DNS, monitoring, and the inventory — a half-decommissioned edge device is a future shadow asset.

---

## Detection: what appliance telemetry can and cannot give you

Design detection around an honest capability table, then compensate for the right column with the egress monitoring section below.

| The appliance usually CAN give you | The appliance usually CANNOT give you |
|---|---|
| Admin authentication successes/failures | Process-level telemetry (EDR-grade process creation, memory) |
| Configuration change events (if audit logging is on) | Integrity self-attestation you can trust when the OS is compromised (AA24-060B) |
| VPN/session establishment and teardown records | Visibility into ROM/bootloader tampering (ED 25-03) |
| System events: reboots, upgrades, crashes, HA failovers | Logs it never emitted — or that died with the reboot, if you didn't ship them off-box |
| Traffic logs / NetFlow for transiting traffic | Reliable reporting of **its own** outbound connections once compromised |
| SNMP health and interface counters | A hunting shell for your responders |

**High-signal analytics from the left column** (wire the alerts to humans):

- Administrative login to any edge device **from outside the management network** — should be structurally impossible after BOD-23-02-style isolation; page on it.
- Configuration change **without a matching change ticket**, or from an unexpected source/account; new local admin accounts on the appliance.
- **Logging stops**: a syslog stream going quiet is both an outage and a known tampering indicator.
- Unexpected reboots, unscheduled firmware/OS changes, integrity-check failures, HA failovers without cause.
- VPN authentication anomalies: logins without expected MFA context, impossible travel, one account from many sources, or session reuse patterns after a session-theft CVE (AA23-325A's lesson).

### Editorial ATT&CK anchors for edge-device detection

**Author's editorial mapping — not an official artifact.** No published MITRE or CISA mapping defines "edge device class" → ATT&CK techniques; the associations below reflect the advisory record and this library's judgment. Technique IDs verified against this library's ATT&CK data (see the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) and [Detection Strategies](detections/strategies/README.md)).

| Behavior on/through edge devices | ATT&CK anchor | Instrument |
|---|---|---|
| Exploitation of the internet-facing service | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | KEV-keyed patching; IDS at the boundary; appliance crash/error telemetry |
| Authenticated access via VPN/gateway | [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services · [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | VPN session analytics; MFA-context anomalies; first-hop monitoring |
| Web shells on appliances (LEMURLOOT-class, per AA23-158A) | [T1505.003](https://attack.mitre.org/techniques/T1505.003/) Web Shell | Egress from the appliance; vendor integrity checks; config/filesystem diffs where exposed |
| Firmware/OS image tampering, boot-level persistence | [T1601](https://attack.mitre.org/techniques/T1601/) Modify System Image · [T1542](https://attack.mitre.org/techniques/T1542/) Pre-OS Boot | Image hash verification against vendor values; vendor firmware-verification procedures; replacement policy |
| Authentication modification on network devices | [T1556.004](https://attack.mitre.org/techniques/T1556.004/) Network Device Authentication | Config diff alerting; AAA command accounting |
| Disabling/blinding device logging | [T1562](https://attack.mitre.org/techniques/T1562/) Impair Defenses | "Logging went quiet" alerts; off-box log baselines |
| Compromised edge devices as relay infrastructure | [T1090.003](https://attack.mitre.org/techniques/T1090.003/) Multi-hop Proxy | Egress monitoring; botnet-advisory IOC review (Raptor Train) |
| C2 blended into normal protocols | [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol | NetFlow/Zeek baselining of appliance-sourced traffic |

---

## Detection: egress and adjacent-network monitoring

The compensating principle for everything in the right-hand "cannot" column: **watch the box from outside the box.** A compromised appliance can falsify its own logs, but it cannot easily hide from a mirror port, a flow collector, or the authentication logs of the systems behind it. Volt Typhoon (AA24-038A) is the motivating case — years of living-off-the-land dwell, in environments where the footholds themselves produced little usable telemetry.

**Do**
- **Baseline the appliance's own traffic.** Management interfaces and appliance OSes should speak to a short, enumerable set of destinations (vendor update/licensing services, NTP, DNS, syslog, AAA). Capture NetFlow/IPFIX or Zeek at a point the appliance does not control and alert on new destinations, new ports, and volume shifts — see [Network Monitoring](NETWORK_MONITORING_REFERENCE.md).
- **Watch the appliance's DNS.** Device-originated DNS queries are among the log types the NCSC-UK producer guidance demands by default for a reason; resolve appliances through internal resolvers you log, and alert on lookups that fit no vendor pattern.
- **Instrument the first hop behind the gateway.** Post-VPN traffic, unusual internal destinations from the VPN pool, and authentication behavior downstream of the device often reveal what the device itself never will (the Citrix Bleed detection surface was largely downstream session behavior).
- **Mirror where it matters.** A tap/SPAN adjacent to the highest-consequence edge devices, feeding IDS/Zeek, gives responders wire-truth when appliance logs are suspect — and is the practical answer to "the appliance has no EDR".
- **Hunt on advisory cadence.** Each major edge advisory or ED is a trigger to sweep flow data and DNS logs backward over a long window ([Threat Hunting](THREAT_HUNTING_REFERENCE.md)) — edge compromises are found late, so retrospective reach matters more here than anywhere.
- **Alert on management-plane egress especially.** There is almost no legitimate reason for a management interface to originate connections to the internet.

**Don't**
- Point the SIEM only at the appliance's self-reported logs and call the edge "covered".
- Whitelist "the firewall" out of your own network analytics because it is a security device — the record says otherwise.
- Ignore inbound scanning telemetry entirely: mass scanning against your edge is the reconnaissance layer of the zero-day-majority world AA24-317A describes.

---

## Procurement: secure-by-design expectations for edge vendors

The 2023–2026 record is, in large part, a product-quality story — which is why the guidance stack includes documents aimed at **manufacturers** (the CCCS series doc's secure-by-design recommendations; the NCSC-UK forensics/logging specifications). Your leverage is procurement.

CISA's [Secure by Design pledge](https://www.cisa.gov/securebydesign/pledge) (announced May 2024 with 68 initial signers; the [signers page](https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers) is the living roster) commits signing manufacturers to seven goals:

| # | Pledge goal | Edge-procurement question to ask |
|---|---|---|
| **1** | Multi-factor authentication | Is phishing-resistant MFA supported (and default) for device administration? |
| **2** | Eliminate default passwords | Does the product ship without shared/default credentials? |
| **3** | Reduce entire vulnerability classes | What classes (e.g., memory safety, injection) has the vendor measurably engineered out? |
| **4** | Increase patch installation | Are updates reliable, fast to apply, and non-disruptive (HA-aware)? |
| **5** | Vulnerability disclosure policy | Is there a published VDP welcoming good-faith research? |
| **6** | CVE transparency | Are CVEs filed promptly with accurate CWE/CPE — including for exploited-in-the-wild bugs? |
| **7** | Evidence of intrusions | Does the product ship the logging/forensic capability the NCSC-UK specifications describe — by default, without extra licenses? |

Three honest caveats, stated by CISA itself: the pledge is **voluntary and not legally binding**; **CISA does not verify compliance**; and its stated scope is **enterprise software products and services** (on-premises software, cloud, SaaS) — physical products such as IoT devices are explicitly out of scope, so an edge vendor's signature speaks to its software, not its hardware line. Treat signature as a conversation-opener, not an assurance — then put the substance (goals 1, 2, 4, 7 especially, plus external integrity tooling and firmware verification) into RFP requirements and contract language, where it does bind.

---

## Quick reference: the paper trail

| Date | Instrument | One-line takeaway |
|---|---|---|
| **2023-06-07** | AA23-158A (CL0P / MOVEit) | File-transfer appliances: mass data-theft extortion, no encryption needed |
| **2023-06-13** | **BOD 23-02** | Management interfaces: off the internet or behind a separate PEP, in 14 days |
| **2023-10** | NSA Network Infrastructure Security Guide Ver. 1.2 | The hardening baseline: segmentation, AAA ×2, remote logging, admin hardening |
| **2023-11-21** | AA23-325A (Citrix Bleed) | Stolen session tokens bypass passwords and MFA; patch **and** kill sessions |
| **2024-01-19 / 01-31** | **ED 24-01** + Supplemental V1 | Disconnect, rebuild, revoke everything; assume connected accounts compromised |
| **2024-02-07** | AA24-038A (Volt Typhoon) | Five-plus years of LOTL dwell; the cost of appliance telemetry gaps |
| **2024-02-29** | AA24-060B | Vendor integrity checking (ICT) deceived; persistence through factory reset |
| **2024-05** | Secure by Design pledge (68 initial signers) | Seven voluntary manufacturer goals; procurement leverage |
| **2024-09-18** | PRC botnet advisory (Raptor Train) | 260,000+ compromised edge/IoT devices as attack infrastructure |
| **2024-11** | AA24-317A (2023 top exploited) | Majority of top 2023 CVEs first exploited as zero-days; edge-heavy product mix |
| **2025-02-04** | Four-publication edge guidance series | Threats, seven mitigation strategies, forensics/logging specs for producers |
| **2025-09-25** | **ED 25-03** (Cisco ASA/Firepower) | ROM-level persistence through reboot/upgrade; core dumps to CISA in ~1 day |
| **2025-10-15** | **ED 26-01** (F5) | Vendor's own dev environment breached; the supply chain is edge attack surface |
| **2026-02-05** | End-of-support edge devices guidance | Inventory support timelines; replace EOS devices promptly |
| **2026-06-10** | **BOD 26-04** (supersedes BOD 22-01) | Four-factor risk tiers; 3-day worst case + forensic triage; KEV carries forward |

---

## Sources

- CISA — BOD 23-02: Mitigating the Risk from Internet-Exposed Management Interfaces (June 13, 2023): <https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02> · [Implementation guidance](https://www.cisa.gov/news-events/directives/bod-23-02-implementation-guidance-mitigating-risk-internet-exposed-management-interfaces)
- CISA — BOD 26-04: Prioritizing Security Updates Based on Risk (June 10, 2026): <https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk>
- CISA — Known Exploited Vulnerabilities catalog (criteria): <https://www.cisa.gov/known-exploited-vulnerabilities> · JSON feed (version 2026.09.24 cited here): <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- CISA — Guidance and Strategies to Protect Network Edge Devices (series landing page): <https://www.cisa.gov/resources-tools/resources/guidance-and-strategies-protect-network-edge-devices> · [Series announcement (Feb 4, 2025)](https://www.cisa.gov/news-events/alerts/2025/02/04/cisa-partners-asds-acsc-cccs-ncsc-uk-and-other-international-and-us-organizations-release-guidance)
- CCCS — Security Considerations for Edge Devices (ITSM.80.101): <https://www.cyber.gc.ca/en/guidance/security-considerations-edge-devices-itsm80101>
- NCSC-UK — Guidance on digital forensics and protective monitoring specifications for producers of network devices and appliances (Feb 4, 2025): <https://www.ncsc.gov.uk/guidance/guidance-on-digital-forensics-protective-monitoring>
- ASD ACSC — Mitigation Strategies for Edge Devices: Practitioner Guidance: <https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/network-hardening/securing-edge-devices/mitigation-strategies-for-edge-devices-practitioner-guidance>
- NSA — Network Infrastructure Security Guide, CTR, Ver. 1.2 (October 2023 update): <https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003018261/>
- CISA — ED 24-01: Mitigate Ivanti Connect Secure and Ivanti Policy Secure Vulnerabilities (Jan 19, 2024): <https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities> · [Supplemental Direction V1 (Jan 31, 2024)](https://www.cisa.gov/news-events/directives/supplemental-direction-v1-ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure)
- CISA — ED 25-03: Identify and Mitigate Potential Compromise of Cisco Devices (Sept 25, 2025): <https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices>
- CISA — ED 26-01: Mitigate Vulnerabilities in F5 Devices (Oct 15, 2025): <https://www.cisa.gov/news-events/directives/ed-26-01-mitigate-vulnerabilities-f5-devices>
- CISA — AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways (Feb 29, 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b>
- CISA — AA23-158A: #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability (June 7, 2023): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a>
- CISA — AA23-325A: #StopRansomware: LockBit 3.0 Ransomware Affiliates Exploit CVE 2023-4966 Citrix Bleed Vulnerability (Nov 21, 2023): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a>
- CISA — AA24-317A: 2023 Top Routinely Exploited Vulnerabilities (November 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-317a>
- CISA — AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure (Feb 7, 2024): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a>
- FBI/CNMF/NSA et al. — People's Republic of China-Linked Actors Compromise Routers and IoT Devices for Botnet Operations (Sept 18, 2024): <https://media.defense.gov/2024/Sep/18/2003547016/-1/-1/0/CSA-PRC-LINKED-ACTORS-BOTNET.PDF>
- CISA — Secure by Design pledge: <https://www.cisa.gov/securebydesign/pledge> · [Signers roster](https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers)
- CISA/FBI/NCSC-UK — Reducing the Attack Surface for End-of-Support Edge Devices (Feb 5, 2026): <https://www.cisa.gov/resources-tools/resources/reducing-attack-surface-end-support-edge-devices>
- Ivanti — enhanced external Integrity Checker Tool announcement (Feb 2024): <https://www.ivanti.com/blog/enhanced-external-integrity-checking-tool-to-provide-additional-visibility-and-protection-for-customers-against-evolving-threat-actor-techniques-in-relation-to-previously-disclosed-vulnerabilities>

---

*This reference summarizes third-party government and framework publications — CISA directives and advisories, the international edge-device guidance series (CCCS, NCSC-UK, ASD ACSC), NSA cybersecurity technical reports, the KEV catalog, and MITRE ATT&CK® — as an independent practitioner summary; it is not affiliated with or endorsed by those organizations. Directives, advisories, KEV entries, and pledge signers change continuously; consult the linked originals for authoritative and current content. The ATT&CK table above is an editorial mapping by this library, not an official MITRE or CISA artifact.*
