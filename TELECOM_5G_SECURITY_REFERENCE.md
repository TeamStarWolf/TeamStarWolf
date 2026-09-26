# Telecom & 5G Security Reference

> **Telecommunications networks are now a primary espionage target, and [MITRE FiGHT™](https://fight.mitre.org/) is the ATT&CK-style model for defending them.** FiGHT (the *5G Hierarchy of Threats*), launched in September 2022 by MITRE with the DoD Office of the Under Secretary of Defense, catalogs adversary tactics and techniques against 5G systems — and the 2024–2025 **Salt Typhoon** intrusions into commercial telecom providers turned that catalog from theory into the most consequential defensive problem in critical infrastructure.

This reference covers the FiGHT framework's structure and how it extends ATT&CK, legacy signaling interconnect risk (SS7/Diameter/SIP) and the GSMA defense guidance, 5G core security architecture per 3GPP TS 33.501 (SBA, SUCI/SUPI privacy, SEPP roaming security), network slicing and O-RAN security, lawful-intercept infrastructure risk, and the CISA/FBI advisory record on Salt Typhoon with the resulting hardening guidance — distilled for defenders.

| | |
|---|---|
| **Framework** | MITRE FiGHT (5G Hierarchy of Threats) — [fight.mitre.org](https://fight.mitre.org/) · [github.com/mitre/FiGHT](https://github.com/mitre/FiGHT) |
| **Version** | v3.1.0 (release commit dated 2025-11-14; prior: v3.0.0 2025-06-10, v3.0.1 2025-07-02) |
| **Tactics** | 15 — 14 reuse ATT&CK Enterprise tactic IDs, plus the FiGHT-unique **Fraud** (TA5001) |
| **Techniques** | 183 technique objects (86 parents + 97 sub-techniques), as of v3.1.0 per the official `fight.yaml` |
| **Mitigations / data sources** | 92 mitigations · 49 data sources with 120 components |
| **Key advisories** | FBI/CISA joint statements (Oct/Nov 2024) · Dec 2024 hardening guidance · [AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) |

**Related:** [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Mobile ATT&CK Atlas](MOBILE_ATTACK_ATLAS.md) · [Wireless Security](WIRELESS_SECURITY_REFERENCE.md) · [SDR & RF Security](SDR_RF_SECURITY_REFERENCE.md) · [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) · [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md)

| | |
|---|---|
| **Read this when** | You defend or assess a telecom operator or private 5G estate, you need to scope FiGHT techniques or GSMA signaling defenses into a threat-informed program, or you are responding to the Salt Typhoon advisory record and hardening guidance |
| **Start at** | [Why telecom infrastructure is a target](#why-telecom-infrastructure-is-a-target-the-salt-typhoon-wake-up-call) · [Case study: Salt Typhoon and AA25-239A](#case-study-salt-typhoon-and-the-advisory-record-aa25-239a) · [Hardening communications infrastructure](#hardening-communications-infrastructure-the-december-2024-joint-guidance-distilled) |

---

## Why telecom infrastructure is a target: the Salt Typhoon wake-up call

A telecom operator concentrates everything an espionage service wants in one place: **who talks to whom** (call detail records), **where every subscriber is** (location and registration data), **the content of unencrypted communications**, and — uniquely — **the lawful-intercept systems** that are purpose-built to covertly monitor selected targets. Compromise the operator and you inherit all of it, across every customer at once.

That is exactly what the public record now documents:

| Date | Event |
|---|---|
| **2024-10-25** | First joint [FBI/CISA statement](https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-prc-activity-targeting-telecommunications) announcing an investigation into PRC-affiliated unauthorized access to commercial telecommunications infrastructure |
| **2024-11-13** | [Follow-up joint statement](https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-peoples-republic-china-prc-targeting-commercial-telecommunications) confirming compromise of multiple providers, with three impact categories (below) |
| **2024-12-03** | CISA/NSA/FBI + ACSC (AU), CCCS (CA), NCSC-NZ release [Enhanced Visibility and Hardening Guidance for Communications Infrastructure](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure) |
| **2024-12-18** | CISA releases [Mobile Communications Best Practice Guidance](https://www.cisa.gov/resources-tools/resources/mobile-communications-best-practice-guidance) for highly targeted individuals |
| **Jan 2025** | FCC adopts a Declaratory Ruling ([FCC 25-9](https://docs.fcc.gov/public/attachments/FCC-25-9A1.pdf)) interpreting CALEA §105 as requiring carriers to secure networks against unlawful access, plus an NPRM on risk-management plans |
| **2025-08-27** | Joint advisory [AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) released, co-sealed by agencies from **13 countries** (updated to v1.1 on 2025-09-03) |
| **2025-11-20** | FCC votes 2–1 to **rescind** the CALEA Declaratory Ruling and withdraw the NPRM ([Federal Register, 2025-12-15](https://www.federalregister.gov/documents/2025/12/15/2025-22830/protecting-the-nations-communications-systems-from-cybersecurity-threats)) — the January 2025 ruling is **no longer in force** |

The November 13, 2024 statement confirmed three categories of impact from the PRC-affiliated campaign:

1. **Theft of customer call records data** — bulk metadata: who called whom, when, from where.
2. **Compromise of private communications** of a limited number of individuals, primarily involved in government or political activity.
3. **Copying of "certain information that was subject to U.S. law enforcement requests pursuant to court orders"** — the publicly documented compromise touching lawful-intercept infrastructure.

> **The lesson for defenders:** the victims were not exotic 5G core functions — the advisory record centers on **network edge devices, management planes, and legacy protocols** in ordinary carrier backbone and enterprise-edge routers. The hardening that would have raised the cost is boring, well-understood network engineering (see [Hardening communications infrastructure](#hardening-communications-infrastructure-the-december-2024-joint-guidance-distilled) below). Track the actor in [Threat Group Profiles](THREAT_GROUP_PROFILES.md).

---

## MITRE FiGHT: structure, technique types, and how it extends ATT&CK

FiGHT is a purpose-built knowledge base of adversary tactics and techniques for 5G systems, publicly launched **September 26, 2022** by MITRE and the DoD Office of the Under Secretary of Defense. In MITRE's own words it is *modeled after the MITRE ATT&CK framework, and its tactics and techniques are complementary to those in ATT&CK* — a separate knowledge base, **not** an ATT&CK domain or matrix. Its stated operational uses: threat assessments, adversarial emulation, coverage-gap identification, and cyber investment planning for 5G networks and the devices and applications that use them.

Version history lives in the [mitre/FiGHT](https://github.com/mitre/FiGHT) repo's commit messages (there is no GitHub Releases page): current is **v3.1.0** (2025-11-14), after v3.0.0 (2025-06-10) and v3.0.1 (2025-07-02). Per the repo README, a minority of FiGHT techniques are based on real-world observations, documented accordingly in each technique's evidentiary status; the v3.1.0 data has visibly absorbed the 2024–2025 Salt Typhoon record (see [Groups, software, campaigns](#groups-software-campaigns)).

### The 15 tactics

14 of FiGHT's 15 tactics reuse ATT&CK Enterprise tactic IDs; one is FiGHT-unique:

| ID | Tactic | Origin |
|---|---|---|
| **TA0043** | Reconnaissance | ATT&CK |
| **TA0042** | Resource Development | ATT&CK |
| **TA0001** | Initial Access | ATT&CK |
| **TA0002** | Execution | ATT&CK |
| **TA0003** | Persistence | ATT&CK |
| **TA0004** | Privilege Escalation | ATT&CK |
| **TA0005** | Defense Evasion | ATT&CK |
| **TA0006** | Credential Access | ATT&CK |
| **TA0007** | Discovery | ATT&CK |
| **TA0008** | Lateral Movement | ATT&CK |
| **TA0009** | Collection | ATT&CK |
| **TA0011** | Command and Control | ATT&CK |
| **TA0010** | Exfiltration | ATT&CK |
| **TA0040** | Impact | ATT&CK |
| **TA5001** | **Fraud** | **FiGHT-unique** — described in the FiGHT data as obtaining service without contractually paying for it |

The Fraud tactic is what makes FiGHT more than "ATT&CK with radios": in telecom, monetization abuse (subscription fraud, service theft) is a first-class adversary objective, not an afterthought. Pair it with the [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md) when the fraud is financial rather than service-oriented.

### Technique ID convention

FiGHT technique IDs encode their lineage (observable directly in the official data):

| Pattern | Meaning | Example |
|---|---|---|
| **FGT1###** | ATT&CK-derived — `FGT` + the ATT&CK technique number | FGT1195 ↔ ATT&CK [T1195 Supply Chain Compromise](ATTACK_TECHNIQUE_ATLAS.md) |
| **FGT5###** | 5G-unique technique with no ATT&CK counterpart | 43 of the 86 parent techniques |
| **FGT1###.5##** | FiGHT-added sub-technique under an ATT&CK-derived parent | FGT1542.501 (a 5G-specific sub of T1542 Pre-OS Boot) |

As of v3.1.0, the 86 parent techniques split exactly evenly: **43 ATT&CK-derived (`FGT1xxx`) and 43 5G-unique (`FGT5xxx`)** — half of what FiGHT models simply does not exist in Enterprise ATT&CK, because it lives in RAN, core, or interconnect behavior.

### Evidentiary status — FiGHT's most useful field

Every FiGHT technique carries a status label, something ATT&CK does not do. Use it to weight your risk register:

| Status | Count (v3.1.0) | How to treat it |
|---|--:|---|
| **Observed** | 53 | Real-world use documented — prioritize for detection coverage now |
| **Proof of Concept** | 19 | Demonstrated in research — plausible for capable actors; validate exposure |
| **Theoretical** | 111 | Architecturally possible — architecture/design-review input, not detection backlog |

*(Counts computed from the official `fight.yaml` on the main branch; MITRE publishes no official count summary page, so recount from the data file if exactness matters at your publish time. Both non-Theoretical counts merge status spellings present in the data: PoC = 18 "Proof Of Concept" + 1 "POC"; Observed = 49 plain "Observed" + 4 qualified variants such as "Observed In 4G And Expected To Be Observed In 5G" and "Observed In Enterprise".)*

### Groups, software, campaigns

FiGHT v3.1.0 ships 10 groups, 16 software entries, and 2 campaigns. Telecom-relevant group entries include **Salt Typhoon (G1045)**, **Liminal Panda (FGG5001)**, **GALLIUM (G0093)**, Stone Panda (FGG5002), HiddenArt (FGG5003), Scattered Spider (FGG5004), TeamTNT, Silence, HAFNIUM, and APT29; the two campaigns are **Operation Soft Cell (FGC5001)** and SolarWinds Compromise (C0024). Salt Typhoon appears 51 times in the v3.1.0 data file — the framework has visibly absorbed the 2024–2025 campaign.

---

## Using FiGHT in a threat-informed defense program

FiGHT slots into the same loop as ATT&CK — see [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) and [CTEM](CTEM_REFERENCE.md):

| Program activity | How FiGHT contributes |
|---|---|
| **Threat assessment** | Scope which of the 183 techniques apply to *your* footprint (RAN? core? MVNO? private 5G?), weighted by evidentiary status |
| **Adversary emulation** | Build emulation plans from FiGHT groups (G1045, FGG5001, G0093) and campaigns (FGC5001) for [purple team](PURPLE_TEAM_REFERENCE.md) exercises |
| **Coverage-gap analysis** | Map the 49 data sources / 120 components against your telemetry, exactly as you would ATT&CK data components ([ATT&CK Data Components](ATTACK_DATA_COMPONENTS.md) shows the method) |
| **Investment planning** | The 92 mitigations give a defensible backlog; Observed-status techniques justify spend first |
| **Navigator layers** | The `FGT1xxx` techniques share ATT&CK numbering, so cyber and telecom coverage can be reviewed side-by-side in [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) |

**Do**
- Treat `FGT1xxx` techniques as the **join key** between your enterprise ATT&CK program and your telecom estate — one detection engineering backlog, two matrices.
- Use the **Theoretical** techniques in architecture and procurement reviews (they are requirements, not detections).
- Re-pull `fight.yaml` when you build tooling — versions move and counts change.

**Don't**
- Don't present FiGHT-to-anything mappings as official unless MITRE published them. **No officially published FiGHT→D3FEND or FiGHT→NIST 800-53 mapping was found as of this writing** — if you need [D3FEND](D3FEND_REFERENCE.md) countermeasures, map via the shared ATT&CK technique IDs and label the result as your own inference.
- Don't treat FiGHT as an ATT&CK domain in tooling that assumes STIX ATT&CK bundles — it is distributed as its own YAML data model.

---

## Legacy signaling interconnect risk: SS7, Diameter, and SIP

Every mobile operator is federated with hundreds of others through interconnect and roaming agreements. The signaling protocols that make roaming work were designed for a **closed club of trusted state carriers** — they authenticate *nothing* by default. Access to the interconnect (via a rogue operator, a leased Global Title, or a compromised carrier) has historically been enough to interact with other networks' subscribers.

| Protocol | Where it lives | Interconnect exposure (conceptual) |
|---|---|---|
| **SS7** (MAP/CAP, incl. over SIGTRAN) | 2G/3G core interconnect | Public advisories and GSMA guidance describe subscriber **location tracking**, **call/SMS interception** (which defeats SMS-based MFA), **fraud**, and **denial of service** against subscribers — all achievable with signaling messages the protocol treats as inherently trusted |
| **Diameter** | 4G/LTE core interconnect (S6a etc.) | Same *classes* of abuse re-expressed in Diameter semantics; IPsec/TLS support exists but interconnect deployment is inconsistent |
| **SIP** | VoLTE/VoWiFi, IMS, SIP trunking | Caller-ID spoofing, registration abuse, toll fraud, and interception risk at poorly filtered IMS/NNI borders — *no dedicated public GSMA/CISA document verified for SIP interconnect; treat this row as conceptual* |
| **GTP** (GTP-C/GTP-U) | Roaming user/control plane (2G–5G NSA) | User-plane and session-management abuse at roaming borders; filtered by GTP firewalls at the same perimeter |

Why this still matters in a 5G document: **5G non-standalone (NSA) rides on the 4G core**, roaming partners run every generation simultaneously, and downgrade to 2G/3G re-exposes subscribers to SS7-era weaknesses. Legacy signaling risk retires when the last 2G/3G roaming agreement does — not before.

This section stays at the interconnect/defense altitude; for the attack-mechanics view of SS7 and Diameter S6a abuse (message flows, IMSI-catcher interplay, protocol history), see [Wireless Security](WIRELESS_SECURITY_REFERENCE.md) §4.4–4.5.

---

## Signaling defense: firewalls, monitoring, and GSMA FS.11 / FS.19 / FS.21

The GSMA's Fraud and Security Group maintains the operator-side defense guidance ([GSMA cybersecurity knowledge base](https://www.gsma.com/solutions-and-impact/technologies/security/cybersecurity-knowledge-base/interworking-security/)):

| Document | Title / scope |
|---|---|
| **GSMA FS.11** | *SS7 Interconnect Security Monitoring and Firewall Guidelines* — the GSMA's baseline SS7 defense document, regularly updated (GSMA publishes no public version history or approval dates) |
| **GSMA FS.19** | *Diameter Interconnect Security* |
| **GSMA FS.21** | *Interconnect Signalling Security Recommendations* — the cross-protocol umbrella document above both |

> These documents are **GSMA member-gated**; current version numbers are not publicly verifiable, so they are cited here by title only. If your organization is a GSMA member, pull the current versions from InfoCentre before building controls against them.

**What a signaling firewall actually does.** Industry practice built on this guidance screens interconnect messages in escalating tiers: (1) drop message types that have no legitimate reason to arrive from an external interconnect at all; (2) drop messages that claim to concern your own subscribers but arrive from networks where those subscribers cannot plausibly be; (3) apply stateful plausibility checks — velocity (can the subscriber physically have moved that far since the last event?), correlation with roaming status, and rate anomalies. The same conceptual tiers apply to SS7 and Diameter, with protocol-specific rulesets.

**Do**
- Deploy **signaling firewalls on every interconnect border** (SS7 STP-adjacent, Diameter DEA/DRA-adjacent, GTP borders) — monitoring mode first, then enforce.
- Feed signaling firewall verdicts and interconnect telemetry into the SOC like any other sensor ([SIEM Reference](SIEM_REFERENCE.md)) — signaling abuse against your executives is an *intrusion signal*, not just a fraud metric.
- Run periodic external signaling assessments against your own network from the interconnect side.
- Treat **SMS-based MFA as compromised by design** for high-value accounts — this is a downstream enterprise consequence of SS7/Diameter exposure ([Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)).

**Don't**
- Don't assume IPX or roaming-hub providers filter for you — verify contractually and empirically.
- Don't attribute SIP interconnect guidance to FS.11/FS.19 (they cover SS7 and Diameter respectively).
- Don't leave Global Titles and roaming agreements unaudited; unused or resold GT ranges are a classic abuse enabler.

---

## 5G core security architecture: SBA, SUCI/SUPI, SEPP, and TS 33.501

The authoritative 5G security specification is **3GPP TS 33.501, "Security architecture and procedures for 5G System,"** owned by working group SA3. Latest version at the time of writing: **20.2.0** (2026-06-25, SA#112); latest per-release: Rel-15 15.20.0, Rel-16 16.20.0, Rel-17 17.16.0, Rel-18 18.12.0, Rel-19 19.7.0 ([3GPP portal record](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3169)). Versions mint at every SA plenary — check the portal before citing.

What changed architecturally from 4G:

| 5G security element | What it is | Why it matters |
|---|---|---|
| **SBA (Service-Based Architecture)** | Core network functions (AMF, SMF, UDM, AUSF, NRF, NEF…) exposing HTTP/2 REST APIs on a service mesh, instead of point-to-point telecom protocols | The core becomes *API security territory*: TS 33.501 specifies transport protection (TLS) between network functions and token-based authorization for service access — bringing [API Security](API_SECURITY_REFERENCE.md) discipline into the core |
| **SUPI → SUCI concealment** | The permanent subscriber identifier (SUPI) is encrypted into a SUCI over the air; the **SIDF** (Subscription Identifier De-concealing Function), offered by the UDM in the home network, de-conceals it | Kills passive IMSI-catcher-style permanent-identifier harvesting *when 5G SA is actually in use* — downgrade to legacy RATs reintroduces the exposure |
| **Unified primary authentication** | 5G-AKA / EAP-AKA′ with home-network involvement in authentication confirmation | The home operator gets cryptographic say in roaming authentication, closing a 4G-era trust gap |
| **SEPP (Security Edge Protection Proxy)** | The mandatory security gateway at the PLMN perimeter for inter-operator control-plane (roaming) traffic | Replaces the "flat trust" interconnect model of SS7/Diameter with an authenticated, encrypted, policy-enforcing border — the single most important interconnect upgrade in 5G |

### SEPP and the N32 interface

```
        HOME PLMN                                        VISITED PLMN
 ┌─────────────────────────┐                     ┌─────────────────────────┐
 │  UDM ── AUSF ── NRF ──… │                     │  AMF ── SMF ── NRF ──…  │
 │   │(SIDF: SUCI→SUPI)    │                     │              │          │
 │  ═╪══ SBA service mesh ═│                     │═ SBA service mesh ══╪═  │
 │        │                │                     │                │        │
 │    ┌───┴──┐   N32-c: handshake & param negotiation   ┌───┴──┐          │
 │    │ SEPP │◄════════════════════════════════════════►│ SEPP │          │
 │    └──────┘   N32-f: forwarding, application-layer   └──────┘          │
 └────────────│  protection (JWE, RFC 7516)  │───────────────────────────┘
              └───── via IPX / interconnect ─┘
```

N32 splits into **N32-c** (the control connection where the two SEPPs mutually authenticate and negotiate protection parameters) and **N32-f** (the forwarding channel carrying the actual signaling with application-layer protection using JSON Web Encryption, RFC 7516 — protecting message contents even across intermediary IPX carriers). SEPP functions include mutual authentication and key management, **topology hiding** (the partner sees the SEPP, not your core), access control, discarding malformed N32 messages, rate limiting, and anti-spoofing.

**Defender's view of the 5G core:** it is a Kubernetes-hosted microservice estate speaking HTTP/2 — so [container security](CONTAINER_SECURITY_REFERENCE.md), [Kubernetes security](KUBERNETES_SECURITY_REFERENCE.md), certificate lifecycle management, and NRF (service discovery) abuse monitoring are now *telecom core* disciplines, not just IT ones.

---

## Network slicing security: isolation threats and the NSA/CISA ESF guidance

Network slicing lets one physical 5G infrastructure carry multiple logical end-to-end networks (a public-safety slice, an IoT slice, an enterprise slice) with distinct SLAs. Isolation between slices is a *configuration outcome*, not a physical fact — which makes it a security boundary that must be engineered and continuously verified.

Two ESF (Enduring Security Framework — NSA/CISA/ODNI) publications anchor the topic:

| Document | Date | Core content |
|---|---|---|
| [**Potential Threats to 5G Network Slicing**](https://media.defense.gov/2022/Dec/13/2003132073/-1/-1/0/POTENTIAL%20THREATS%20TO%205G%20NETWORK%20SLICING_508C_FINAL.PDF) | 2022-12-13 | Identifies **denial of service**, **man-in-the-middle**, and **configuration attacks** as the principal slicing threat vectors |
| [**5G Network Slicing: Security Considerations for Design, Deployment, and Maintenance**](https://www.cisa.gov/news-events/alerts/2023/07/17/nsa-cisa-release-guidance-security-considerations-5g-network-slicing) | 2023-07-17 | Hardening practices across the full slice lifecycle for standalone 5G |

**Do**
- Design slice isolation across **all three domains at once** — RAN, transport, core. A perfectly isolated core slice sharing an unpoliced transport VLAN is not isolated.
- Treat the **slice orchestrator/MANO stack as crown-jewel management plane**: phishing-resistant MFA, RBAC, change control, and full audit logging on every slice-template and lifecycle operation.
- Monitor per-slice resource consumption — cross-slice starvation is the DoS vector the ESF paper leads with.
- Re-validate isolation after every orchestration change (the "configuration attack" vector is mostly *drift*, not exotic exploitation).

**Don't**
- Don't sell or accept a slice as a "private network" without written isolation guarantees you can test.
- Don't let slice management APIs share authentication realms with general IT.

---

## O-RAN security: WG11, threat model, zero trust, and supply chain

Open RAN disaggregates the radio access network into interoperable components (RU/DU/CU, RIC, xApps/rApps) over open interfaces. CISA and NSA's [Open Radio Access Network Security Considerations](https://us-cert.cisa.gov/ncas/current-activity/2022/09/15/cisa-and-nsa-publish-open-radio-access-network-security) (ESF Open RAN Working Panel, 2022-09-15) set the baseline framing: some security considerations are shared with traditional proprietary RAN, others are unique to Open RAN's expanded interface and vendor surface.

Security specification work is led by **O-RAN ALLIANCE WG11**. Per the official [O-RAN ALLIANCE Security Update 2026](https://www.o-ran.org/blog/o-ran-alliance-security-update-2026) (2026-02-24), the four core WG11 documents are:

| WG11 document | Version (Feb 2026) |
|---|---|
| **Security Requirements and Controls Specifications** | v14.0 |
| **Security Protocols Specifications** | v14.0 |
| **Security Tests Specifications** | v12.0 |
| **Threat Modeling and Risk Assessment** (Technical Report) | v8.0 |

*(WG11 versions move quickly and secondary sources disagree — re-check the o-ran.org specifications page before citing.)* ETSI and ATIS published the four primary O-RAN security documents in 2025, giving them standing in formal standards ecosystems.

Key facts from the official [2025 security update](https://www.o-ran.org/blog/o-ran-alliance-security-update-2025):

- The WG11 threat model covers **over 160 distinct threats** to O-RAN interfaces, network functions, and architecture elements (39 AI/ML threats added in 2024), analyzed using **STRIDE** ([Threat Modeling](THREAT_MODELING_REFERENCE.md)).
- WG11 published the **Zero Trust Architecture for Secure O-RAN** white paper (May 2024), aligned to **NIST SP 800-207** and assessed against **CISA's Zero Trust Maturity Model** ([Zero Trust Reference](ZERO_TRUST_REFERENCE.md)).
- Requirements mandate a **vendor-signed, NTIA-compliant SBOM with every O-RAN software delivery** — supply-chain transparency as a conformance requirement, not a nice-to-have ([Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md)).
- Security assurance specifications (**SCAS**) developed with GSMA/TIFG become publicly available in 2026.

The practitioner takeaway: O-RAN's security posture is *specifiable and testable* in a way closed RAN never was — but only if buyers actually put WG11 requirements, SBOM delivery, and SCAS conformance into procurement language.

---

## Lawful-intercept infrastructure risk

Lawful interception (LI) systems are the highest-leverage components in any operator: infrastructure whose *purpose* is covert, targeted access to communications, with legally mandated secrecy around its operation. An adversary who compromises LI inherits a monitoring capability that is designed to be invisible — and learns *who is under surveillance*, which is itself counterintelligence gold.

**The 3GPP LI specification trio** (created fresh for the 5G era — [3gpp.org/technologies/li](https://www.3gpp.org/technologies/li)):

| Spec | Scope |
|---|---|
| **TS 33.126** | LI requirements |
| **TS 33.127** | LI architecture and functions |
| **TS 33.128** | Protocol and procedures for LI (Stage 3) |

**This risk is no longer hypothetical.** The November 13, 2024 FBI/CISA joint statement documented that PRC-affiliated actors copied "certain information that was subject to U.S. law enforcement requests pursuant to court orders" — publicly confirming adversary reach into data tied to the lawful-access process at compromised providers.

**The regulatory whiplash (US):** in January 2025 the FCC adopted a Declaratory Ruling ([FCC 25-9](https://docs.fcc.gov/public/attachments/FCC-25-9A1.pdf)) interpreting **CALEA Section 105** as affirmatively requiring carriers to secure their networks against unlawful access and interception, with an accompanying NPRM proposing cybersecurity risk-management plans and annual certifications — a direct response to Salt Typhoon. On **November 20, 2025** the FCC voted 2–1 to **rescind that ruling and withdraw the NPRM** via an Order on Reconsideration ([Federal Register, Dec 15, 2025](https://www.federalregister.gov/documents/2025/12/15/2025-22830/protecting-the-nations-communications-systems-from-cybersecurity-threats)), calling the prior ruling a misinterpretation of CALEA. **Do not cite the January 2025 ruling as current law.** The engineering obligation, however, doesn't depend on the FCC: treat LI as crown-jewel infrastructure regardless of mandate.

**Do**
- Put LI mediation and administration functions in their own **maximum-isolation enclave**: dedicated accounts, dedicated jump infrastructure, hardware-backed MFA, no shared administration with the general core.
- Log and independently review **every** LI provisioning and query event — the audit trail is the only thing that distinguishes lawful use from abuse of the same capability.
- Include the LI enclave in red-team scope (with counsel's involvement); it is the one system where "nobody ever tests it" and "catastrophic if compromised" reliably coincide.

**Don't**
- Don't allow LI systems to share identity providers, patch infrastructure, or monitoring blind spots with the corporate network.
- Don't let vendor remote access to LI equipment bypass your own access-control and session-recording stack.

---

## Case study: Salt Typhoon and the advisory record (AA25-239A)

[AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a), *"Countering Chinese State-Sponsored Actors Compromise of Networks Worldwide to Feed Global Espionage System"* (released 2025-08-27, updated to v1.1 on 2025-09-03), is the definitive public document on the campaign — co-sealed by agencies from **13 countries**: US (NSA, CISA, FBI, DC3), Australia, Canada, New Zealand, UK, Czech Republic, Finland, Germany, Italy, Japan, Netherlands, Poland, and Spain.

| Advisory element | Content |
|---|---|
| **Actor overlap** | Activity partially overlaps industry reporting on **Salt Typhoon**, OPERATOR PANDA, RedMike, UNC5807, and GhostEmperor |
| **Named PRC companies** | Sichuan Juxinhe Network Technology Co. Ltd. · Beijing Huanyu Tianqiong Information Technology Co. Ltd. · Sichuan Zhixin Ruijie Network Technology Co. Ltd. |
| **Sectors** | Telecommunications, government, transportation, lodging, military |
| **Exploited CVEs** | See table below |

The five CVEs the advisory lists — all edge/network-device vulnerabilities, none of them 5G-specific ([CVE Reference](CVE_REFERENCE.md) for KEV/EPSS triage method):

| CVE | Affected technology |
|---|---|
| **CVE-2018-0171** | Cisco IOS/IOS XE Smart Install |
| **CVE-2023-20198** | Cisco IOS XE web UI |
| **CVE-2023-20273** | Cisco IOS XE web UI |
| **CVE-2024-21887** | Ivanti Connect Secure / Policy Secure |
| **CVE-2024-3400** | Palo Alto Networks PAN-OS GlobalProtect |

AA25-239A's defender guidance: **management-plane isolation, SNMPv3-only, control-plane policing, immediate patching of the listed CVEs, disabling unused protocols, strong authentication, continuous configuration-change monitoring, and centralized logging with secure transmission.**

> **Mapping honesty note:** AA25-239A maps activity to **ATT&CK Enterprise**, not to FiGHT. FiGHT does contain a Salt Typhoon group entry (**G1045**), but **no official FiGHT-to-advisory technique mapping exists** — don't invent one. If you need the advisory's technique-level detail, pull its own ATT&CK table directly from CISA and work it through the [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md). The campaign's exploitation of internet-exposed management services and network-device weaknesses corresponds to well-known Enterprise technique *families* (e.g., exploitation of public-facing applications, valid accounts, external remote services — T1190, T1078, T1133 exist in the ATT&CK data in this library), but treat any specific advisory-to-ID pairing you make yourself as your own analysis, clearly labeled.

---

## Hardening communications infrastructure: the December 2024 joint guidance, distilled

The [Enhanced Visibility and Hardening Guidance for Communications Infrastructure](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure) (CISA/NSA/FBI + ACSC, CCCS, NCSC-NZ; December 3, 2024; [full PDF](https://www.cisa.gov/sites/default/files/2025-01/joint-guidance-enhanced-visibility-hardening-guide-for-comms-infrastructure-508c_0.pdf)) is the direct operational answer to Salt Typhoon. Its recommendations fall into two categories.

### Strengthening visibility

| Measure | What good looks like |
|---|---|
| **Configuration-change monitoring** | Every device config change is captured, diffed, and alerted on out-of-band — an attacker's config edit *is* the incident |
| **Centralized, secured logging** | Device logs shipped off-box over encrypted transport to a store the device (and its admins) cannot alter |
| **SIEM correlation** | Network-device telemetry treated as first-class SIEM input, not an afterthought ([SIEM Reference](SIEM_REFERENCE.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md)) |
| **Network flow monitoring** | NetFlow/IPFIX baselining across backbone and management networks to expose abnormal peer-to-peer and exfil paths ([Network Monitoring](NETWORK_MONITORING_REFERENCE.md)) |

### Hardening

| Measure | What good looks like |
|---|---|
| **Out-of-band management** | Management plane on physically separate infrastructure from the data plane — an attacker on the transit path never touches device administration |
| **Default-deny ACLs** | Management services reachable only from enumerated admin networks |
| **Segmentation** | VLAN + firewall separation between management, signaling, user plane, and corporate IT ([Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md)) |
| **Phishing-resistant MFA** | FIDO2/PKI on all administrative access |
| **RBAC / least privilege** | Per-admin accounts, command authorization, no shared enable credentials |
| **Protocol hygiene** | Disable Telnet, SSHv1, SNMPv1/v2c; SNMPv3 only; TLS 1.3 with strong ciphers for services that remain |
| **Cisco-specific** | Disable Smart Install (the CVE-2018-0171 surface), disable guestshell, disable non-encrypted web management |

**Companion for the people layer:** CISA's [Mobile Communications Best Practice Guidance](https://www.cisa.gov/resources-tools/resources/mobile-communications-best-practice-guidance) (December 18, 2024) covers the *highly targeted individual* side — senior government and political figures — recommending end-to-end encrypted communications and hardened mobile practices precisely because carrier infrastructure could not be presumed uncompromised ([Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md)).

---

## Detection, visibility, and program guidance for telecom defenders

Telemetry worth collecting first, mapped to what it catches:

| Telemetry source | What it surfaces |
|---|---|
| **AAA/TACACS+ command accounting** | Every administrative command on every network device, per admin — the primary record of management-plane abuse |
| **Config archive + diff alerting** (e.g., RANCID/Oxidized-class tooling or vendor equivalent) | Unauthorized configuration changes — the core visibility measure in the Dec 2024 guidance |
| **Off-box syslog over encrypted transport** | Device events an intruder with device admin cannot silently erase |
| **NetFlow/IPFIX from backbone and management networks** | Abnormal peering, management-network egress, staging and exfiltration paths |
| **Signaling firewall verdict logs** (SS7/Diameter/GTP) | Interconnect reconnaissance, tracking, and interception attempts against your subscribers |
| **SEPP/N32 handshake and error logs** | Failed or anomalous roaming-partner negotiations at the 5G border |
| **NRF service-discovery and SBA API access logs** | Rogue or anomalous network-function registration and inter-NF calls in the core |
| **Kubernetes audit logs for core workloads** | Change and access history for the platform the 5G core actually runs on |
| **LI provisioning/query audit trail** | The only record distinguishing lawful use of intercept capability from its abuse |

Pulling the advisory record and frameworks into one operating posture:

**Do**
- **Instrument the management plane first.** Every documented impact in this campaign flowed through device administration. TACACS+/AAA command accounting, config-diff alerting, and off-box syslog are the highest-yield telemetry in the sector.
- **Run FiGHT-informed coverage reviews** on a cadence: Observed techniques → detection backlog; PoC → exposure validation; Theoretical → architecture review. Track it like any [CTEM](CTEM_REFERENCE.md) loop.
- **Baseline interconnect behavior** — signaling firewall verdicts, GTP anomalies, N32/SEPP errors — and treat deviations as security events, not just ops noise.
- **Exercise the seam between fraud and intrusion.** FiGHT's Fraud tactic (TA5001) and [F3](FRAUD_FRAMEWORK_REFERENCE.md) both exist because the fraud desk and the SOC routinely see two halves of the same actor.
- **Put supplier requirements in writing**: WG11 conformance, signed NTIA-compliant SBOMs, SCAS results, vendor remote-access controls ([Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md)).
- **Patch the named CVEs as a standing directive** — the AA25-239A five are the demonstrated entry set for this campaign class.

**Don't**
- Don't scope "5G security" to the 5G core while 2G–4G interconnect, edge routers, and LI enclaves carry the demonstrated risk.
- Don't accept flat management networks or shared admin credentials anywhere in the operator estate — this is the exact terrain the advisories describe being exploited.
- Don't build compliance posture on the FCC's January 2025 CALEA ruling — it was rescinded November 20, 2025.
- Don't wait for telecom-specific detection content to be handed to you; the December 2024 guidance is deliberately vendor-practical and implementable with standard NSM tooling ([Network Defense](NETWORK_DEFENSE_REFERENCE.md)).

---

## Sources

**MITRE FiGHT**
- FiGHT site — https://fight.mitre.org/
- Official repo and data (`fight.yaml`, v3.1.0) — https://github.com/mitre/FiGHT
- Launch press release (2022-09-26) — https://www.mitre.org/news-insights/news-release/mitre-and-office-under-secretary-defense-announce-fighttm-framework

**Salt Typhoon advisory record and hardening guidance**
- FBI/CISA joint statement, 2024-10-25 — https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-prc-activity-targeting-telecommunications
- FBI/CISA joint statement, 2024-11-13 — https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-peoples-republic-china-prc-targeting-commercial-telecommunications
- Enhanced Visibility and Hardening Guidance, 2024-12-03 — https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure ([PDF](https://www.cisa.gov/sites/default/files/2025-01/joint-guidance-enhanced-visibility-hardening-guide-for-comms-infrastructure-508c_0.pdf))
- Mobile Communications Best Practice Guidance, 2024-12-18 — https://www.cisa.gov/resources-tools/resources/mobile-communications-best-practice-guidance
- Joint advisory AA25-239A, 2025-08-27 (v1.1 2025-09-03) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a

**3GPP and GSMA**
- 3GPP TS 33.501 specification record — https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3169
- 3GPP lawful interception (TS 33.126/33.127/33.128) — https://www.3gpp.org/technologies/li
- GSMA interconnect security knowledge base (FS.11 / FS.19 / FS.21, member-gated) — https://www.gsma.com/solutions-and-impact/technologies/security/cybersecurity-knowledge-base/interworking-security/
- SEPP / N32 mechanics summary (secondary source) — https://blog.3g4g.co.uk/2020/06/5g-roaming-with-sepp-security-edge.html

**Network slicing and O-RAN**
- ESF, Potential Threats to 5G Network Slicing, 2022-12-13 — https://media.defense.gov/2022/Dec/13/2003132073/-1/-1/0/POTENTIAL%20THREATS%20TO%205G%20NETWORK%20SLICING_508C_FINAL.PDF
- NSA/CISA, 5G Network Slicing: Security Considerations, 2023-07-17 — https://www.cisa.gov/news-events/alerts/2023/07/17/nsa-cisa-release-guidance-security-considerations-5g-network-slicing
- CISA/NSA, Open RAN Security Considerations, 2022-09-15 — https://us-cert.cisa.gov/ncas/current-activity/2022/09/15/cisa-and-nsa-publish-open-radio-access-network-security
- O-RAN ALLIANCE Security Update 2026 (2026-02-24) — https://www.o-ran.org/blog/o-ran-alliance-security-update-2026
- O-RAN ALLIANCE Security Update 2025 — https://www.o-ran.org/blog/o-ran-alliance-security-update-2025

**Regulatory**
- FCC Declaratory Ruling FCC 25-9 (January 2025; rescinded) — https://docs.fcc.gov/public/attachments/FCC-25-9A1.pdf
- FCC Order on Reconsideration rescinding the ruling (Federal Register, 2025-12-15) — https://www.federalregister.gov/documents/2025/12/15/2025-22830/protecting-the-nations-communications-systems-from-cybersecurity-threats

---

*MITRE FiGHT™ and ATT&CK® are trademarks of The MITRE Corporation; 3GPP specifications are the property of the 3GPP Organizational Partners; GSMA documents are the property of the GSM Association; O-RAN specifications are the property of the O-RAN ALLIANCE. FiGHT structural counts were computed from the official v3.1.0 data file and MITRE publishes no official count page — recount from `fight.yaml` if exactness matters. This is an independent practitioner reference summary, not affiliated with or endorsed by any of these organizations; consult the upstream sources for authoritative and current content.*
