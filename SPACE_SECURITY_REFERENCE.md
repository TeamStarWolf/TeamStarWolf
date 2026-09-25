# Space Systems Security Reference

> **Space systems are critical infrastructure with a threat model no other domain has.** [The Aerospace Corporation's SPARTA](https://sparta.aerospace.org) (Space Attack Research and Tactic Analysis) framework gives defenders an ATT&CK-style taxonomy of **9 tactics** and **90 countermeasures (CM0001–CM0090)** for spacecraft and the systems that fly them — assets that cannot be rebooted by a technician, patched over a crossover cable, or physically inspected after compromise.

A satellite is a computer you can never touch again after launch, reachable only over an RF link, commanded from a ground network that looks like any other enterprise IT estate — and that ground network is where most real-world compromises start. The 2022 Viasat KA-SAT incident demonstrated the pattern publicly: a ground-side intrusion, a wiper pushed through a legitimate management network, and tens of thousands of user terminals dead on the morning of an invasion.

This reference covers the four segments of a space system and their attack surface, the SPARTA framework and its countermeasures, TT&C link protection with CCSDS SDLS, GPS/GNSS interference resilience, the Viasat case study, and the US standards and policy stack (SPD-5, NIST IR 8270/8401/8441/8323, CISA guidance) that a space cybersecurity program is built on.

**Related:** [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [D3FEND Countermeasures](D3FEND_REFERENCE.md) · [SDR & RF Security](SDR_RF_SECURITY_REFERENCE.md) · [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) · [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) · [Notable Incidents](NOTABLE_INCIDENTS.md)

---

## Why space systems security is different

| Property | Security consequence |
|---|---|
| **No physical access after launch** | No hands-on forensics, no hardware swap, no "reimage the box". Recovery depends entirely on what was designed in before launch |
| **Constrained SWaP** (size, weight, power) | Onboard security controls compete with the mission for CPU, memory, and power budget; heavyweight agents are usually impossible |
| **Long lifecycles** | Spacecraft fly for 15+ years on hardware and software frozen years before launch; crypto and protocols must survive that horizon |
| **RF is the only door** | Every interaction crosses an open radio link that can be jammed, intercepted, or — if unauthenticated — spoofed |
| **Ground segment is standard IT** | Mission operations centers run commodity OSes, VPNs, and remote access; they inherit the entire enterprise threat model |
| **Cyber + counterspace overlap** | Threats span cyber intrusion, electronic warfare (jamming/spoofing), and physical/kinetic effects; frameworks must cover more than malware |
| **Cascading dependencies** | GPS/GNSS timing underpins telecom, finance, and power grids; SATCOM outages cascade into other critical infrastructure (Viasat → wind turbines) |

Space Policy Directive-5 frames the adversary goal set precisely: activities that **manipulate, deny, degrade, disrupt, destroy, surveil, or eavesdrop on** space system operations. A defensive program has to answer all seven verbs, not just "malware on the ground network".

---

## Segments and attack surface

NIST IR 8270 and CISA's operator recommendations both decompose a space system into segments — the standard unit of attack-surface and risk analysis in this domain.

```
                    ┌─────────────────────────┐
                    │      SPACE SEGMENT      │
                    │  bus · payload · OBC    │
                    │  flight software        │
                    └───────────▲─────────────┘
                                │
                         LINK SEGMENT
                    TT&C uplink/downlink,
                    mission data, crosslinks
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ GROUND SEGMENT │    │  GROUND SEGMENT  │    │   USER SEGMENT   │
│ mission ops    │◄──►│  ground stations │    │ user terminals,  │
│ center (MOC)   │    │  & antennas      │    │ modems, GNSS     │
│ planning, FDS  │    │  (owned/leased)  │    │ receivers        │
└────────────────┘    └──────────────────┘    └──────────────────┘
        ▲
        │  corporate IT, remote access, vendors, supply chain
        └── the usual enterprise attack surface, now mission-critical
```

| Segment | What it contains | Representative attack surface |
|---|---|---|
| **Space** | Spacecraft bus, payload, onboard computers, flight software, RTOS | Malicious or malformed commanding, flight software supply chain, hosted payload trust boundaries, onboard resource exhaustion |
| **Ground** | Mission operations center, TT&C ground stations, mission planning, flight dynamics, archives | Everything in enterprise ATT&CK: phishing, VPN/remote-access compromise, credential theft, lateral movement to command consoles |
| **Link** | TT&C uplink/downlink, mission data downlink, inter-satellite crosslinks | Jamming, eavesdropping on unencrypted links, command replay or injection against unauthenticated links, hijacking transponders |
| **User** | User terminals, SATCOM modems, GNSS receivers, VSATs | Terminal/modem firmware compromise (AcidRain), default credentials, exposed management interfaces, GNSS spoofing of receivers |

**The practical asymmetry:** the space segment has the most exotic failure modes, but the ground and user segments carry most of the realized incidents — they are reachable from the internet, run commodity software, and are staffed by phishable humans. CISA's June 2024 operator recommendations and advisory AA22-076A are aimed almost entirely at ground and user segment hygiene for exactly this reason.

### The threat is wider than cyber

SPD-5's verb list (manipulate, deny, degrade, disrupt, destroy, surveil, eavesdrop) deliberately spans more than network intrusion, and SPARTA's scope statement matches it — compromise "via cyber and traditional counterspace means" (so stated on the [sparta.aerospace.org](https://sparta.aerospace.org) front page as of September 2026; some site pages, such as the FAQ, abbreviate the scope to "via cyber means", but the counterspace techniques are in the matrix itself). A space program's threat model therefore has three lanes, and the cyber team usually owns only part of each:

| Lane | Examples (taxonomy level) | Primary defensive lever |
|---|---|---|
| **Cyber** | Ground-network intrusion, hostile commanding, flight/ground software compromise, supply chain implants, terminal/modem malware | Everything in this document: segmentation, authenticated commanding, hardening, detection |
| **Electronic warfare** | Uplink/downlink jamming, GNSS jamming and spoofing, signal interception | Link margin and waveform design, authenticated links, interference monitoring and geolocation, PNT diversity |
| **Physical / kinetic** | Ground-site sabotage or seizure, threats to spacecraft themselves | Physical security, site redundancy, constellation-level resilience — outside this document's scope, but in SPARTA's |

The lanes interact: EW can be a denial tool while a cyber operation proceeds, and a cyber compromise of a ground station is often the cheapest path to an "EW-like" effect (transmitting from *your* antenna). Threat models and exercises should mix them rather than treating each in isolation.

---

## The SPARTA framework

**SPARTA — Space Attack Research and Tactic Analysis** — is created and maintained by [The Aerospace Corporation](https://sparta.aerospace.org) to break down information-sharing barriers around space-system TTPs. It catalogs how spacecraft may be compromised via cyber **and traditional counterspace** means — the scope as stated on the SPARTA homepage — and pairs every technique with defenses.

| | |
|---|---|
| **Maintainer** | The Aerospace Corporation |
| **Canonical URL** | [sparta.aerospace.org](https://sparta.aerospace.org) |
| **First release** | v1.0, October 2022 |
| **Current version** | **v4.0.1** (August 24, 2026 — website fixes, corrected STIX bundles, CM0003 TEMPEST/EMSEC modification); v4.0 debuted August 2026 at DEF CON 34 |
| **Tactics** | 9 |
| **Techniques** | 87 active techniques as rendered on the live matrix (September 2026); many techniques carry sub-techniques, with per-technique counts varying widely — consult the matrix rather than quoting a range |
| **Countermeasures** | 90 (CM0001–CM0090), tiered I/II/III |
| **Official mappings** | NIST SP 800-53 Rev. 5, MITRE D3FEND, ISO/IEC 27001, NASA best-practice guidance |
| **Tooling** | Navigator, Countermeasure Mapper, Control Mapper, Spacecraft Mapper, JSON Creator, Attack Flow, Spacetrail, STIX bundles |

### Version trajectory

| Milestone | Date | Significance |
|---|---|---|
| **v1.0** | October 2022 | Initial public release — the first ATT&CK-style TTP framework for space systems |
| **Countermeasure Utilization & Prioritization** | March 2026 | Published methodology scoring every CM on efficacy, feasibility (SWaP, architecture, maturity), and cost |
| **v4.0** | August 2026 (debuted at DEF CON 34) | Impact tactic redesign, Ground System Defense section, lifecycle-focused countermeasure revision |
| **v4.0.1** | August 24, 2026 | Current — website fixes, corrected STIX bundles, CM0003 TEMPEST/EMSEC modification |

### What changed in v4.0 (August 2026)

- **Impact tactic redesigned** — eight new techniques added (IMP-0007 through IMP-0014) and the original six (IMP-0001 through IMP-0006) deprecated, aligning impact language with how operators actually experience mission loss.
- **Dedicated Ground System Defense section** added — formal acknowledgment that ground-segment defense is a first-class part of the framework, not an afterthought.
- **All 90 countermeasures revised** with a lifecycle focus — countermeasures now speak to when in the program lifecycle (design, build, test, operate) each defense must be injected.

Earlier, in March 2026, Aerospace published a **Countermeasure Utilization & Prioritization** methodology that scores each CM on **efficacy**, **feasibility** (SWaP impact, architectural fit, technology maturity), and **cost** — turning the countermeasure list into a rankable engineering backlog rather than a checklist.

---

## SPARTA tactics and techniques

The nine tactics follow the familiar ATT&CK narrative arc, retold for spacecraft. Technique counts below are as rendered on the live matrix in September 2026 (deprecated techniques excluded); SPARTA does not publish a banner total, so treat per-tactic counts as primary and re-check [sparta.aerospace.org](https://sparta.aerospace.org) before quoting.

| # | Tactic | Techniques | What the adversary is doing |
|---|---|--:|---|
| 1 | **Reconnaissance** | 9 | Gathering mission information: orbital parameters, RF characteristics, ground infrastructure, organizational and supply-chain details |
| 2 | **Resource Development** | 5 | Building or acquiring what the operation needs — ground station access, RF equipment, capabilities against space systems |
| 3 | **Initial Access** | 13 | Getting a first foothold: compromising the ground segment or supply chain, exploiting the RF link, abusing trusted relationships |
| 4 | **Execution** | 18 | Getting hostile instructions to run — malicious commanding, exploiting flight software, abusing onboard interpreters and processes (the largest tactic) |
| 5 | **Persistence** | 5 | Surviving resets and contact gaps on a system nobody can physically touch |
| 6 | **Defense Evasion** | 12 | Defeating or blinding the limited onboard and ground defenses — masking activity in nominal telemetry, evading monitoring |
| 7 | **Lateral Movement** | 7 | Moving between ground and space, bus and payload, or spacecraft and spacecraft via crosslinks and hosted-payload boundaries |
| 8 | **Exfiltration** | 10 | Stealing mission data or spacecraft information, including over RF paths that never touch the victim's network monitoring |
| 9 | **Impact** | 8 | Producing mission effect — the v4.0-redesigned tactic (IMP-0007 – IMP-0014) covering denial, degradation, manipulation, and destruction outcomes |

Two structural notes for anyone used to ATT&CK:

- **Execution is the center of gravity.** Eighteen techniques — commanding a spacecraft *is* execution, so the tactic absorbs much of what Enterprise ATT&CK spreads across several tactics.
- **Counterspace is in scope.** SPARTA techniques include electronic warfare and other non-cyber counterspace means alongside network intrusion. A purely packet-shaped mental model misses a third of the matrix.

### Reading the matrix as a defender

Technique names and IDs live on the site; what stays stable is the defensive question each tactic forces. Per tactic:

| Tactic | The defender's question | Where the answer mostly lives |
|---|---|---|
| **Reconnaissance** | What about our mission is discoverable — RF parameters, ground-site details, staffing, suppliers — and what of it must we accept as public? | OPSEC and information handling; orbital/RF data is largely observable, so plan controls assuming the adversary has it |
| **Resource Development** | What does an operation against us need to acquire (ground station access, RF gear, insider help, capabilities), and can we raise that cost? | Vendor and partner vetting, insider risk, threat intelligence on capability proliferation |
| **Initial Access** | Which paths reach mission systems from outside — remote access, supply chain, RF, trusted integrators? | Ground enclave boundary, remote-access hardening, supply chain controls, link authentication |
| **Execution** | Can hostile instructions run — on the ground software stack or the spacecraft itself? | Command authentication, command-link protection, application control on ground hosts, flight software load controls |
| **Persistence** | Could an adversary survive our resets, contact schedules, and software reloads? | Verified boot/known-good reload paths, configuration baselining and drift detection, ground rebuild procedures |
| **Defense Evasion** | Which of our few sensors could be blinded or fooled, and would we notice? | Telemetry integrity, redundant/independent observables, protecting monitoring itself |
| **Lateral Movement** | What are the crossings — corporate↔mission, MOC↔station, bus↔payload, satellite↔satellite — and what enforces each boundary? | Segmentation and interface control at every seam, hosted-payload trust boundaries |
| **Exfiltration** | Which paths could move our mission data out, including RF paths that bypass network monitoring entirely? | Downlink encryption, data handling in the ground archive, egress monitoring in the mission enclave |
| **Impact** | Which mission effects (denial, degradation, manipulation, destruction) matter most, and which do our recovery plans actually cover? | Fault management, safe-mode design, recovery/contingency procedures rehearsed against *adversarial* — not just random — failure |

---

## SPARTA countermeasures (CM0001–CM0090)

SPARTA's defensive half is its differentiator: **90 countermeasures** with stable IDs, each mapped to the techniques it defeats. (A `CM-NA` placeholder — "Countermeasure Not Identified" — marks techniques without a cataloged defense; it is not one of the 90.)

| Dimension | How SPARTA organizes it |
|---|---|
| **Defense-in-depth layers** | CMs are grouped by architectural layer — the site's layering includes data protection, spacecraft software, the single-board computer, IDS/IPS, cryptography, the comms link, the ground segment, and up-front prevention (verify exact layer names on the [countermeasures page](https://sparta.aerospace.org/countermeasures/SPARTA) before enumerating them as canonical) |
| **Tiers** | **Tier I** — foundational, do-first defenses · **Tier II** — moderate · **Tier III** — advanced capabilities for high-threat missions |
| **Lifecycle** | Since v4.0, each CM is framed against the program lifecycle — many spacecraft defenses are only purchasable at design time |
| **Prioritization** | The March 2026 methodology scores efficacy × feasibility (SWaP, architecture, maturity) × cost per CM |

### Official control mappings

These are the mappings SPARTA itself publishes — use them as-is rather than inventing crosswalks:

| Mapped to | What you get |
|---|---|
| **NIST SP 800-53 Rev. 5** | Control IDs per countermeasure — the bridge from SPARTA into an RMF/ATO package or an existing 800-53 baseline |
| **MITRE D3FEND** | Defensive tactics, techniques, and digital artifacts per CM — joins SPARTA to the same countermeasure graph as this library's [D3FEND Reference](D3FEND_REFERENCE.md) |
| **ISO/IEC 27001** | Annex-control alignment for organizations governed by ISO-based ISMS programs |
| **NASA guidance** | NASA best-practice references per CM, useful for civil-space and NASA-contract programs |

**How to actually use this:** pick the spacecraft or mission class (the **Spacecraft Mapper** tool generates threat-informed CM baselines), pull the Tier I set as the floor, run the prioritization scoring against your SWaP and budget reality, and export the 800-53 mapping into whatever package your authorizing official reads. That is a threat-informed baseline traceable from technique → countermeasure → control — the same TTP-to-control pipeline this library uses for ATT&CK, applied to space.

### Building a SPARTA coverage map

The same coverage-mapping discipline this library applies to ATT&CK works on SPARTA, with the tooling SPARTA ships:

1. **Scope one mission** (one spacecraft class + its ground system), not the whole fleet — the CTEM scoping rule applies unchanged.
2. **Build a threat layer** in the SPARTA Navigator: which tactics/techniques are relevant to your orbit, architecture, and adversary assumptions. Be honest about the counterspace lanes you can't defend with software.
3. **Map deployed countermeasures** with the Countermeasure Mapper — what you actually have, per technique, per segment. Expect the space-segment column to be sparse on anything already flying; record that as accepted risk, not as a to-do.
4. **Score the gaps** with the prioritization methodology (efficacy × feasibility × cost). SWaP-infeasible countermeasures on a flying bird get closed on the *next* design, and compensated on the ground meanwhile — write both halves down.
5. **Export the STIX/JSON** and diff between review cycles, exactly like an ATT&CK Navigator layer — coverage drift is the metric leadership can read.
6. **Trace to controls** via the Control Mapper so the same work feeds the compliance package instead of duplicating it.

---

## How SPARTA parallels ATT&CK

SPARTA explicitly borrows MITRE ATT&CK's **methodology** — the tactic → technique → sub-technique → countermeasure model, matrix rendering, STIX representation, and Navigator-style tooling. It is a parallel matrix for a domain ATT&CK does not cover, not a part of ATT&CK.

| | MITRE ATT&CK (Enterprise) | SPARTA |
|---|---|---|
| **Maintainer** | MITRE | The Aerospace Corporation |
| **Domain** | Enterprise IT (plus Mobile, ICS matrices) | Spacecraft and space systems, including counterspace |
| **Technique IDs** | `T####` | Per-tactic prefixes (e.g., `IMP-####` for Impact) |
| **Defensive side** | Mitigations (M-codes), D3FEND as a separate project | Countermeasures (CM0001–CM0090) built in, with D3FEND/800-53/ISO mappings |
| **Evidence base** | Publicly reported in-the-wild behavior | Space-domain TTPs from research, incidents, and engineering analysis (public incident data is far scarcer) |

Rules for staying honest when you use them together:

- **There is no official SPARTA↔ATT&CK technique crosswalk.** SPARTA's site does not publish technique-to-technique ID mappings to ATT&CK, and none should be presented as if it exists. The official mappings are countermeasure-side (800-53r5, D3FEND, ISO 27001, NASA).
- ATT&CK does not currently include a dedicated space-segment matrix — its Enterprise matrix is still the right lens for the *ground segment*, which is ordinary IT. A workable division of labor: **ATT&CK for the ground network, SPARTA for the link and space segments**, joined where needed through their shared D3FEND countermeasure mappings.
- Where the two vocabularies describe similar behavior (e.g., a wiper on user terminals is *Data Destruction* [T1485] / *Disk Wipe* [T1561] in ATT&CK terms), treat any pairing as an informal analyst judgment and label it as such.

---

## Protecting TT&C and the link segment

Telemetry, Tracking & Commanding is the crown-jewel interface: whoever can command the bus owns the mission. Link-segment protection has a real standards answer.

### CCSDS Space Data Link Security (SDLS)

**CCSDS 355.0-B-2** (Blue Book, July 2022) defines the Space Data Link Security Protocol — security at the data link layer for the CCSDS framing protocols used by most civil and commercial missions:

| SDLS provides | Mechanism |
|---|---|
| **Authentication** | Cryptographic MAC over frames — a receiver rejects commands that were not produced by a holder of the key |
| **Confidentiality** | Frame payload encryption — telemetry and commands are not readable off the air |
| **Authenticated encryption** | Combined modes such as AES-GCM |
| **Anti-replay** | Sequence-number windows, so a recorded valid command cannot simply be transmitted again later |
| **Applies to** | CCSDS **TM** (telemetry), **TC** (telecommand), **AOS**, and **USLP** data link protocols |

### Key management is the hard part

SDLS makes the crypto tractable; the program-killer is managing key material across a mission that outlives three laptop refresh cycles. The working checklist:

| Concern | What good looks like |
|---|---|
| **Key hierarchy** | Separate long-lived key-encryption/master keys from operational session keys, so routine rotation never exposes the roots |
| **Mission-life inventory** | Key material sized and planned for the full design life plus extension — running out of keys on orbit is a real failure mode |
| **Rekey procedures** | Defined, tested procedures for routine rotation *and* emergency rekey under compromise assumptions, rehearsed before launch |
| **Compromise recovery** | Recovery keys held offline under split knowledge/dual control; a written decision tree for "we believe command keys are exposed" |
| **Ground protection** | Keys generated and stored in HSMs; command-generation hosts treated as part of the cryptographic boundary |
| **Crypto agility** | Algorithm and key-length headroom for a 15+ year horizon, with a documented path to swap primitives if one ages out |
| **Desync handling** | Anti-replay counter recovery procedures that do not degenerate into "turn authentication off to regain the bird" |

### Do / Don't for commanding

**Do**
- **Authenticate every command path**, including backup/emergency commanding and test interfaces. Unauthenticated "safe mode" or contingency command paths are a classic residual hole.
- **Enforce anti-replay** state on the spacecraft side, and define the recovery procedure for sequence-counter desynchronization *before* launch.
- **Plan key management for the full mission life**: key inventory sized for 15+ years, over-the-air rekey procedures, compromise-recovery keys stored offline, and crypto agility for algorithm aging.
- **Protect the ground crypto boundary** — SDLS moves trust to the ground key material and command-generation systems, so HSM-backed key storage and tightly controlled command-generation hosts become the real perimeter.
- **Monitor the link itself**: carrier power, spectrum occupancy, unexpected uplink activity at your slots, and command counters in telemetry reconciled against your own command log (commands the MOC never sent are the highest-value alert in the domain).

**Don't**
- Rely on "obscurity of the waveform" or proprietary protocol formats as access control — RF parameters are recoverable by a resourced observer.
- Treat encryption-without-authentication as command protection; integrity/authenticity is the property that stops hostile commanding.
- Leave engineering/development command dictionaries or simulator configurations (which describe exactly how to command the spacecraft) on the general corporate network.
- Assume the link is the attacker's cheapest path — a compromised MOC workstation sends perfectly authenticated hostile commands. Link crypto and ground hardening only work together.

---

## GPS/GNSS interference and PNT resilience

GNSS is a one-way, unauthenticated (for civil signals), extremely weak broadcast — which makes interference the most commonly encountered space-related threat for ordinary organizations. Keep the discussion of incidents conceptual; the defensive posture is what matters.

| Threat | What it is | Effect on the receiver |
|---|---|---|
| **Jamming** | Overpowering GNSS frequencies with noise | Loss of lock — position/timing outage; failure is at least *visible* |
| **Spoofing** | Transmitting counterfeit GNSS signals | Receiver computes a **wrong** position or time while appearing healthy — the dangerous case |
| **Meaconing** | Receiving and rebroadcasting genuine signals with delay | Position/time offset without crafting signals — a low-skill spoofing variant |

### Policy anchor

- **Executive Order 13905** (February 12, 2020) — "Strengthening National Resilience Through Responsible Use of Positioning, Navigation, and Timing Services" — establishes the US policy that PNT-dependent systems must be identified and made resilient.
- **NIST IR 8323 Rev. 1** (January 31, 2023; original February 2021) — the *Foundational PNT Profile* — applies the Cybersecurity Framework to responsible PNT use and is the working document for building a PNT resilience program.

### Receiver observables worth monitoring

Interference detection starts at the receiver, with observables most GNSS hardware already exposes:

| Observable | Nominal behavior | Interference signature |
|---|---|---|
| **C/N0 (carrier-to-noise density)** | Stable per-satellite profile for the antenna environment | Broad simultaneous drops (jamming); unusually uniform or elevated values across satellites (spoofing) |
| **AGC (automatic gain control)** | Steady within a characterized band | Sustained shifts indicate added RF energy in-band — a classic jamming tell |
| **Clock bias / drift** | Smooth, physically plausible evolution | Step changes or drift inconsistent with the local oscillator — a timing-attack red flag |
| **Position residuals / consistency** | Solutions agree across constellations and with known-fixed antenna position | A "moving" fixed site, or constellations that suddenly disagree |
| **Satellite geometry** | Matches published almanac for time and location | Signals from below the horizon or implausible geometry |
| **Cross-receiver comparison** | Independent receivers/antennas agree | One site diverging from its neighbors localizes the interference |

Route these to the SOC with thresholds, exactly like host telemetry. A fixed-site receiver that starts "moving" is not a maintenance ticket.

### Do / Don't for PNT-dependent systems

**Do**
- **Inventory PNT dependence first** (IR 8323's core move): which systems consume GNSS position, which consume GNSS *time*, and what breaks at what offset. Timing dependence hides in telecom, trading, power, and datacenter infrastructure.
- **Detect before you mitigate**: monitor receiver observables — C/N0 anomalies, sudden clock bias jumps, position residuals, unexpected constellation geometry — and alert on them like any other security telemetry.
- **Hold time through outages** with disciplined holdover oscillators sized to your accuracy requirement, and validate GNSS time against independent references (network time from trusted sources, multiple constellations/frequencies).
- **Diversify PNT sources** for critical functions: multi-constellation, multi-frequency receivers; non-GNSS timing paths; inertial or terrestrial augmentation where the mission justifies it.
- **Plan degraded-mode operations** — rehearse what operators do when PNT is flagged untrusted, the same way you rehearse network isolation.

**Don't**
- Treat GNSS as a trusted input just because it has always been right; civil GNSS signals carry no authentication.
- Let a single GNSS-disciplined clock be a silent single point of failure for logging, authentication (time-based tokens), and correlation across your security stack.
- Quote incident statistics without checking a primary source — interference reporting volumes change fast; the resilient-architecture guidance does not.

---

## Case study: the 2022 Viasat KA-SAT incident

The most instructive public space-system cyber incident to date — notable for *where* it happened (user and ground segments, not the satellite) and *how little* of it was exotic.

| Date | Event |
|---|---|
| **February 24, 2022** | As Russia invades Ukraine, an attack on Viasat's KA-SAT consumer broadband network renders satellite modems inoperable in Ukraine and across Europe. Spillover knocks out remote monitoring and control of roughly 5,800 Enercon wind turbines in Germany (a figure from public reporting) |
| **March 17, 2022** | CISA/FBI release joint advisory **AA22-076A**, "Strengthening Cybersecurity of SATCOM Network Providers and Customers" — hardening guidance for SATCOM operators and customers (the original release carried no formal attribution; the advisory was updated later) |
| **March 31, 2022** | SentinelLabs publishes analysis of **AcidRain**, an ELF MIPS wiper for modems and routers, noting code overlap with VPNFilter. Viasat confirms AcidRain was used in the incident |
| **May 10, 2022** | The EU, together with the US, UK, and other Five Eyes governments, formally attributes the attack to Russia |

### What actually happened, in segment terms

- **The satellite was never touched.** The compromise ran through a misconfigured VPN appliance into the KA-SAT **ground-segment management network**, per public reporting and Viasat's own statements.
- **The destructive payload landed on the user segment**: AcidRain wiped modem firmware/storage at scale, pushed through the legitimate management plane that existed to update those modems.
- **The blast radius was cross-sector**: a SATCOM attack became a wind-energy operations problem — the case study for why space systems are treated as critical infrastructure with cascading dependencies.

### Lessons defenders should actually implement

| Lesson | Concrete control |
|---|---|
| **Remote access into ground/management networks is the front door** | Harden and MFA every VPN and remote-access path into TT&C and network-management enclaves; audit appliance configurations against vendor hardening guides (AA22-076A's first theme) |
| **The management plane is a weapon against your own fleet** | Segment and monitor the systems that can mass-push firmware/config to terminals; require signing and staged rollout for anything the management plane distributes |
| **Least privilege between provider and customer segments** | AA22-076A: enforce least privilege, review trust relationships between SATCOM providers, integrators, and customers |
| **Wipers demand recovery engineering, not just prevention** | Out-of-band terminal re-provisioning, golden firmware images, and a tested mass-recovery procedure (Viasat had to ship replacement modems in bulk) |
| **Log and watch the boring infrastructure** | AA22-076A calls out logging and monitoring of SATCOM network gear — the intrusion path was visible territory: VPNs, management servers, network appliances |
| **Plan for spillover** | If your operations depend on SATCOM or any third-party link, treat its loss as a scenario in *your* IR and continuity planning, not just the provider's |

---

## Standards, policy, and program guidance

The US public-guidance stack, in the order a program usually consumes it:

| Document | Date | What it gives you |
|---|---|---|
| **Space Policy Directive-5 (SPD-5)** — *Cybersecurity Principles for Space Systems* | Signed September 4, 2020 | The policy foundation: US government civil/national-security and private space systems should use risk-based, cybersecurity-informed engineering against activities that manipulate, deny, degrade, disrupt, destroy, surveil, or eavesdrop on operations |
| **NIST IR 8270** — *Introduction to Cybersecurity for Commercial Satellite Operations* | Final July 25, 2023 | The on-ramp: introductory, CSF-aligned risk management for commercial satellite operators; establishes the segment decomposition used across the domain |
| **NIST IR 8401** — *Satellite Ground Segment: Applying the Cybersecurity Framework to Satellite Command and Control* | Final December 30, 2022 | CSF profile for the ground segment commanding satellite buses and payloads — the document to hand the MOC/ground-network owner |
| **NIST IR 8441** — *Cybersecurity Framework Profile for Hybrid Satellite Networks (HSN)* | Final September 25, 2023 | CSF profile for architectures mixing owned, leased, and commercial space/ground components — the multi-party trust problem |
| **NIST IR 8323 Rev. 1** — *Foundational PNT Profile* | January 31, 2023 | CSF profile for PNT-consuming systems, responding to EO 13905 |
| **CISA/FBI AA22-076A** — *Strengthening Cybersecurity of SATCOM Network Providers and Customers* | Originally March 17, 2022 | Post-Viasat hardening: secure authentication, least privilege, encryption, patching, and log monitoring across SATCOM providers and customers |
| **CISA SSCIWG** — *Recommendations to Space System Operators for Improving Cybersecurity* | June 6, 2024 | Per-segment risk and mitigation catalog aligned to NIST guidance, from CISA's Space Systems Critical Infrastructure Working Group; CISA's space hub is [cisa.gov/space-systems](https://www.cisa.gov/space-systems) |
| **CCSDS 355.0-B-2** — *Space Data Link Security (SDLS) Protocol* | Blue Book, July 2022 | The engineering standard for link-layer authentication/encryption of TM/TC/AOS/USLP |

**Assembly guide:** SPD-5 sets the mandate → IR 8270 frames the program → IR 8401 covers your ground segment (IR 8441 if your architecture is hybrid) → SDLS secures the link → IR 8323 covers your PNT dependence → CISA's recommendations and AA22-076A supply the operator-level hardening checklist → SPARTA turns all of it into technique-level coverage you can measure.

### AA22-076A distilled

The advisory's recommendation themes, translated into a SATCOM operator/customer checklist:

| Theme | Provider side | Customer side |
|---|---|---|
| **Secure authentication** | MFA on operator, administrator, and customer-portal access; kill shared accounts | MFA on the SATCOM provider portal and on any remote access to your terminals |
| **Least privilege** | Scope what management systems and support staff can touch per customer; review trust relationships with integrators | Assume the provider link is untrusted transport; don't extend internal trust across it |
| **Encryption** | Protect management and provisioning traffic in transit | Run your own encryption (VPN/application-layer) over the SATCOM link rather than trusting link-layer confidentiality alone |
| **Patching** | Timely updates on network appliances, VPN gateways, and management servers — the actual 2022 intrusion surface | Keep terminal/modem firmware current; track vendor advisories for your terminal fleet |
| **Log monitoring** | Centralize and review logs from network gear and management infrastructure; alert on anomalous provisioning actions | Log terminal behavior and connectivity; investigate fleet-wide anomalies as security events, not just outages |

---

## Defensive architecture and hardening

What the guidance above converges on, segment by segment. Threat-level descriptions stay at taxonomy level; the defensive detail is the point.

### Ground segment (highest-leverage, most attackable)

- **Enclave the mission network.** TT&C, mission planning, and flight dynamics live in their own segmented enclave with controlled, monitored interconnects to corporate IT — the Purdue-style zoning argument from [ICS/OT security](ICS_OT_SECURITY_REFERENCE.md) applies nearly verbatim.
- **Treat command-capable hosts as Tier-0 assets**: dedicated hardened workstations, no email/browsing, application allow-listing, EDR, and privileged access management for operator accounts.
- **MFA and least privilege on every remote path** — operator VPNs, vendor support access, antenna-site links, backup MOC connectivity. This is the exact surface that failed publicly in 2022.
- **Harden the boring gear**: VPN concentrators, jump hosts, network management servers, and station equipment get vendor-hardening-guide configuration, prompt patching, and centralized logging (AA22-076A's core recommendations).
- **Control the mission data path** separately from the command path — different trust levels, different monitoring.

### Space segment (design-time or never)

- **Authenticated, anti-replay commanding** (SDLS or mission equivalent) as a non-negotiable baseline.
- **Fault management with security in mind**: safe modes that do not silently drop link authentication; watchdog and reset behavior that an attacker cannot weaponize into denial of service.
- **Flight software integrity**: signed software/parameter loads, verified boot where the platform allows, and strict control of memory-write and software-load commands.
- **Onboard resource monitoring** as intrusion-sensitive telemetry: unexpected CPU/memory/bus utilization, unexpected mode transitions, command counters.
- **Hosted payload and rideshare boundaries**: treat other payloads as untrusted tenants; enforce bus/payload interface controls.

### Supply chain and lifecycle

- Apply [supply-chain security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) discipline to flight software, ground software, and hardware: provenance, SBOM where feasible, and integrity verification for everything that touches the spacecraft before and after launch. (In ATT&CK terms, ground-side supply chain compromise is T1195 — the enterprise matrix covers this part of the estate directly.)
- Security requirements enter at RFP/design time — SPARTA's lifecycle-focused countermeasures and tiering exist precisely because most spacecraft defenses cannot be retrofitted.
- Development and test environments (simulators, flatsats, engineering models) hold command dictionaries and flight software; protect them like production.

### User segment

- Terminal/modem firmware update paths: signed updates, staged rollout, and monitoring of the management plane that pushes them.
- Change default credentials, disable unneeded management interfaces, and inventory terminals so a mass-compromise is detectable and recoverable.
- Assume the SATCOM link is untrusted transport: customers run their own encryption over it and place terminals outside the internal trust boundary (AA22-076A's customer-side theme).
- GNSS receivers per the PNT section above.

---

## Detection and monitoring

Space programs get a detection stack in three layers — two of them familiar, one unique:

| Layer | Telemetry to collect | What to alert on |
|---|---|---|
| **Ground network (standard SOC)** | EDR, authentication logs, VPN/remote-access logs, netflow from the mission enclave, appliance syslog | Everything your enterprise SOC already hunts — phishing → credential use → lateral movement toward the mission enclave; new/unusual remote access to command-capable hosts |
| **Mission operations** | Command logs from the MOC, ground software audit trails, file transfers into the mission enclave, changes to command dictionaries/mission plans | Commands transmitted that reconcile against no operator action; out-of-window commanding; modification of planning products |
| **Spacecraft & link (domain-specific)** | Spacecraft telemetry (command counters, rejected-command counts, mode transitions, resource usage), RF ground truth (carrier power, spectrum monitoring, ranging anomalies), SDLS authentication-failure counters | Onboard command counter ≠ MOC send count; bursts of authentication/anti-replay failures; unexpected carriers on your uplink frequencies; telemetry excursions with no commanded cause |

Practical notes:

- **The single best space-domain detection** is reconciling the spacecraft's own accepted-command counter against the MOC's transmit log every pass. It is cheap, it is already in most telemetry streams, and it directly detects hostile commanding regardless of path.
- **SDLS failure counters are security telemetry**, not just link-quality data — route them to the SOC, not only to the flight controllers.
- **Baseline pass behavior**: contacts happen on a schedule; commanding outside scheduled passes, from unexpected ground stations, or at unusual volumes is a tight, low-noise anomaly class.
- Feed all three layers into one correlation point. A VPN anomaly in layer 1 plus an out-of-window command in layer 3 is an incident; separately, each may rate a shrug. Fold the spacecraft-specific alerts into existing [SIEM](SIEM_REFERENCE.md) and IR processes rather than building a parallel stovepipe.

### Exercise scenarios worth running

Space-flavored tabletops expose seams that generic IR exercises never touch. Candidates, all drawn from the public record or the guidance above:

| Scenario | What it tests |
|---|---|
| **Viasat replay** — management-plane compromise pushes destructive firmware to your terminal fleet | Management-plane segmentation, mass terminal recovery, provider/customer coordination, public communications |
| **Unattributed commanding** — spacecraft command counter shows accepted commands the MOC never sent | The reconciliation detection, link-compromise vs. ground-compromise triage, decision authority to inhibit commanding |
| **MOC operator credential theft** — valid operator credentials used from an anomalous source | PAM and MFA coverage on command paths, session monitoring, whether "valid credentials" bypasses every control you have |
| **GNSS timing spoof** — site timing shifts slowly; logs, tokens, and scheduling drift with it | PNT dependence inventory (IR 8323), holdover procedures, whether security tooling itself trusts the spoofed clock |
| **Ground station provider breach** — a leased/commercial station in your architecture reports an intrusion | Hybrid-architecture trust boundaries (IR 8441's territory), contractual visibility, ability to operate without that station |
| **Contact-window denial** — uplink jamming during a critical operations window | EW/cyber coordination, alternate station fallback, and whether ops can distinguish interference from equipment failure |

---

## Standing up the program

A sequencing that matches how the guidance stack was written to be consumed — each phase produces something a leadership team can see:

| Phase | Focus | Concrete outputs |
|---|---|---|
| **1. Frame** | SPD-5 principles + NIST IR 8270 as the program charter | Named accountable owner; segment-by-segment system inventory; PNT dependence inventory started |
| **2. Baseline the ground** | NIST IR 8401 profile + AA22-076A / CISA 2024 recommendations as the checklist | Mission-enclave segmentation reviewed; MFA on all remote paths; command-capable hosts identified and hardened; logging into the SOC |
| **3. Baseline the link** | SDLS (or mission equivalent) posture review | Authentication/anti-replay status per command path, including contingency paths; key-management plan with mission-life horizon |
| **4. Map coverage** | SPARTA Navigator + Countermeasure Mapper on one mission | Threat layer, countermeasure layer, prioritized gap list scored by efficacy/feasibility/cost |
| **5. Detect** | The three-layer detection stack above | Command-counter reconciliation live; SDLS failure counters and RF monitoring routed to the SOC; pass-schedule baselining |
| **6. Exercise & iterate** | Tabletops from the scenario table; re-run the coverage map on a cadence | Findings fed back into the gap list; coverage drift tracked between cycles |

### Metrics that show the program is real

| Metric | Why it matters |
|---|---|
| **% of command paths with authentication + anti-replay** (including contingency paths) | The single most direct measure of hostile-commanding risk |
| **Remote-access paths into the mission enclave with MFA / total** | The Viasat lesson, quantified |
| **Command reconciliation coverage** (% of passes where spacecraft counters are checked against MOC logs) | Detection of hostile commanding, regardless of path |
| **SPARTA Tier I countermeasure coverage per mission** | Foundation-first progress, in the framework's own terms |
| **Prioritized gaps closed vs. accepted per cycle** | Whether the coverage map drives work or decorates it |
| **PNT-dependent systems with validated holdover/fallback** | EO 13905 / IR 8323 posture in one number |
| **Mean time to recover a mass-compromised terminal fleet** (from exercise) | Wiper resilience as a measured capability, not an assumption |

> **Failure modes to avoid:** treating the spacecraft as the primary attack surface while the VPN concentrator rots; buying link crypto but leaving contingency command paths unauthenticated; a coverage map built once for an audit and never diffed again; PNT resilience scoped to navigation while every log timestamp trusts one GNSS clock; and security requirements arriving after the design review where they were still purchasable.

---

## SPARTA tooling and related frameworks

| Resource | What it does |
|---|---|
| **SPARTA Navigator** | ATT&CK-Navigator-style layer building over the SPARTA matrix — coverage maps, threat-profile overlays |
| **Countermeasure Mapper** | Technique → countermeasure selection and gap views |
| **Control Mapper** | Countermeasure → NIST 800-53r5 / ISO control traceability |
| **Spacecraft Mapper** | Threat-informed countermeasure baselining per spacecraft/mission class |
| **JSON Creator / STIX bundles** | Machine-readable matrix and mappings for pipelines and tooling — the same integration pattern this library uses for ATT&CK data |
| **Attack Flow** | Builds and visualizes multi-step attack sequences chaining SPARTA techniques — listed on the SPARTA resources page as an interactive tool plus a code repository |
| **Spacetrail** | Educational companion game in the SPARTA resource set — an Oregon Trail-style survival sim (per Aerospace's DEF CON 34 materials) about keeping mission assets online through hazards; awareness/training, not analysis tooling |
| **ESA SPACE-SHIELD** | The main European parallel: an ATT&CK-like knowledge base of adversary tactics and techniques for the space segment and communication links, at [spaceshield.esa.int](https://spaceshield.esa.int/). Maintained by ESA; version/counts not tracked here — consult the site directly |

**In this library:** SPARTA's D3FEND mappings join the [D3FEND Reference](D3FEND_REFERENCE.md); ground-segment work runs on the [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) and [Detection Strategies](detections/strategies/README.md); RF fundamentals live in [SDR & RF Security](SDR_RF_SECURITY_REFERENCE.md); the segmentation and safety-critical operations mindset carries over from [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md); and the Viasat case study above is this library's write-up of that incident ([Notable Incidents](NOTABLE_INCIDENTS.md) covers the broader incident record but does not currently include Viasat).

---

## Domain vocabulary

The minimum vocabulary for reading space-security guidance without stalling:

| Term | Meaning |
|---|---|
| **Bus** | The spacecraft platform itself — power, attitude control, thermal, computing — as distinct from the payload |
| **Payload** | The part of the spacecraft that performs the mission (imager, transponder, sensor); may have a different owner than the bus |
| **Hosted payload** | A payload owned by one party flying on another party's bus — a trust boundary in orbit |
| **OBC / flight software** | Onboard computer and the software that flies the spacecraft, typically on a real-time operating system |
| **TT&C** | Telemetry, Tracking & Commanding — the housekeeping link that monitors and controls the spacecraft |
| **TM / TC** | Telemetry (down) / Telecommand (up) — the CCSDS data link protocols for each direction |
| **AOS / USLP** | Advanced Orbiting Systems and Unified Space Data Link Protocol — further CCSDS data link protocols covered by SDLS |
| **SDLS** | Space Data Link Security — CCSDS 355.0-B-2, link-layer authentication/encryption for TM/TC/AOS/USLP |
| **MOC** | Mission Operations Center — where operators plan and command the mission |
| **Pass / contact** | The scheduled window when a ground station can communicate with a satellite |
| **Crosslink / ISL** | Inter-satellite link — satellite-to-satellite communication, a lateral-movement seam |
| **Transponder** | A payload channel that relays communications traffic (bent-pipe SATCOM) |
| **VSAT** | Very Small Aperture Terminal — the class of user terminals hit in the Viasat incident |
| **Flatsat** | A ground-based replica of spacecraft avionics used for development and test — holds flight software and command knowledge, protect accordingly |
| **SWaP** | Size, Weight, and Power — the budget every onboard security control must fit inside |
| **PNT / GNSS** | Positioning, Navigation, and Timing / Global Navigation Satellite Systems (GPS, Galileo, GLONASS, BeiDou) |
| **Meaconing** | Rebroadcast of genuine navigation signals with delay to induce position/timing error |
| **Bent pipe** | A transparent relay architecture — the satellite retransmits what it receives without processing it |

---

## Using this reference with the rest of the library

| Goal | How |
|---|---|
| **Assess a space program's exposure** | Run the [CTEM loop](CTEM_REFERENCE.md) with the mission enclave as the scope; use the SPARTA coverage-map workflow above as the discovery/prioritization engine |
| **Defend the ground segment** | It's enterprise IT — use the [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md), and [Detection Strategies](detections/strategies/README.md) directly |
| **Join SPARTA to your countermeasure graph** | Through its official D3FEND mappings and the [D3FEND Reference](D3FEND_REFERENCE.md) — the shared defensive vocabulary between matrices |
| **Understand the RF layer** | [SDR & RF Security](SDR_RF_SECURITY_REFERENCE.md) covers the radio fundamentals behind jamming, interception, and spoofing |
| **Borrow the operational mindset** | [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) — safety-critical operations, segmentation zones, and engineering-driven change control translate almost directly |
| **Brief the incident history** | The Viasat case study above — this library's coverage of that incident — plus [Notable Incidents](NOTABLE_INCIDENTS.md) for incidents in other domains |
| **Secure what you buy and build** | [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) for the flight/ground software pipeline; [Cryptography](CRYPTOGRAPHY_REFERENCE.md) for the key-management foundations |

---

## Sources

- SPARTA — The Aerospace Corporation: [sparta.aerospace.org](https://sparta.aerospace.org) · [version updates](https://sparta.aerospace.org/resources/updates-current) · [countermeasures](https://sparta.aerospace.org/countermeasures/SPARTA) · [resources](https://sparta.aerospace.org/resources/)
- Aerospace Corporation, *Understanding Space-Cyber Threats with the SPARTA Matrix*: [aerospace.org](https://aerospace.org/article/understanding-space-cyber-threats-sparta-matrix)
- Aerospace Corporation, *SPARTA 4.0 makes its debut at DEF CON* (Spacetrail description): [aerospace.org](https://aerospace.org/kickstage/sparta-40-makes-its-debut-def-con)
- NIST IR 8270 (final, 2023-07-25): [csrc.nist.gov/pubs/ir/8270/final](https://csrc.nist.gov/pubs/ir/8270/final)
- NIST IR 8401 (final, 2022-12-30): [csrc.nist.gov/pubs/ir/8401/final](https://csrc.nist.gov/pubs/ir/8401/final)
- NIST IR 8441 (final, 2023-09-25): [csrc.nist.gov/pubs/ir/8441/final](https://csrc.nist.gov/pubs/ir/8441/final)
- NIST IR 8323 Rev. 1 (2023-01-31), responding to EO 13905 (2020-02-12): [csrc.nist.gov/pubs/ir/8323/final](https://csrc.nist.gov/pubs/ir/8323/final)
- Space Policy Directive-5 (2020-09-04): [cisa.gov](https://www.cisa.gov/resources-tools/resources/space-policy-directive-5)
- CISA/FBI AA22-076A (orig. 2022-03-17): [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-076a)
- CISA SSCIWG operator recommendations (2024-06-06): [cisa.gov](https://www.cisa.gov/resources-tools/resources/recommendations-space-system-operators-improving-cybersecurity) · space hub: [cisa.gov/space-systems](https://www.cisa.gov/space-systems)
- CCSDS 355.0-B-2, Space Data Link Security Protocol (July 2022): [ccsds.org](https://ccsds.org/Pubs/355x0b2.pdf)
- SentinelLabs, *AcidRain: A Modem Wiper Rains Down on Europe* (2022-03-31): [sentinelone.com](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/)
- CCDCOE Cyber Law Toolkit, *Viasat KA-SAT attack (2022)*: [cyberlaw.ccdcoe.org](https://cyberlaw.ccdcoe.org/wiki/Viasat_KA-SAT_attack_(2022))
- Viasat hack attribution timeline (May 10, 2022 EU/US/UK statements): [en.wikipedia.org/wiki/Viasat_hack](https://en.wikipedia.org/wiki/Viasat_hack)
- ESA SPACE-SHIELD: [spaceshield.esa.int](https://spaceshield.esa.int/)

---

*SPARTA is created and maintained by The Aerospace Corporation; MITRE ATT&CK® and D3FEND™ are trademarks of The MITRE Corporation; SPACE-SHIELD is maintained by ESA. This is an independent practitioner reference summary, not affiliated with or endorsed by any of these organizations — consult the upstream sources for authoritative and current content. Technique and countermeasure counts reflect the SPARTA matrix as rendered in September 2026 (v4.0.1) and will drift; re-verify before quoting.*
