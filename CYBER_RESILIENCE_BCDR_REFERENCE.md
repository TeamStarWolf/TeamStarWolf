# Cyber Resilience & BCDR Reference

> **Business continuity and disaster recovery became a security discipline the day adversaries started attacking the recovery capability itself.** [NIST SP 800-34 Rev. 1](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final) (2010) still supplies the planning vocabulary — BIA, MTD, RTO, RPO, plan types, alternate sites — but it was written for floods, fires, and failed disks, not for an adversary who encrypts the backups, takes Active Directory with them, and is already inside the DR site because it shares the production domain. This reference joins the classical canon ([SP 800-34](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final), [ISO 22301:2019](https://www.iso.org/standard/75106.html), [SP 800-84](https://csrc.nist.gov/pubs/sp/800/84/final)) with the cyber-native layer built on top of it: [NIST SP 800-160 Vol. 2 Rev. 1](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final) cyber-resiliency engineering, CISA's resilience assessments and exercise packages, and Microsoft's [AD Forest Recovery Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide) — because in a cyber disaster, identity recovers first or nothing does.

Ransomware is the scenario that forced the merger. When encryption of production **and** backups became a business model, "the DR plan" stopped being an IT compliance artifact and became the control that decides whether an incident is a bad week or an existential event. [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) owns the ransomware-specific program — backup architecture, tripwires, payment policy. This document is the continuity discipline around it: impact analysis, recovery objectives, plan taxonomy, resiliency engineering, identity recovery, alternate processing, exercising, governance, and metrics.

**Related:** [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) · [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [IR Playbooks](IR_PLAYBOOKS.md) · [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) · [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md)

| | |
|---|---|
| **Read this when** | writing or overhauling a DR/BC plan for cyber scenarios, setting or defending RTO/RPO/MTD targets, planning an AD forest recovery or a DR exercise program |
| **Start at** | [Scope & how to use this reference](#scope-amp-how-to-use-this-reference) · [How cyber scenarios break classical DR assumptions](#how-cyber-scenarios-break-classical-dr-assumptions) · [Identity recovery first](#identity-recovery-first) |

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **Backup architecture, immutability, restore-order waves, payment policy** | [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) |
| **The response procedure during an active incident** | [IR Playbooks](IR_PLAYBOOKS.md) · [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md) |
| **AD attack and hardening detail** (what you are recovering *from*) | [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) |
| **Framework comparisons and compliance program context** | [Frameworks](FRAMEWORKS.md) · [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) · [GRC Reference](GRC_REFERENCE.md) |
| **Control-to-technique mappings** (CP family → ATT&CK Impact techniques) | [Controls Mapping](CONTROLS_MAPPING.md) |
| **The continuity/resilience discipline itself** — BIA, RTO/RPO/MTD, plans, testing, governance, metrics | **This document** |

Everything here is defensive and program-level. Attacker behavior appears only in the language public advisories use; defender actions are concrete.

---

## Why BCDR became a security problem

Classical BCDR grew up answering natural and mechanical hazards: the data center floods, the region loses power, the SAN dies. Those scenarios share three properties that quietly became design assumptions — the disaster is **external** (nobody is fighting back), **local** (somewhere to fail over *to* still exists), and **integrity-preserving** (the data you saved yesterday is good, you just need it back).

Ransomware violates all three at once, deliberately. ATT&CK documents the intent directly: [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) covers destruction of shadow copies, backup catalogs, and reachable "online" backups, expressly to augment the effects of [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) — and in incident reporting that destruction typically lands shortly before encryption begins. The adversary reads your DR design as an attack surface: whatever recovery path a domain credential can reach, they can reach.

The result is a discipline shift, not just a new scenario row in the risk register:

| Era | Continuity question | Owning function |
|---|---|---|
| **Classical DR** | Can we resume IT service after a facility or hardware loss? | IT operations / facilities |
| **Business continuity** | Can the *business process* continue through any disruption? | Risk / continuity office |
| **Cyber resilience** | Can we deliver critical services **while under attack**, and recover **from an adversary who targeted recovery**? | Security + IT + business, jointly |

The joint [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) (CISA, MS-ISAC, NSA, FBI — current edition October 2023) makes the merged ownership explicit in its backup guidance: maintain *offline, encrypted* backups of critical data and "regularly test the availability and integrity of backups in a disaster recovery scenario," maintain golden images of critical systems, and consider immutable storage. That is DR guidance published by security agencies — the merger, in one sentence.

---

## Core concepts — BIA, MTD, RTO, RPO

### Business impact analysis

The BIA is step 2 of SP 800-34's process and the load-bearing wall of everything downstream: it identifies mission/business processes, maps them to the systems and dependencies that support them, and characterizes the impact of losing them over time. Recovery priorities, RTO/RPO targets, alternate-site tier, and spend all derive from it — a DR plan without a current BIA is a technology preference, not a risk decision. ISO's dedicated BIA guidance is [ISO/TS 22317:2021](https://www.iso.org/standard/79000.html) (second edition, replacing the 2015 TS).

**Cyber twist the classical BIA misses:** score *dependency concentration*, not just process criticality. Identity (AD/Entra), DNS, PKI, virtualization management, and the backup platform rarely appear as "business processes," yet every process depends on them — which is exactly why adversaries target them. Give shared infrastructure services their own BIA entries with the shortest RTOs in the plan.

### The recovery metrics, per SP 800-34

SP 800-34 Rev. 1 defines the three numbers everything else negotiates against (definitions verified against the [publication PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf)):

| Metric | SP 800-34 definition (condensed) | Who sets it | Cyber-scenario caveat |
|---|---|---|---|
| **MTD** — Maximum Tolerable Downtime | "The total amount of time the system owner/authorizing official is willing to accept for a mission/business process outage or disruption," including *all* impact considerations | Business / authorizing official | Cyber outages are typically **multi-process and simultaneous** — MTDs set per process in isolation understate the aggregate impact of everything being down at once |
| **RTO** — Recovery Time Objective | "The maximum amount of time that a system resource can remain unavailable before there is an unacceptable impact on other system resources, supported mission/business processes, and the MTD" — normally shorter than the MTD | IT + business, per system | Clock starts at *declaration*, but cyber incidents delay declaration (investigation, scoping, eradication) — budget that lag inside the MTD |
| **RPO** — Recovery Point Objective | "The point in time, prior to a disruption or system outage, to which mission/business process data can be recovered (given the most recent backup copy of the data)" — explicitly **not** part of the MTD | Business, per data set | The most recent backup may be *compromised*; the operative restore point is the last **clean** copy, which integrity validation decides, not the backup schedule ([below](#how-cyber-scenarios-break-classical-dr-assumptions)) |

```
                RPO                                RTO
      ◄──────────────────────►◄─────────────────────────────────────►
                                                                          time
  ────┼───────────────────────┼──────────────────────────────────────┼────►
   last usable            DISRUPTION                            service
   backup copy                │                                 restored
                              │
      ◄── data loss window ──►◄───────── outage window ──────────────►
                              │
                              ◄────────────── MTD ────────────────────►
                                 (RTO must fit inside it; RPO is a
                                  data-loss tolerance, not downtime)
```

SP 800-34 adds a governance teeth-check worth keeping verbatim in policy: if the RTO **cannot** be met and the MTD is inflexible, initiate a Plan of Action and Milestones — a documented gap with an owner and a date, not a shrug.

### ISO terminology, for translation

The ISO 22300 series (vocabulary and the ISO 22313:2020 guidance around ISO 22301) conventionally uses **MTPD** (maximum tolerable period of disruption, sometimes seen as **MAO**, maximum acceptable outage) for roughly the ground SP 800-34's MTD covers, and **MBCO** (minimum business continuity objective) for the minimum level of service acceptable *during* the disruption. Exact definitions sit in the series' paywalled texts — treat the terms as translation aids across audit regimes, and pull precise wording from the editions your auditors cite rather than from this summary.

---

## How cyber scenarios break classical DR assumptions

SP 800-34 dates to 2010 and is scoped to federal information systems; it does not discuss ransomware, encrypted backups, or the loss of Active Directory. The failure modes below are this document's own analysis, grounded in the ransomware advisory record (see [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md)) and post-incident reporting — presented here precisely because the classical canon predates them.

| Classical assumption | How the cyber scenario breaks it | Design response |
|---|---|---|
| **Backups will be there when needed** | T1490 behavior: shadow copies deleted, backup catalogs destroyed, network-reachable repositories encrypted; replication faithfully replicates the encryption | Offline + immutable tiers outside the production identity domain; backup-console audit logging as a detection source — architecture in [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md) |
| **The newest backup is the best backup** | The newest backup may contain the intrusion (persistence, tooling, poisoned data); *last copy ≠ last clean copy* | Integrity-driven restore-point selection: scan/validate before restore, restore into isolation first, pick the restore point by forensic evidence, not by timestamp |
| **Retention only needs to cover the outage** | Dwell time between initial access and encryption commonly exceeds short retention windows — a 7-day cycle can age out every clean copy before anyone knows there was an intrusion | Size retention to a realistic dwell-time assumption; keep periodic long-horizon copies (weekly/monthly) beyond the operational window |
| **The DR site is trustworthy by construction** | A warm/hot site joined to the production forest shares its identity blast radius; replicated AD is replicated compromise; the adversary's credentials work there too | Separate identity plane and credentials for recovery infrastructure; an isolated recovery environment for rebuild-and-validate before reconnection |
| **Failover restores service** | Failing over a compromised workload relocates the adversary along with it | Eradicate before failover; validate each recovered wave against detection tripwires before opening it to users |
| **Core services (AD, DNS, DHCP, PKI) are ambient** | In a cyber disaster they are the first casualty — or the attack vector itself; nothing authenticates, resolves, or decrypts without them | Identity-first recovery ordering ([below](#identity-recovery-first)); infrastructure services carry their own BIA entries and the shortest RTOs |
| **Disaster declaration is obvious** | Cyber disruption is gradual, ambiguous, and often deliberately timed for weekends and holidays; teams burn MTD hours debating whether "this is the event" | Pre-authorized declaration criteria that include security triggers (confirmed T1490-class activity, EDR mass-tamper, backup-console compromise), with named declarers and deputies |
| **You can coordinate the recovery over corporate comms** | Email, chat, VoIP, and the intranet may be encrypted, monitored by the adversary, or evidence | Out-of-band communications provisioned in peacetime ([below](#alternate-processing-and-communications-planning)) |
| **One plan activation at a time** | Double extortion runs the DR plan, the IR plan, the crisis-communications plan, and legal/regulatory clocks **concurrently** | Exercise the plans together, not separately; one incident commander structure spanning them |

**Do**
- Write the cyber scenario into the DR plan explicitly — "total loss of primary data center **and** primary identity **and** online backups" — and derive requirements from it.
- Define the *last clean copy* decision: who determines it, on what forensic evidence, and what the RPO becomes when it moves.
- Treat declaration lag as a budgeted quantity inside the MTD.

**Don't**
- Present any of the above as SP 800-34 content — the guide is the vocabulary, not the threat model.
- Let "we replicate to a second region" stand in for a backup strategy; replication is an availability control, not a recovery control.

---

## NIST SP 800-34 — the contingency planning canon

**Citation discipline first.** The current edition is **SP 800-34 Rev. 1** (May 2010), updated November 11, 2010 with errata — cite the [upd1 page](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final). CSRC trap: the pre-errata page for Rev. 1 displays "(Withdrawn)", which refers only to the superseded May 2010 print, not the publication; the original 2002 SP 800-34, however, [is genuinely withdrawn](https://csrc.nist.gov/pubs/sp/800/34/final), superseded by Rev. 1. No Rev. 2 exists as of September 2026.

### The seven-step contingency planning process

| Step | Activity | The cyber-era emphasis |
|---|---|---|
| **1** | Develop the contingency planning policy statement | Name security as a co-owner; include cyber scenarios in scope |
| **2** | Conduct the business impact analysis (BIA) | Add shared-infrastructure dependencies (identity, DNS, backup platform) as first-class entries |
| **3** | Identify preventive controls | This is where the [ransomware hardening program](RANSOMWARE_DEFENSE_REFERENCE.md) plugs in |
| **4** | Create contingency strategies | Backup tiers, alternate sites, cloud recovery paths — designed against an adversary, not just an outage |
| **5** | Develop the information system contingency plan | Keep a reachable copy *outside* the systems it recovers |
| **6** | Ensure plan testing, training, and exercises | The [testing tiers](#testing-tiers-tabletop-to-full-failover) below; companion guidance in SP 800-84 |
| **7** | Ensure plan maintenance | "A living document that is updated regularly" — governance section below |

### The eight plan types

SP 800-34 Section 2.2 taxonomizes the planning landscape so one document is never asked to do everything. Scope summaries are condensed; the plan names are the guide's own.

| Plan | Scope (condensed) | Security-relevant note |
|---|---|---|
| **Business Continuity Plan (BCP)** | Sustaining mission/business processes during and after disruption | The business-side umbrella; the BIA feeds it |
| **Continuity of Operations (COOP) Plan** | Continuing an organization's essential functions at an alternate site (federal continuity lineage) | Where "essential functions" get named and ranked |
| **Crisis Communications Plan** | Internal and external communications during the event | In double extortion, activated on day one, not after recovery |
| **Critical Infrastructure Protection (CIP) Plan** | Protection of critical-infrastructure components | Sector obligations; see [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) |
| **Cyber Incident Response Plan** | Detecting and responding to attacks on the organization's systems | This library's [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md) and [IR Playbooks](IR_PLAYBOOKS.md) |
| **Disaster Recovery Plan (DRP)** | Relocating and restoring system operations, typically at an alternate site, after a major (usually physical) disruption | The document most in need of the cyber rewrite above |
| **Information System Contingency Plan (ISCP)** | Recovery of a *single* information system, site change or not | The per-system unit of work; federal systems carry one per system |
| **Occupant Emergency Plan (OEP)** | Personnel safety and evacuation | Out of cyber scope, but shares the activation machinery |

In a ransomware event the shaded reality is that **BCP, DRP, cyber IR plan, and crisis communications plan activate concurrently** — which is the argument for exercising them together and for a single command structure across them.

### Alternate-site readiness continuum

SP 800-34 describes five alternate-site types; detail in the [alternate processing section](#alternate-processing-and-communications-planning) below: **cold → warm → hot → mobile → mirrored**, where mirrored sites are "fully redundant facilities with automated real-time information mirroring."

### Companions

- **[SP 800-84](https://csrc.nist.gov/pubs/sp/800/84/final)** (2006) — Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities; still final and non-withdrawn, the TT&E methodology behind step 6.
- **[SP 800-53 Release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)** (August 27, 2025) — the CP (Contingency Planning) control family is the control-level anchor; see [Plan governance](#plan-governance-and-maintenance).

---

## ISO 22301 and the business continuity management system

Where SP 800-34 is a planning guide for systems, **ISO 22301** is a certifiable *management system* standard for the whole organization: leadership commitment, scoped BCMS, documented BIA and risk assessment, strategies, procedures, exercising, and continual improvement, on the ISO management-system clause skeleton. Organizations certify against it; auditors and customers ask for it by name.

| Standard | Current edition | Role |
|---|---|---|
| **[ISO 22301](https://www.iso.org/standard/75106.html)** | 2019 (2nd edition, developed by ISO/TC 292; cancels and replaces ISO 22301:2012) **plus [Amd 1:2024](https://www.iso.org/standard/88412.html)** (climate action changes) | BCMS *requirements* — the certifiable document; cite it as "ISO 22301:2019 as amended" |
| **ISO 22313** | 2020 | *Guidance* on the use of ISO 22301 — the how-to companion |
| **[ISO/TS 22317](https://www.iso.org/standard/79000.html)** | 2021 (2nd edition; cancels and replaces the 2015 TS) | Business impact analysis guidelines |
| **ISO 22300 (series vocabulary)** | — | Terminology for the 22300 family (MTPD/MAO/MBCO usage lives here and in 22313, per the hedge above) |

Within 22301:2019, clause **8.2.2** carries the BIA requirement and **8.2.3** the risk assessment — the two analyses every downstream strategy must trace to. (ISO standards are paywalled and cannot be quoted at length; this section is an attributed summary — work from the purchased text for implementation.)

**How the two canons fit together:** run the BCMS (ISO 22301) as the organizational governance shell; use SP 800-34's process and plan taxonomy as the systems-level machinery inside it; and let the cyber scenarios above drive both. For certification-program mechanics (scoping, audit cycles, management review), see [GRC Reference](GRC_REFERENCE.md).

---

## Cyber-resiliency engineering — NIST SP 800-160 Vol. 2

Contingency planning assumes you can *plan around* an adverse event. **[SP 800-160 Vol. 2 Rev. 1](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final)** (December 2021; Ross, Pillitteri, Graubart, Bodeau, McQuaid — NIST with MITRE) takes the complementary position: engineer the systems themselves to keep delivering under attack. It defines cyber resiliency as the ability to **"anticipate, withstand, recover from, and adapt to adverse conditions, stresses, attacks, or compromises on systems that use or are enabled by cyber resources"** (the publication's glossary definition) — and unlike classical DR, it explicitly assumes an intelligent adversary who may already be inside.

The framework's constructs (all counts verified against the [publication PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v2r1.pdf)):

| Construct | Count | The list |
|---|---|---|
| **Goals** | 4 | Anticipate · Withstand · Recover · Adapt |
| **Objectives** | 8 | Prevent or Avoid · Prepare · Continue · Constrain · Reconstitute · Understand · Transform · Re-Architect |
| **Techniques** | 14 | Adaptive Response · Analytic Monitoring · Contextual Awareness · Coordinated Protection · Deception · Diversity · Dynamic Positioning · Non-Persistence · Privilege Restriction · Realignment · Redundancy · Segmentation · Substantiated Integrity · Unpredictability |
| **Strategic design principles** | 5 | Focus on Common Critical Assets · Support Agility and Architect for Adaptability · Reduce Attack Surfaces · Assume Compromised Resources · Expect Adversaries to Evolve |
| **Structural design principles** | 14 | Enumerated in the publication's Table D-9 — consult the PDF for the list |

Each technique decomposes further into implementation approaches; the publication does not give a headline count for those, so resist secondary sources that do.

**Reading it as a BCDR practitioner** (this document's mapping, not NIST's): *Redundancy*, *Segmentation*, and *Substantiated Integrity* are your backup tiers, isolated recovery environment, and clean-copy validation wearing engineering names; *Non-Persistence* underwrites golden-image rebuilds over in-place cleanup; *Assume Compromised Resources* is the design stance the whole [assumptions table](#how-cyber-scenarios-break-classical-dr-assumptions) above demands. Two of the eight objectives — **Continue** and **Reconstitute** — are the continuity mission stated as engineering outcomes. Related library material: [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) (the Deception technique), [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) (Segmentation), [D3FEND](D3FEND_REFERENCE.md) (countermeasure vocabulary).

Use SP 800-160v2 at the architecture review, not in the DR binder: it is a systems-engineering catalog for making the *next* system inherently recoverable, while SP 800-34 recovers the estate you have.

---

## Identity recovery first

Every other recovery step authenticates against the directory: backup consoles, hypervisor managers, storage arrays, the SIEM, remote access for the recovery team itself. If Active Directory is destroyed or untrusted, the recovery sequence has a hard prerequisite — and if AD is *compromised* rather than merely down, restoring it uncritically restores the compromise. That is why identity is wave zero in the [restore-order model](RANSOMWARE_DEFENSE_REFERENCE.md), and why forest recovery deserves its own rehearsed plan.

### The Microsoft AD Forest Recovery Guide

Microsoft's [AD Forest Recovery Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide) (learn.microsoft.com, page dated 2025-07-09) covers recovering a forest "if a forest-wide failure renders all domain controllers (DCs) in the forest incapable of functioning normally." It applies to DCs running Windows Server 2022, 2019, 2016, 2012 R2, and 2012 (the list as the page states it), and Microsoft is explicit that it is a **template to customize into your own forest recovery plan** — not a runbook you can execute cold from the vendor's site.

The high-level path, per the guide's [restore-the-forest steps](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-steps-for-restoring-the-forest):

| Phase | What happens | Why it is ordered this way |
|---|---|---|
| **1 — Identify the problem** | Confirm the failure is truly forest-wide; "total forest recovery should be the last option" | Forest recovery is drastic; partial recovery is preferred when honest analysis supports it |
| **2 — Determine how to recover** | Choose the recovery approach and the backups to use | The *last clean copy* decision, for identity |
| **3 — Perform initial recovery** | "In isolation, recover one DC for each domain, clean it, and reconnect the domains. Reset privileged accounts, and rectify problems caused by security breaches" | Isolation prevents re-poisoning; one clean DC per domain is the minimum trusted seed |
| **4 — Redeploy remaining DCs** | Rebuild outward from the trusted seed | Scale resumes only after trust does |
| **5 — Cleanup** | Name resolution, LOB application re-validation | The forest is back; the *services* still need proving |

Microsoft recommends practicing forest recovery **"on a regular basis,"** and notes the steps are "designed to minimize the possibility of reintroducing dangerous data into the recovered forest" — vendor confirmation that identity recovery is an anti-adversary procedure, not just a restore.

### The krbtgt double reset

During forest recovery, Microsoft's [krbtgt guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) is specific, and worth quoting exactly because paraphrases keep dropping the operative constraint:

- "You should perform this operation twice. You must wait 10 hours between password resets" — 10 hours being the default maximum user/service ticket lifetime.
- "The password history value for the krbtgt account is 2... By resetting the password twice you effectively clear any old passwords from the history, so there's no way another DC replicates with this DC by using an old password."

The double reset is what invalidates Kerberos tickets an adversary minted with stolen krbtgt material (the Golden Ticket problem — see [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md)); skipping the wait, or doing one reset, leaves the old secret honored.

### Break-glass access

Widely adopted practitioner guidance, stated as such: recovery presumes someone can still log in to *something* when federation, MFA infrastructure, and the PAM vault are all inside the blast radius.

**Do**
- Maintain emergency-access ("break-glass") accounts that do **not** depend on anything being recovered: excluded from federation and from MFA methods that ride on recoverable infrastructure, with long random credentials stored offline (sealed, dual-control) and an alert on *any* use.
- Keep offline copies of the forest recovery plan, DC backup inventory, and the recovery-team contact tree — printed or on isolated media, reachable when the document-management system is encrypted.
- Include cloud identity (Entra ID or equivalent) in the identity-recovery plan: hybrid environments can lose both planes, or lose the sync trust between them.
- Time an identity-recovery drill annually and record the number — it is usually the true floor under every RTO in the plan ([metrics](#resilience-metrics)).

**Don't**
- Store break-glass credentials in the password vault they exist to survive.
- Domain-join the systems that recover the domain — backup infrastructure, recovery jump hosts, and the isolated recovery environment live outside the production identity plane (see [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md)).
- Restore a DC from backup straight into the production network "to have a look" — isolation first, per Microsoft's phase 3.

---

## Alternate processing and communications planning

### The SP 800-34 site continuum

| Site type | Readiness posture (condensed from SP 800-34) | Cyber-era note |
|---|---|---|
| **Cold site** | Facility with space and infrastructure, no equipment staged | Slowest; the RTO must absorb procurement and build time |
| **Warm site** | Partially equipped; needs configuration and data before cutover | The common compromise tier |
| **Hot site** | Fully equipped, ready for near-term operation | Expensive; verify its *identity* separation, not just its readiness |
| **Mobile site** | Transportable, self-contained capability | Niche; field and ICS/OT contexts |
| **Mirrored site** | "Fully redundant facilities with automated real-time information mirroring" | Highest availability — and the highest risk of mirroring the *attack*: real-time replication has no integrity lag to hide behind |

**The cloud translation** (this document's analysis, not SP 800-34's): cloud regions and IaC collapse much of the cold/warm/hot spend curve — golden images plus infrastructure-as-code can make a "cold" tenant warm in hours. But a second region in the **same account/tenant, same control plane, same credentials** is a mirrored site in the worst sense: one stolen credential reaches both. Recovery capacity belongs in a separate account or tenant, with separate (break-glass-reachable) identity, and data crossing into it one-way. Backup tiering, object-lock immutability, and the reference topology live in [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md).

Control-catalog anchors for this section, from the SP 800-53 r5 CP family: **CP-6 Alternate Storage Site**, **CP-7 Alternate Processing Site** (control names as carried in this library's [control mapping data](CONTROLS_MAPPING.md), sourced from the CTID NIST 800-53 r5 mappings).

### Out-of-band communications

A perennial exercise finding: domain controllers are down, email is encrypted, the VoIP system authenticates against AD — and the recovery team cannot talk to itself. Communications planning is a first-class contingency deliverable (SP 800-34 gives crisis communications its own plan type), and the cyber scenario adds a constraint the classical plan never had: **assume the adversary can read the corporate channels that still work.**

**Do**
- Pre-provision an out-of-band channel — a stand-alone conference bridge, an external messaging workspace, or vetted secure-messaging apps on devices that do not authenticate against the corporate identity plane — and enroll the IR and recovery teams in peacetime.
- Print the activation card: bridge numbers, channel names, contact tree, declaration criteria. Wallet-sized beats wiki-hosted when the wiki is encrypted.
- Host the external status page (customers, partners, workforce) outside your own estate.
- Decide *in the plan* who talks to regulators, insurers, law enforcement, and the press — the crisis communications plan and the [IR plan](INCIDENT_RESPONSE_REFERENCE.md) must name the same people.

**Don't**
- Coordinate incident response over the potentially compromised network you are investigating — standard IR guidance, doubly true mid-recovery.
- Let the out-of-band channel become shadow IT: it is provisioned, inventoried, and exercised, or it will not exist when needed.

---

## Testing tiers — tabletop to full failover

An untested plan is a hypothesis with a signature page. The testing canon: SP 800-34 step 6 plus **[SP 800-84](https://csrc.nist.gov/pubs/sp/800/84/final)** for TT&E program design, and FEMA's **[HSEEP](https://www.fema.gov/emergency-managers/national-preparedness/exercises/hseep)** doctrine (current revision January 2020, superseding 2013) for the exercise typology most CISA material aligns to.

SP 800-34 itself distinguishes two exercise types — **tabletop** ("discussion-based... does not involve deploying equipment") and **functional** (performing duties "in a simulated operational environment") — while HSEEP's ladder recognizes seven exercise types in two categories:

| HSEEP category | Types | What they validate |
|---|---|---|
| **Discussion-based** | Seminars · Workshops · Tabletop exercises (TTX) · Games | Plans, policies, decision paths, inter-team agreements — people talking |
| **Operations-based** | Drills · Functional exercises (FE) · Full-scale exercises (FSE) | Actual capability under realistic conditions — people (and systems) doing |

The practitioner escalation ladder, with "full failover" as the BCDR-specific summit of HSEEP's full-scale tier:

| Tier | What happens | What it proves | Typical cadence |
|---|---|---|---|
| **Plan walkthrough** | Owners read the plan end to end | The plan exists, is current, roles are named | Semiannual, and on material change |
| **Tabletop** | Facilitated scenario discussion, injects, no systems touched | Decision paths, declaration criteria, comms, the payment-policy question | At least annual; executive and technical variants |
| **Drill** | One capability executed for real (restore one system from Tier 2, activate the call tree, use break-glass in a lab) | A single function, timed | Quarterly, rotating functions |
| **Functional exercise** | Teams execute roles against a simulated operational environment | Coordination across teams; RTO plausibility | Annual |
| **Full failover / full-scale** | Production services actually recovered — failover to the alternate site/tenant, or a timed full restore in the isolated recovery environment | RTO and RPO **achieved**, measured, with evidence | Annual for the most critical services |

**CISA Tabletop Exercise Packages (CTEPs).** CISA's [CTEP service](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages) offers over 100 self-run packages across three categories — cybersecurity scenarios (ransomware, insider threat, phishing, ICS compromise, and sector-specific variants), physical security scenarios, and cyber-physical convergence — each with template objectives, a scenario, discussion questions, plus invitation, slide, feedback, and After-Action-Report templates (contact: cisa.exercises@cisa.dhs.gov). The page remained live as of September 24, 2026, but given the 2026 CISA program cuts described below, verify status before building an annual program on it.

**Do**
- Script every exercise against the cyber-broken assumptions: backups gone, AD gone, comms gone — the scenarios that expose plan fiction fastest.
- Time everything operations-based and record the numbers; exercise results are the only honest source for "RTO achieved" ([metrics](#resilience-metrics)).
- Run the HSEEP after-action loop: AAR, improvement plan, owners, dates, and closure tracking — findings without closure are theater.
- Rehearse forest recovery specifically (Microsoft: practice "on a regular basis") — it is the longest pole in almost every full-restore timeline.

**Don't**
- Let the first full failover in the organization's history be the real incident.
- Test only the happy path (single file restore, planned failover with both sites healthy) and report DR as "validated."
- Exercise the DR plan, IR plan, and crisis-communications plan in separate silos when the scenario that matters activates all three at once.

---

## CISA resilience resources and the 2025–2026 transition

### The Cyber Resilience Review (CRR)

The CRR is a maturity-style assessment of operational resilience practices, derived from the **CERT Resilience Management Model (CERT-RMM)** developed by Carnegie Mellon University's Software Engineering Institute. Per the [official fact sheet](https://www.cisa.gov/sites/default/files/publications/Cyber-Resilience-Review-Fact-Sheet-508.pdf), it assesses ten domains:

| # | CRR domain | # | CRR domain |
|---|---|---|---|
| 1 | Asset Management | 6 | Service Continuity Management |
| 2 | Controls Management | 7 | Risk Management |
| 3 | Configuration and Change Management | 8 | External Dependency Management |
| 4 | Vulnerability Management | 9 | Training and Awareness |
| 5 | Incident Management | 10 | Situational Awareness |

Domain 6, Service Continuity Management, is the BCDR core — but the surrounding nine are the point: the CRR's model says continuity is an emergent property of asset knowledge, dependency management, and situational awareness, not a standalone binder. It was offered as a downloadable self-assessment or a facilitated on-site session.

**Status and crosswalk caveats, stated plainly:**

- The CRR self-assessment kit (Self-Assessment PDF, User Guide, Question Set with Guidance, NIST CSF Crosswalk) is dated **April 2020**, and its crosswalk maps to **NIST CSF v1.1 — not CSF 2.0**. No official CRR-to-CSF-2.0 crosswalk exists; do not improvise one and present it as authoritative.
- Both the CRR service page and the [downloadable-resources page](https://www.cisa.gov/resources-tools/resources/cyber-resilience-review-downloadable-resources) now carry an "Archived Content" banner on cisa.gov, though the kit itself remained downloadable as of September 2026.
- The 10-domain fact sheet is a DHS CS&C-era document with obsolete contact information — use it for the domain list and CERT-RMM lineage only.

### The 2026 retirement of facilitated assessments

Per an August 25, 2026 internal notice [reported by Cybersecurity Dive](https://www.cybersecuritydive.com/news/cisa-cybersecurity-assessments-ending/829371/) (CISA confirmed in early September 2026), CISA retired six free facilitated assessments: **Cyber Resilience Reviews, Cyber Resilience Essentials surveys, Ransomware Readiness Assessments, Incident Management Reviews, External Dependencies Management Assessments, and Cyber Infrastructure Surveys**. CISA directs organizations to its Cross-Sector Cybersecurity Performance Goals instead. No formal CISA press release had been located at this writing — treat the details as reported, and recheck before citing in anything load-bearing; this transition is moving quickly.

### CPG 2.0 — the pointed-to successor

[CISA's Cross-Sector Cybersecurity Performance Goals version 2.0](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) (released December 11, 2025) is restructured to align with the six [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) functions — Govern, Identify, Protect, Detect, Respond, **Recover** — with a new governance component and companion Sector-Specific Goals. For a resilience program, the practical translation of the transition: the facilitated maturity conversation is gone; the self-service baseline (CPG 2.0's Recover-aligned goals, plus the archived CRR question set as a richer self-assessment) is what remains. The CRR question set is still one of the best free structured self-assessments of continuity practice available — archived does not mean wrong.

---

## Plan governance and maintenance

SP 800-34's step 7 sets the standard in one phrase: the plan is "a living document that is updated regularly." Governance is what makes that sentence true.

| Governance element | Working practice |
|---|---|
| **Ownership** | Every plan (BCP, DRP, ISCP, crisis comms, cyber IR) has a named owner and deputy; the *program* has an executive sponsor who owns the MTD decisions |
| **Review cadence** | Annual review minimum, plus event triggers: material architecture change, identity-platform change, backup-platform change, M&A, vendor change on a critical dependency, and **after every exercise and every real incident** |
| **BIA currency** | The BIA is versioned and re-validated on the same triggers — stale BIA, stale everything downstream |
| **After-action integration** | HSEEP-style loop: AAR → improvement plan → tracked items with owners and dates → closure reported to the sponsor |
| **Gap register** | RTO-vs-MTD gaps carry a documented plan of action (SP 800-34's POA&M instruction), not silent acceptance |
| **Distribution & availability** | Current plan copies reachable out-of-band (printed/isolated media); an encrypted plan repository is a self-own |
| **Third parties** | Critical vendors' continuity obligations (RTOs, notification clocks, exercise participation) written into contracts — CRR domain 8's concern, made contractual |

**Control-catalog anchor.** In federal and FedRAMP contexts, the CP family of [SP 800-53 Release 5.2.0](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) (August 27, 2025) is where this discipline becomes assessable controls. Family members carried with verified names in this library's [control mapping data](CONTROLS_MAPPING.md) (CTID r5 mappings): **CP-2 Contingency Plan**, **CP-6 Alternate Storage Site**, **CP-7 Alternate Processing Site**, **CP-9 System Backup**, **CP-10 System Recovery and Reconstitution**. The family also carries controls for contingency training, plan testing, and telecommunications services — pull exact control text from NIST's Cybersecurity and Privacy Reference Tool (CPRT), which now maintains the catalog in machine-readable form.

---

## Resilience metrics

Report movement against declared objectives, not activity. Formulas and reporting patterns: [Security Metrics](SECURITY_METRICS_REFERENCE.md); ransomware-specific counterparts: [Ransomware Defense](RANSOMWARE_DEFENSE_REFERENCE.md).

| Metric | Why it matters |
|---|---|
| **RTO achieved vs. declared** (per critical service, from timed exercises) | The only honest RTO is a measured one; the delta is the risk statement |
| **RPO achieved vs. declared** (measured from actual restore points) | Includes the cyber correction: measured to the last *clean* copy, not the last copy |
| **MTD breaches in exercises** | Any scenario where the measured recovery blows through the MTD is a board-level finding |
| **Identity recovery time** (timed forest-recovery / identity-restore drill) | The floor under every other RTO; if this number is unknown, the others are fiction |
| **Restore-test pass rate** (per backup tier) | "Backup completed" is not a metric; "restore verified" is |
| **BIA coverage & currency** (% critical processes with a BIA reviewed in-window) | Leading indicator for whether priorities still match the business |
| **Plan currency** (% plans reviewed on cadence / after material change) | The living-document requirement, quantified |
| **Exercise cadence & finding-closure rate** | Proves the program learns; open findings older than a cycle are accepted risk in disguise |
| **Alternate-processing coverage** (% critical services with a *tested* alternate path) | Untested failover capacity is capacity on paper |
| **Out-of-band readiness** (% recovery/IR staff enrolled and drilled on the OOB channel) | The cheapest metric on this list, and the first one an incident tests |
| **Dependency mapping coverage** (% critical services with mapped upstream dependencies) | The CRR domain-8 concern as a number; unmapped dependencies are unplanned outages |

For executive framing, hang the program on the **Recover** function of [NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) (released February 26, 2024, adding Govern as the sixth function) and CPG 2.0's Recover-aligned goals — the shared vocabulary boards, insurers, and assessors are converging on.

---

## Sources

- NIST — SP 800-34 Rev. 1 (upd1, the citable edition): <https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final> · [Publication PDF](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf) · withdrawn 2002 original: <https://csrc.nist.gov/pubs/sp/800/34/final>
- NIST — SP 800-84, Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities (2006): <https://csrc.nist.gov/pubs/sp/800/84/final>
- NIST — SP 800-160 Vol. 2 Rev. 1, Developing Cyber-Resilient Systems (Dec 2021): <https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final> · [Publication PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v2r1.pdf)
- NIST — SP 800-53 Release 5.2.0 (Aug 27, 2025): <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- NIST — CSF 2.0 / CSWP 29 (Feb 26, 2024): <https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf>
- ISO — ISO 22301:2019, Security and resilience — BCMS — Requirements: <https://www.iso.org/standard/75106.html> · Amd 1:2024: <https://www.iso.org/standard/88412.html> · ISO/TS 22317:2021: <https://www.iso.org/standard/79000.html>
- CISA — Cyber Resilience Review fact sheet (10 domains, CERT-RMM lineage): <https://www.cisa.gov/sites/default/files/publications/Cyber-Resilience-Review-Fact-Sheet-508.pdf> · CRR downloadable resources (archived; kit dated April 2020): <https://www.cisa.gov/resources-tools/resources/cyber-resilience-review-downloadable-resources> · CRR service page: <https://www.cisa.gov/resources-tools/services/cyber-resilience-review-crr>
- CISA — Tabletop Exercise Packages (CTEP): <https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages>
- CISA — Cross-Sector Cybersecurity Performance Goals (CPG 2.0, Dec 11, 2025): <https://www.cisa.gov/cross-sector-cybersecurity-performance-goals>
- CISA/MS-ISAC/NSA/FBI — #StopRansomware Guide (October 2023): <https://www.cisa.gov/stopransomware/ransomware-guide>
- Cybersecurity Dive — CISA ending six facilitated assessment programs (Sept 2026 reporting): <https://www.cybersecuritydive.com/news/cisa-cybersecurity-assessments-ending/829371/>
- FEMA — Homeland Security Exercise and Evaluation Program (HSEEP, January 2020 doctrine): <https://www.fema.gov/emergency-managers/national-preparedness/exercises/hseep>
- Microsoft — AD Forest Recovery Guide: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide> · Steps for restoring the forest: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-steps-for-restoring-the-forest> · Resetting the krbtgt password: <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password>
- MITRE ATT&CK — T1490 Inhibit System Recovery: <https://attack.mitre.org/techniques/T1490/> · T1486 Data Encrypted for Impact: <https://attack.mitre.org/techniques/T1486/>

---

*This reference summarizes third-party publications — NIST SP 800-34r1, SP 800-84, SP 800-160v2r1, SP 800-53 and CSF 2.0; ISO 22301/22313/22317 (attributed summary only; the standards are copyrighted and paywalled); CISA CRR, CTEP, CPG and #StopRansomware materials; FEMA HSEEP; Microsoft's AD Forest Recovery Guide; and MITRE ATT&CK® — as an independent practitioner summary. It is not affiliated with or endorsed by those organizations. CISA's assessment-program transition was in motion in late 2026; verify the current status of CRR and CTEP resources, and work from the linked originals for anything load-bearing.*
