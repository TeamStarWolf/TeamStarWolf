# Insider Threat Program Reference

> **The insider is the one adversary who never needs initial access.** The [MITRE Center for Threat-Informed Defense (CTID)](https://ctid.mitre.org/) **Insider Threat TTP Knowledge Base** is the first cross-sector, multi-organization collection of techniques that insiders *actually used* in IT environments — real incident case files, expressed in ATT&CK terms, so a SOC can detect, mitigate, and emulate insider actions with the same behavioral model it already uses for external adversaries.

An insider threat program is different from every other security program in this library: the "attacker" is on payroll (or was), authenticates legitimately, and triggers none of the perimeter tripwires external actors must cross. That changes the TTPs (no privilege escalation, no initial-access tooling), changes the telemetry that matters (user activity, data movement, HR events), and changes the governance (HR, legal, and privacy sit *inside* the program, not adjacent to it). This reference covers the CTID Knowledge Base, the U.S. policy foundations (EO 13587, NITTF, NISPOM, NIST SP 800-53), CISA's program lifecycle, CERT/SEI's case research, detection approaches, and how to measure maturity.

**Related:** [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md) · [ATT&CK Mitigations](ATTACK_MITIGATIONS_REFERENCE.md) · [Identity Security](IDENTITY_SECURITY_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md)

---

## Insider threat vs. insider risk

CISA's definitions are the common denominator across U.S. guidance:

| Term | CISA definition |
|---|---|
| **Insider** | "Any person who has or had authorized access to or knowledge of an organization's resources" — employees, former employees, contractors, vendors, partners |
| **Insider threat** | "The potential for an insider to use their authorized access or understanding of an organization to harm that organization" |
| **Insider risk** | Industry framing that widens the lens from *hostile people* to *risky outcomes* — including well-meaning employees who mishandle data. Programs increasingly brand themselves "insider risk management" (IRM) to reflect that most loss events are not malicious |

The distinction matters operationally. A **threat**-framed program hunts bad actors; a **risk**-framed program also measures and reduces negligent data handling, departing-employee data movement, and third-party access sprawl — which is where most of the volume is. Both framings run on the same telemetry and the same governance; the risk framing is usually easier to fund and easier to explain to the workforce.

**Scope note:** the CTID Knowledge Base deliberately covers only **cyber actions on IT systems**. Physical-world insider actions (theft of hardware, workplace violence) and insider **motives** are explicitly out of scope of the KB — those belong to the CISA guide and CERT/SEI research covered below. A complete program needs all three lenses:

| Lens | Source | Question it answers |
|---|---|---|
| **Behavioral (technical)** | CTID Insider Threat TTP KB | *What do insiders do on systems, and how do we detect it?* |
| **Programmatic** | CISA guide, NITTF, NIST PM-12 | *How do we build and govern the capability?* |
| **Empirical (human + org)** | CERT/SEI case research | *What do 3,000+ real cases teach about people, precursors, and response?* |

---

## The insider-risk taxonomy

CISA's taxonomy ([Defining Insider Threats](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats)) has four types:

| Type | Sub-types | What it looks like |
|---|---|---|
| **Unintentional** | Negligence · Accidental | Policy shortcuts, misdelivered email, lost devices, falling for phishing. No intent to harm — still a loss event |
| **Intentional** | — | The "malicious insider": acts for personal benefit or from grievance (passed over for promotion, termination, ideology, financial pressure) |
| **Collusive** | — | An insider cooperating with an external threat actor — recruitment of employees by criminal or state actors to provide access or data |
| **Third-party** | — | Contractors and vendors with granted access who compromise security directly or through negligence |

Industry vocabulary commonly compresses this into **malicious / negligent / compromised**, where "compromised" means a legitimate account driven by an external actor (credential theft, session hijack). Be precise about which taxonomy a tool or report is using:

| Term you'll hear | Nearest CISA type | Watch out |
|---|---|---|
| **Malicious insider** | Intentional | CISA folds personal-benefit fraud and grievance-driven sabotage into one type; CERT/SEI research has long modeled fraud, IT sabotage, and IP theft as distinct incident classes because their actors, timelines, and indicators differ |
| **Negligent insider** | Unintentional | The largest population in industry survey data; cheapest per incident, expensive in aggregate |
| **Compromised insider** | (closest: Collusive) | A hijacked account is arguably an *external* intrusion using insider access — but IRM tooling catches it, because the behavioral baseline breaks the same way |
| **Third-party risk** | Third-party | Frequently unmonitored: vendor and contractor accounts often sit outside UAM scope entirely |

Why the class matters: a fraud insider and a departing IP thief generate different telemetry on different timelines. Fraud is **low-and-slow inside business applications** (see the KB findings below); IP theft **spikes around resignation and separation**; sabotage clusters around **grievance events** and privileged technical staff. One detection posture does not fit all three.

> The CTID KB does not adopt a motive taxonomy at all — it records *what the insider did on systems*, regardless of why. That makes it composable with any of the framings above.

---

## The CTID Insider Threat TTP Knowledge Base

| | |
|---|---|
| **Maintainer** | MITRE [Center for Threat-Informed Defense](https://ctid.mitre.org/) (CTID) |
| **Repo** | [center-for-threat-informed-defense/insider-threat-ttp-kb](https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb) · Apache-2.0 |
| **Current version** | **v2.0.0** (March 2024) — latest release as of September 2026 |
| **Built on** | MITRE ATT&CK **v14** |
| **Coverage** | **47 techniques + 29 sub-techniques** (per CTID's v2.0 release announcement); case data touches **~22%** of all ATT&CK techniques, up from ~16% in v1 |
| **Ships as** | [Project website](https://center-for-threat-informed-defense.github.io/insider-threat-ttp-kb/) · CSV · Excel · ATT&CK Navigator layer (JSON) |
| **Stated purpose** | Enable SOCs and insider-threat analysts to "detect, mitigate, and emulate insider actions on IT systems" |
| **Contact** | ctid@mitre.org · document numbers CT0041 / CT0102, approved for public release |

### What makes the data credible

The KB is built from **real, documented insider incident case files** submitted by participating corporations through a secure portal — "actions that insiders actually did," not hypothetical scenarios or red-team guesses. For each case the project records:

1. the **TTPs** the insider used (in ATT&CK terms),
2. the **method of detection** — how the organization actually caught it,
3. the **data sources** used to detect, and
4. **Observable Human Indicators (OHIs)** associated with the case.

| Release | Date | Contributing organizations |
|---|---|---|
| **v0.0.1** (draft) | February 2022 | — |
| **v1.0** | February 17, 2022 | 6 orgs: Citi, CrowdStrike, HCA, JP Morgan, Microsoft, Verizon |
| **v2.0** | March 2024 | 7 orgs: CrowdStrike, HCA, JP Morgan, Lloyds, Microsoft, NEXT, Verizon |

(The GitHub v1.0.0 tag was retro-published in March 2024 alongside v2.0.0; v1 actually launched February 2022 per the archived CTID project page.)

v2.0 added **16 techniques and 9 sub-techniques** over v1 — more than 50% growth — and introduced two structural upgrades:

- **Mitigations and data sources.** Insider techniques are connected to standard ATT&CK **Mitigations (M-codes)** and **Data Sources (DS-codes)**. Example from the project's own pages: **T1078 Valid Accounts** maps to M1027 Password Policies, M1018 User Account Management, M1026 Privileged Account Management, M1013 Application Developer Guidance, M1017 User Training, M1015 Active Directory Configuration, and M1036 Account Use Policies. The project's position is that *"all mitigations for ATT&CK for enterprise are relevant to insider threats."*
- **Observable Human Indicators (OHI).** A new data-source concept for the human side of detection — indicators observable about the *person*, not the host. The project itself calls the human-factor area "an area for growth," and publishes no canonical OHI list yet; treat OHI as an emerging construct, not a finished taxonomy, and keep anything you build on it reviewable by HR/legal.

The documentation site (v2.0.0) is organized as: *Introduction · Knowledge Base · Case Analysis · Identifying and Mitigating Threats · Observable Human Indicators*.

### How to actually use the artifacts

| Artifact | Use |
|---|---|
| **Navigator layer (JSON)** | Load in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) and overlay against your detection-coverage layer — the intersection of "insiders actually do this" and "we can't see it" is your backlog |
| **CSV / Excel** | Join technique IDs against your detection inventory or [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) workbench for coverage scoring |
| **Case Analysis pages** | Read before designing detections — the *method of detection* and *data sources* fields tell you what actually worked in seven large enterprises |
| **Emulation** | The KB's stated purpose includes *emulating* insider actions: run benign purple-team versions of the KB's dominant chains (e.g., stage → archive → copy a marked test file to USB) to prove the telemetry and alerts fire end to end — see [Purple Team](PURPLE_TEAM_REFERENCE.md) |

### Version drift you must account for

The KB is pinned to **ATT&CK v14** (current October 2023 – April 2024). Live ATT&CK is **v19.2** — the v19 release cycle began April 28, 2026 (splitting Defense Evasion into Stealth and Defense Impairment tactics), and v18 (October 28, 2025) replaced Detections/Data Sources with **Detection Strategies and Analytics**. Consequences:

- The KB lags the live framework by **five major versions**; no official re-mapping to later ATT&CK versions has been published.
- The KB's **DS-code references follow the older, now-deprecated ATT&CK detection model**. When you operationalize KB detection guidance, translate DS-codes into the v18+ Detection Strategies model (see [Detection Strategies](detections/strategies/README.md)) yourself — and treat that translation as your own engineering, not CTID's.
- Technique IDs are stable enough that the KB's technique list still joins cleanly against current ATT&CK data — but verify any individual ID against the live framework before building on it.

> **No invented crosswalks.** The only official mappings the KB publishes are to ATT&CK M-codes and DS-codes. **There is no official mapping** between the KB and NIST SP 800-53 controls, the CERT Common Sense Guide practices, or the NITTF Maturity Framework. Any table claiming otherwise is someone's interpretation — useful, perhaps, but label it as such.

---

## How insider TTPs differ from external-adversary ATT&CK usage

This is the KB's core analytical payoff. The same matrix, used very differently:

| Dimension | External adversary | Insider (per KB case data) |
|---|---|---|
| **Initial access** | Must earn it — phishing, exploits, valid-account purchase | Already granted. Activity starts mid-matrix, from **T1078 Valid Accounts** territory |
| **Privilege escalation** | Nearly universal | **None observed in the case data**, per the KB's own case analysis (its fraud discussion softens this to "rarely identified"). Insiders operate within existing legitimate access |
| **Tooling** | Malware, C2, offensive frameworks | Ordinary business tools: file explorer, email, USB drives, SaaS apps |
| **Tempo** | Dwell measured in days–months, then smash-and-grab | **Low and slow** — fraud insiders often operated undetected for extended periods, *years* in some cases |
| **Transaction size** | Large exfil events | Many small events — individual fraud compensation was typically **under $250** per transaction |
| **Defense evasion** | Disable EDR, wipe logs | Mostly unnecessary — normal-looking activity *is* the evasion |
| **Best predictive signal** | Threat intel on the actor | Context on the person: role change, grievance, resignation (the OHI idea) |

### The two behavior clusters in the case data

**Fraud cluster.** Fraud cases concentrated on four techniques:

| Technique | Insider usage |
|---|---|
| **[T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565/)** | Altering records the insider is authorized to touch — the fraud itself lives here |
| **[T1136 Create Account](https://attack.mitre.org/techniques/T1136/)** | Standing up accounts to route benefits, receive payments, or preserve access |
| **[T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)** | Harvesting from SharePoint, wikis, ticketing, CRM — systems the insider legitimately reads |
| **[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/)** | Modifying accounts and permissions within delegated authority |

**Exfiltration cluster.** Dominated by one path:

```
  T1213 / normal file access          collect what you already can read
            │
            ▼
  T1074 Data Staged                   pile it somewhere convenient
            │
            ▼
  T1560 Archive Collected Data        zip it (often just "select → compress")
            │
            ▼
  T1052.001 Exfiltration over USB     walk it out the door
```

**[T1052.001 Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001/)** dominated observed exfiltration, commonly preceded by **[T1074 Data Staged](https://attack.mitre.org/techniques/T1074/)** and **[T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560/)**. This is the single highest-yield detection chain an insider-threat program can build first — every link produces free telemetry on a standard Windows estate.

### Program implications

- Threat-hunt playbooks written for external actors will whiff — there is no beacon, no persistence implant, no privilege escalation to catch. Hunt **authorized-access anomalies** instead.
- Detection thresholds tuned for volume (large transfers, mass deletion) miss the under-$250, multi-year fraud pattern. You need **longitudinal baselines**, not spike alerts.
- Because insiders start at Valid Accounts, the mitigations with the most leverage are identity ones: least privilege, account-lifecycle hygiene, separation of duties, and account-use policies — see [ATT&CK Mitigations](ATTACK_MITIGATIONS_REFERENCE.md) M1018 / M1026 / M1036 and [Identity Security](IDENTITY_SECURITY_REFERENCE.md).
- The fraud cluster lives in **business applications**, not the OS. If your telemetry stops at endpoint and network, the KB's fraud techniques are invisible to you; application-tier audit logs (payments, claims, CRM, HR systems) are first-class insider telemetry.
- The insider TTP surface is *narrower* than the full matrix (~22% of techniques) — which is good news: a focused program can realistically cover the behaviors that real cases show, instead of boiling the ATT&CK ocean.

---

## Program foundations and governance

The U.S. policy scaffolding, in order of appearance:

| Instrument | Date | What it does |
|---|---|---|
| **Executive Order 13587** | October 2011 | Post-WikiLeaks order: directs federal agencies handling classified information to establish insider threat detection and prevention programs; creates the **National Insider Threat Task Force (NITTF)** under joint DOJ (Attorney General) / ODNI leadership |
| **National Insider Threat Policy & Minimum Standards** | November 2012 (Presidential Memorandum) | Defines the minimum elements of an executive-branch program — including a **designated senior official**, **user activity monitoring (UAM)**, **employee training**, and **information integration and analysis** capability |
| **NITTF Insider Threat Guide** | 2017 | NITTF's practical how-to for meeting the Minimum Standards |
| **NITTF Maturity Framework** | November 1, 2018 | **19 maturity elements** to advance programs *beyond* minimum compliance ([PDF at dni.gov](https://www.dni.gov/files/NCSC/documents/features/NITTF_MaturityFramework_web.pdf)) |
| **32 CFR Part 117 (NISPOM rule)** | Effective February 24, 2021 | Moves the NISPOM into federal regulation for **cleared industry**: contractors must designate an **Insider Threat Program Senior Official (ITPSO)**, run an insider threat program, and deliver insider-threat awareness training to newly cleared employees **before** classified access and **annually** thereafter |

NITTF operates under the **National Counterintelligence and Security Center (NCSC)** and is co-directed with the FBI. Even if you are a purely commercial organization with no clearances, this lineage matters: the Minimum Standards' element list (senior accountable official, UAM, training, fusion/analysis capability) is the de facto blueprint every commercial program copies — and auditors, regulators, and courts treat it as the reasonable-practice baseline.

### NIST SP 800-53 Rev 5 hooks

For organizations that anchor on 800-53 (current release **5.2.0**, August 27, 2025; Rev 5 organizes controls into **20 families**):

| Control | Requirement |
|---|---|
| **PM-12 Insider Threat Program** | *The* program control: implement an insider threat program that includes a **cross-discipline insider threat incident handling team** |
| **AT-2(2) Literacy Training and Awareness — Insider Threat** | Train the workforce to recognize and report potential indicators — 800-53's own examples include long-term job dissatisfaction, attempts to access information not required for the job, and unexplained financial resources |
| **PS-3 Personnel Screening** | Screen individuals before authorizing access; rescreen per policy |
| **PS-4 Personnel Termination** | Disable access, retrieve organization property, and handle separations on a defined timeline — the single most abused seam in insider cases |
| **PS-8 Personnel Sanctions** | A formal, consistently applied sanctions process — programs without one end up improvising under legal risk |

The wider **PS (Personnel Security) family** supplies the personnel-lifecycle substrate an insider-risk program builds on, and **PM-12's cross-discipline team** is the governance answer to "who owns this?" — nobody alone; security, HR, legal, privacy, and counterintelligence together. Access-control and audit families (e.g., **AC-2 Account Management**, **AU-6 Audit Record Review, Analysis, and Reporting**, **SI-4 System Monitoring**) carry the technical weight of what the program watches.

> **Reminder:** mapping PM-12/PS controls to CTID KB techniques or CERT practices is *your* engineering judgment. No official crosswalk exists.

### The operating model: fusion is the product

The Minimum Standards' "information integration and analysis" element is the part most programs under-build. The capability worth drawing is the fusion point — one place where technical and human signals meet before anyone acts:

```
   TECHNICAL SIGNALS                HUMAN / ORG SIGNALS
   ─────────────────                ───────────────────
   UAM / endpoint telemetry         Workforce reports (AT-2(2) training)
   SIEM & app-tier audit logs       HR events: notice, PIP, transfer
   DLP / device control / CASB      Manager & EAP-adjacent concerns
   Identity & PAM logs              Legal / compliance referrals
          │                                │
          └───────────►  FUSION  ◄─────────┘
                    (analysis & triage —
                     one case record per concern)
                             │
                             ▼
              CROSS-DISCIPLINE TEAM (PM-12)
              security · HR · legal · privacy
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
     Supportive         Administrative      Investigation /
     intervention       action, access      law-enforcement
     (EAP, workload)    reduction           referral
          │                  │                  │
          └────────── lessons → controls ───────┘
                     (CSG BP22 feedback loop)
```

Two design consequences: **triage happens before attribution of intent** (the same staging-and-USB pattern can be a thief, a workaholic with bad habits, or a hijacked account — the fusion step is where context decides), and **every outcome path feeds back** into controls, training, and detections, or the program never compounds.

### A 90-day starting plan

| Phase | Weeks | Do this |
|---|---|---|
| **Charter** | 1–3 | Name the senior accountable official; stand up the PM-12 cross-discipline team (security, HR, legal, privacy); get legal/privacy sign-off on the monitoring concept *before* any tooling |
| **Define** | 3–5 | Inventory critical assets and the systems that hold them (CSG BP1); write down what counts as an insider incident *here*; pick the taxonomy your metrics will use |
| **Instrument** | 5–9 | Enable the free telemetry for the KB's USB chain (removable-storage and PNP auditing, process-creation logging, repository audit logs); confirm collection into the SIEM — see [SIEM Reference](SIEM_REFERENCE.md) |
| **Operationalize** | 9–12 | Stand up a triage workflow and case-management record (align fields to IIDES); define the separation-review procedure with HR; deliver first AT-2(2)-style awareness training |
| **Measure** | 12+ | Baseline the KPIs below; load the KB Navigator layer against detection coverage; report gaps as the backlog |

> **Failure modes to avoid:** buying a UEBA platform before governance exists; monitoring everyone deeply instead of tiering by risk; running the program as a security-only function without HR/legal; measuring success by alert volume; and treating separation day as the first time anyone looks at a departing employee's data movement.

---

## The CISA Insider Threat Mitigation Guide (2026 Edition)

CISA released the updated **Insider Threat Mitigation Guide (2026 Edition)** on **September 9, 2026**, replacing the original 2020 edition. Per CISA's release announcement, the update brings: a streamlined format, new case studies and statistics, coverage of **hybrid/remote work** and **AI manipulation and deception tactics**, new **access-control and visitor-screening** guidance, and expanded content on **employee-separation risk**. (The PDF is 21.27 MB; get it from [cisa.gov](https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide).)

CISA's program framework is a four-stage lifecycle:

```
        ┌────────────────────────────────────────────────────┐
        │                                                    │
        ▼                                                    │
   1. DEFINE ──► 2. DETECT & IDENTIFY ──► 3. ASSESS ──► 4. MANAGE
   scope, policy,    indicators, reporting,   evaluate the     intervene:
   governance,       monitoring, tips         concern: threat  HR action, help,
   threat types                               or noise?        controls, referral
```

| Stage | The work |
|---|---|
| **Define** | Program charter, senior accountable official, legal/privacy review, what counts as an insider threat *here*, protected-asset inventory |
| **Detect & Identify** | Reporting channels, training the workforce as sensors (AT-2(2)), technical monitoring, integrating HR/security/IT signals into one picture |
| **Assess** | A trained, multi-disciplinary threat-management team evaluates each concern in context — most concerns resolve as personal distress, error, or noise, not hostility |
| **Manage** | Graduated response: supportive intervention (EAP, workload change), administrative action, access reduction, investigation, or law-enforcement referral |

The guide's consistent through-line — and the reason *Assess* and *Manage* are separate stages — is **early intervention**: a mature program moves a person off the pathway to harm before an incident, rather than maximizing after-the-fact prosecutions. The 2026 edition's new content areas are worth reading even for mature programs: hybrid work moved the staging ground for data theft to home networks and personal cloud accounts, and AI-assisted deception (impersonation of colleagues and executives) gives collusive and third-party scenarios a new entry vector.

### The reporting channel is a control

*Detect & Identify* leans on the workforce more than on tooling — coworkers see grievances, financial stress, and policy drift long before telemetry does. Treat the reporting channel as an engineered control with requirements:

**Do** — offer multiple intake paths (named, anonymous, manager-mediated); acknowledge every report and close the loop with the reporter where appropriate; publish and honor a no-retaliation policy; time-bound triage so reports never vanish into a void; track report volume as a *health* metric (silence usually means distrust, not safety).

**Don't** — don't brand it a snitch line (frame reporting as protecting colleagues and the mission — the CISA early-intervention model gives you honest language for this); don't route reports raw to the subject's manager; don't punish good-faith reports that resolve benign, or the channel dies.

---

## CERT/SEI research: the Common Sense Guide and IIDES

The **CERT National Insider Threat Center** (Carnegie Mellon University, Software Engineering Institute) has run the longest-standing empirical insider-threat research program, built on a corpus of **3,000+ documented insider incidents**.

### Common Sense Guide to Mitigating Insider Threats, 7th Edition

Released **September 8, 2022** ([PDF, SEI digital library](https://www.sei.cmu.edu/documents/619/2022_019_001_886876.pdf)). It defines **22 best practices**, opening with **BP1 "Know and Protect Your Critical Assets"** and closing with **BP22 "Learn From Past Insider Threat Incidents"**. Versus the 6th edition, the 7th adds one new best practice and — notably — a **NIST Privacy Framework mapping**, acknowledging that insider-risk monitoring is itself a privacy risk to be governed (see the privacy section below).

The practices span the full program surface: asset identification, policy and governance, workforce training and positive incentives, personnel-lifecycle risk from hiring through separation, least privilege and separation of duties, monitoring and analytics, incident response, and organizational learning. Each practice ships with implementation guidance sliced by organization size and by responsible group (HR, legal, IT, security) — which makes the guide unusually useful for assigning ownership outside the security team. Use the guide itself for the full numbered list rather than a secondhand summary.

### IIDES — Insider Incident Data Exchange Standard

SEI CERT released **IIDES** — the first comprehensive JSON schema for classifying and sharing insider incident data — as a beta in **November 2024** (announced by SEI in February 2025) and **v1.0 on June 12, 2025**, with a Python reference implementation (**PyIIDES**). Repo: [cmu-sei/iides](https://github.com/cmu-sei/iides).

Why it matters: the field's chronic weakness is that every organization describes incidents in its own vocabulary, so nothing aggregates — internally across years, or externally across companies. IIDES does for insider incidents what STIX did for CTI: a shared schema covering the incident, the insider, the organization, detection, response, and legal outcome. If you run a case-management system, aligning its fields to IIDES now is cheap; retrofitting later is not. Pair it with the CTID KB: **KB for the TTP vocabulary, IIDES for the case-record structure** — together they make your BP22 "learn from incidents" loop machine-readable.

---

## Hardening: shrink what an insider *can* do

Detection gets the attention; prevention does the quiet work. The KB's position that *all* enterprise ATT&CK mitigations apply to insiders is liberating — you don't need an "insider security stack," you need the identity and data controls you already own, pointed at the insider problem. Priorities, driven by the KB's observed clusters:

### Identity (the T1078 starting point)

| Control | Implementation |
|---|---|
| **Least privilege + recertification** | Role-based entitlements with periodic access reviews through your IGA process; the KB's insiders used only the access they already had — every entitlement you remove is attack surface gone (M1018 User Account Management) |
| **Joiner-mover-leaver automation** | Movers are the silent failure: access accretes across role changes and nobody owns the cleanup. Automate revocation on transfer, not just termination |
| **Privileged access management** | Just-in-time elevation, session recording, and vaulted credentials for admins (M1026 Privileged Account Management) — sabotage cases concentrate in privileged technical staff |
| **Account-use policies** | Time-of-day and location conditions on sensitive accounts (M1036 Account Use Policies); service accounts excluded from interactive logon |
| **Separation of duties in apps** | Maker-checker on payments, vendor creation, beneficiary changes, and entitlement grants — the fraud cluster's T1136/T1098 games usually require the absence of a duty split |

### Data and egress (the exfiltration chain)

| Control | Implementation |
|---|---|
| **Scope repository access** | The KB's collection technique is T1213 — reading what the role can already read. Trim site-wide and org-wide read grants in SharePoint/Confluence/CRM (M1022 Restrict File and Directory Permissions) |
| **Removable-media policy** | Windows GPO *Removable Storage Access → "Removable Disks: Deny write access"* for the default population; where business requires USB, enforce *"Deny write access to removable drives not protected by BitLocker"* (BitLocker To Go) so lost/walked-out drives stay encrypted; EDR device control allowlists by hardware ID for the exception list |
| **DLP on the observed channels** | M1057 Data Loss Prevention on endpoints, email, and web uploads — tuned to the crown-jewel data classes from *Define*, not to everything |
| **Egress friction for personal destinations** | Block or step-up-challenge corporate→personal webmail and cloud-storage uploads at the SWG/CASB; log the rest |
| **Auto-forward off by default** | Disable external auto-forwarding tenant-wide and alert on exceptions — closes the T1114.003 path before detection ever has to fire |
| **Backups insiders can't reach** | Immutable/offline backup tiers with separate credentials (M1053 Data Backup) — the sabotage counter, and your ransomware program already paid for it |

Every row above is a standard control from elsewhere in this library ([Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Windows Hardening](WINDOWS_HARDENING_REFERENCE.md), [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md)) — the insider program's job is to *aim* them using the KB's evidence of what insiders actually do, then verify them with the detection layer below.

---

## Detection approaches

### Start from UAM, not from a product category

The authoritative anchor for insider-threat monitoring is the **user activity monitoring (UAM)** element of the NITTF Minimum Standards — the capability to observe and record user actions on systems, integrated with other information for analysis. The industry term **UEBA** (user and entity behavior analytics — analyst-firm vocabulary with no authoritative government definition) describes the analytic layer commonly built on top: per-user and peer-group baselines with anomaly scoring. Buy or build either; the program requirement is the *capability*, not the acronym.

What distinguishes insider detection engineering from ordinary SOC work:

| Property | Consequence for engineering |
|---|---|
| Activity is authorized | Signature/IOC detection is nearly useless; you are modeling *deviation from this user's and their peers' normal* |
| Loss accrues low-and-slow | Aggregate over weeks/months (rolling counters per user), not per-event thresholds |
| Highest-signal moments are HR events | Resignation notice, PIP, termination, org change — detection sensitivity should *change* when HR state changes |
| Fraud lives in business apps | Application-tier audit logs (payments, claims, CRM, HR systems) are first-class telemetry, not an afterthought |
| The KB records what worked | For each case the KB captures the method of detection and the data sources used — mine it before designing your own |

### The exfiltration chain, instrumented

Mapped to the KB's dominant chain (staging → archiving → USB), with concrete Windows/SaaS telemetry:

| Behavior | ATT&CK | Telemetry to collect |
|---|---|---|
| **Bulk collection from repositories** | [T1213](https://attack.mitre.org/techniques/T1213/) | SharePoint/OneDrive operations in the M365 unified audit log (`FileDownloaded`, `FileSyncDownloadedFull`), CRM/EHR export logs, database audit; volume-per-user-per-day baselines |
| **Local staging** | [T1074](https://attack.mitre.org/techniques/T1074/) | Windows file-system auditing (Event **4663** on sensitive shares via SACLs), Sysmon Event 11 (file create), EDR file telemetry; watch atypical concentration of copies into one directory |
| **Archiving** | [T1560](https://attack.mitre.org/techniques/T1560/) | Process creation — Windows Event **4688** (enable *Include command line in process creation events*) or Sysmon Event 1 — for archive utilities; large archive creation by non-admin users outside build/backup contexts |
| **USB exfiltration** | [T1052.001](https://attack.mitre.org/techniques/T1052/001/) | *Audit PNP Activity* (Event **6416** — external device recognized), *Audit Removable Storage* subcategory (Event **4663** with a removable-storage object), device-control/EDR USB logs; correlate device insertion with file-write volume in the following hour |
| **Cloud/web exfil (the modern variant)** | [T1567](https://attack.mitre.org/techniques/T1567/) / [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Proxy/SWG upload volume to personal cloud storage and webmail, CASB, M365 unified audit log; flag corporate→personal tenant transfers |
| **Email out / auto-forward** | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Exchange Online audit events for `New-InboxRule` / `Set-Mailbox`, outbound auto-forward controls and transport-rule reports; forwarding rules created shortly before resignation are a classic |
| **Printing** | — | `Microsoft-Windows-PrintService/Operational` Event **307** (document printed — enable the channel, it is off by default); page-count outliers on sensitive-system users |
| **Fraud-side account games** | [T1136](https://attack.mitre.org/techniques/T1136/) / [T1098](https://attack.mitre.org/techniques/T1098/) | Windows Events **4720** (account created) / **4738** (account changed) / **4732** (added to security-enabled group), Entra ID audit logs, application-tier provisioning outside the joiner-mover-leaver process |

*(The KB's official case-data clusters are the T1213/T1074/T1560/T1052.001 exfiltration chain and the T1565/T1136/T1213/T1098 fraud cluster. The cloud, email, and printing rows are standard ATT&CK techniques and practitioner telemetry added here as guidance — not KB findings.)*

### Baselining for low-and-slow

The KB's fraud finding — many small transactions, years of dwell — dictates the analytic shape:

- **Rolling windows, not thresholds.** Keep 30/90-day per-user counters for the behaviors above; alert on trend breaks and percentile jumps, not absolute values.
- **Peer-group comparison.** Same role, same department, same system entitlements. "Top decile of USB writes among claims adjusters" means something; "10 GB" alone does not.
- **Sequence beats volume.** The chain *repository read → staging → archive → removable media within days* is far higher signal than any single link. Build the correlation, not four alerts.
- **Change-point on HR events.** Elevate scoring sensitivity for users in notice periods, on PIPs, or affected by reorganizations — with the privacy tiering below, and with HR feeding the state change, not analysts guessing.
- **Separation of duties as detection.** In business applications, alert when the same identity both creates and approves (vendors, payments, accounts) — the fraud cluster's T1136/T1098 games usually violate a duty split somewhere.

### Do / Don't

**Do**

- Build the **USB chain first** — it is the KB's dominant observed exfiltration path and every piece of telemetry is free in Windows audit policy.
- Wire **HR state into detection**: a data-movement alert on an employee in their notice period should outrank the same alert on anyone else.
- Mine the KB's per-case *method of detection* and *data sources* fields — they tell you what actually worked in seven large enterprises.
- Treat departures as a standing use case: a defined **separation review** (last-90-days data movement) for every departure from a sensitive role, per CISA's expanded 2026 separation guidance and PS-4.
- Emulate benignly: prove the chain end-to-end with a marked test file and a purple-team run before you trust the dashboard.

**Don't**

- Don't tune for volume spikes only — the KB's fraud cases ran *years* at under $250 a transaction.
- Don't deploy analytics before the [privacy guardrails](#hr-legal-and-privacy-guardrails) below are signed off; a program that surprises its own workforce loses the trust that produces reports, and reporting is your best sensor.
- Don't present a home-grown "KB technique → 800-53 control" table as official. It isn't. Label your own mappings as yours.
- Don't score people. Score **behaviors**, review with humans, and let the cross-discipline team judge context.
- Don't forget third parties: vendor and contractor accounts belong in the same baselines, and are disproportionately absent from them.

---

## Priority scenarios

Five recurring case shapes, with the trigger that should open the case, the first analytical moves, and who leads. (The response splits matter: an insider case run like a malware incident burns the person's due-process rights and the organization's legal position at the same time.)

| Scenario | Opens on | First moves | Lead |
|---|---|---|---|
| **Departing-employee data theft** | Resignation/termination notice from HR | Separation review: last-90-days repository downloads, USB writes, personal-cloud uploads, new forwarding rules; preserve before confronting | Insider team (HR + security) |
| **Insider fraud** | Duty-split violation, long-window anomaly in a business app, tip | Pull application-tier audit trail; reconstruct the *full* history (KB: years, small amounts); loop in the fraud team and map the monetization side with [F3](FRAUD_FRAMEWORK_REFERENCE.md) | Fraud + insider team jointly |
| **Sabotage risk (privileged user)** | Grievance event + anomalous privileged activity | Review recent privileged changes; verify backup integrity and restore points (M1053); consider access reduction pending assessment — a *Manage*-stage decision, not an analyst's | Insider team, IT leadership informed |
| **Negligent exposure** | DLP event, misdirected email, public share/bucket discovery | Contain the exposure; treat the person as a training outcome, not a suspect — coach-mode DLP first, sanctions only for repeat/willful cases (PS-8's graduated ladder) | Security, HR informed |
| **Compromised account** | Behavioral break inconsistent with the human (impossible travel, MFA fatigue burst, odd hours en masse) | Route to standard [incident response](INCIDENT_RESPONSE_REFERENCE.md) — this is an external intrusion wearing insider clothes; the insider team hands off but stays for the "was it really external?" question | SOC/IR |

**Cross-cutting rules:** evidence handling to forensic standard from the first hour (see [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md)) — most insider cases end in HR action or litigation, where chain of custody decides outcomes; one case record per concern (IIDES-aligned), even for benign resolutions, because BP22's learning loop needs the negatives too; and the cross-discipline team — not the analyst — makes people-facing decisions.

---

## HR, legal, and privacy guardrails

PM-12 requires a **cross-discipline incident handling team** for a reason: almost every meaningful program action — monitoring an identified employee, searching a mailbox, interviewing, sanctioning, referring to law enforcement — is an HR/legal act with a security input, not the reverse.

| Function | What they own in the program |
|---|---|
| **Security / SOC** | Telemetry, analytics, triage, technical containment |
| **HR** | Personnel context (roles, performance actions, separations), supportive interventions, sanctions process (PS-8) |
| **Legal / counsel** | Lawful basis for monitoring, evidence handling, employment law, privilege, when to involve law enforcement |
| **Privacy** | Proportionality review, data minimization, retention, works-council and cross-border obligations |
| **Counterintelligence** (where applicable) | Nation-state recruitment patterns, cleared-population obligations (32 CFR 117) |

### Privacy guardrails that keep the program defensible

- **Documented lawful basis and purpose limitation** — monitoring data collected for insider-threat purposes is used for that purpose only, with an approved-use list and an audit trail on analyst access to the tooling itself (watch the watchers).
- **Proportionality tiers** — baseline telemetry for everyone; enhanced monitoring only on documented risk triggers, time-limited, with named sign-off. Blanket covert deep monitoring of the whole workforce is both a legal exposure and a culture killer.
- **Transparency where law and strategy allow** — acceptable-use and monitoring notices, so detection doubles as deterrence.
- **Jurisdiction check before rollout** — works councils, wiretap/interception statutes, and data-protection regimes constrain UAM differently by country; the *same* dashboard can be routine in one jurisdiction and unlawful in another.
- **Use the CSG 7th edition's NIST Privacy Framework mapping** as the checklist for this section — it exists precisely because the 7th edition treats monitoring itself as a privacy risk to be governed. See also [Privacy Engineering](PRIVACY_ENGINEERING_REFERENCE.md).
- **Training as a two-way deal (AT-2(2))** — the workforce learns to recognize and report indicators; the program commits to due process for reports and monitoring data. Early intervention (the CISA *Manage* stage) is the message: the program exists to help people off the pathway, not to ambush them.

### The separation seam

Employee separation deserves its own procedure because it concentrates risk, telemetry, and legal constraints in one moment (PS-4; expanded in CISA's 2026 edition):

**Do** — trigger the data-movement review at *notice*, not at last day; time access removal to the HR event (and same-hour for involuntary separations); include SaaS/OAuth grants, API tokens, and shared-mailbox delegations in deprovisioning, not just AD; retrieve devices and check for personal-cloud sync clients on them; brief departing holders of sensitive access on their continuing obligations.

**Don't** — don't let contractors bypass the process because they're "not employees" (CISA's third-party type exists for a reason); don't keep the review informal — an IIDES-aligned record of what was checked protects both the organization and the departing person.

---

## Metrics and maturity

### NITTF Maturity Framework

The [NITTF Maturity Framework](https://www.dni.gov/files/NCSC/documents/features/NITTF_MaturityFramework_web.pdf) (November 2018) defines **19 maturity elements** for advancing beyond the Minimum Standards, building on the 2017 NITTF Insider Threat Guide. The pattern it encodes generalizes to any organization: minimum standards get you a *compliant* program (an accountable official, UAM, training, an analysis capability); maturity is measured by how well those pieces **fuse** — leadership engagement, analyst tradecraft, breadth of data integration, and feedback loops from incidents back into controls. Grade your program honestly on the fusion, not the parts list.

### Cost benchmarks (industry survey data — label them as such)

The DTEX-sponsored **Ponemon Cost of Insider Risks** global reports are the most-cited benchmark series. These are vendor-sponsored surveys, not government statistics — use them for trend and order-of-magnitude, not precision:

| Metric | 2025 report | 2026 report |
|---|---|---|
| **Average annual insider-incident cost** | $17.4M (up from $16.2M in 2023) | $19.5M — up 20% from the 2023 report's $16.2M |
| **Average containment time** | 81 days (down from 86) | **67 days** (down from 81) |
| **Orgs with or planning an IRM program** | 81% | — |

The containment number is the one to steal for your own reporting: *67 days average* means an insider program that can triage in days and contain in weeks is materially ahead of the field — a defensible claim to make to leadership without touching the shakier cost-projection math.

### Program KPIs worth reporting

| KPI | Why it matters |
|---|---|
| **Time to triage** (signal → human review) | The insider clock runs in months; triage shouldn't |
| **Containment time** (confirmation → access removed) | Benchmarkable against the Ponemon 67-day figure |
| **Referral mix** (% cases from workforce reports vs. tooling vs. HR) | A healthy program gets many human reports — it means training and trust are working |
| **Coverage of critical assets by UAM/DLP telemetry** | Ties spend to the crown jewels identified in *Define* (and CSG BP1) |
| **Separation reviews completed / departures from sensitive roles** | The highest-risk moment, measured directly |
| **KB technique coverage** | % of the KB's 47 techniques with at least one working detection — load the KB Navigator layer against your detection inventory (see [Security Metrics](SECURITY_METRICS_REFERENCE.md) for the coverage-reporting pattern) |
| **False-positive / benign-resolution rate** | Guards both analyst capacity and workforce trust |
| **Time from incident to control change** | BP22 in practice: does the program learn? |
| **Training completion + report volume trend** | AT-2(2) delivered, and evidence it produces sensors, not just attestations |

### What goes in front of leadership

Quarterly, four numbers and one story: **KB technique coverage** (are we watching what insiders actually do?), **separation-review completion** (are we covering the highest-risk moment?), **containment time vs. the 67-day benchmark** (are we faster than the field?), **referral mix trend** (does the workforce trust the program?) — plus one anonymized case walk-through showing the fusion-to-outcome path working. Resist reporting alert counts; they measure tool chatter, not risk reduction. See [Security Metrics](SECURITY_METRICS_REFERENCE.md) for the executive-reporting patterns this slots into.

---

## Using this with the rest of the library

| Goal | How |
|---|---|
| **See insider coverage on the matrix** | Load the KB's Navigator layer against your coverage layers in [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) |
| **Build the detections** | Join KB technique IDs to the [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) and [Detection Strategies](detections/strategies/README.md) |
| **Pick mitigations** | The KB's M-code mappings land in the [ATT&CK Mitigations Reference](ATTACK_MITIGATIONS_REFERENCE.md); identity-heavy ones in [Identity Security](IDENTITY_SECURITY_REFERENCE.md) |
| **Cover insider *fraud* end-to-end** | The KB shows the insider's IT actions; the [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md) models the monetization side — F1033 Insider Access Abuse is the explicit bridge |
| **Validate it works** | Benign emulation of the KB chains via [Purple Team](PURPLE_TEAM_REFERENCE.md) |
| **Feed the exposure program** | Insider exposure (over-entitlement, unmonitored egress, separation gaps) slots into the [CTEM](CTEM_REFERENCE.md) loop like any other exposure class |
| **Report it** | KPI formulas and executive patterns in [Security Metrics](SECURITY_METRICS_REFERENCE.md); governance in [GRC Reference](GRC_REFERENCE.md) |

---

## Acronyms in this space

| Acronym | Expansion | Where it comes from |
|---|---|---|
| **CTID** | Center for Threat-Informed Defense | MITRE's public-private R&D center (formerly under MITRE Engenuity); maintains the Insider Threat TTP KB and [F3](FRAUD_FRAMEWORK_REFERENCE.md) |
| **NITTF** | National Insider Threat Task Force | EO 13587 (2011); operates under NCSC, co-directed with the FBI |
| **NCSC** | National Counterintelligence and Security Center | ODNI component that houses NITTF |
| **UAM** | User Activity Monitoring | NITTF Minimum Standards element; the authoritative term for insider monitoring capability |
| **UEBA** | User and Entity Behavior Analytics | Analyst-firm vocabulary for the baseline/anomaly layer; no authoritative government definition |
| **OHI** | Observable Human Indicators | CTID KB v2 data-source concept for person-level indicators; still maturing |
| **ITPSO** | Insider Threat Program Senior Official | Required designation for cleared contractors under 32 CFR 117 |
| **IRM** | Insider Risk Management | Industry umbrella for risk-framed (vs. threat-framed) programs |
| **CSG** | Common Sense Guide (to Mitigating Insider Threats) | SEI CERT; 7th Edition, 22 best practices |
| **IIDES** | Insider Incident Data Exchange Standard | SEI CERT JSON schema for insider case records, v1.0 (2025) |
| **JML** | Joiner-Mover-Leaver | Identity-lifecycle process the PS family formalizes |
| **EAP** | Employee Assistance Program | The supportive-intervention arm of the CISA *Manage* stage |

---

## Quick reference: versions and dates

| Resource | Version / edition | Date | Source |
|---|---|---|---|
| **CTID Insider Threat TTP KB** | v2.0.0 (on ATT&CK v14) | March 2024 | [github.com/center-for-threat-informed-defense/insider-threat-ttp-kb](https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb) |
| **MITRE ATT&CK (live)** | v19.2 (v19 cycle began April 28, 2026) | 2026 | [attack.mitre.org/resources/versions](https://attack.mitre.org/resources/versions/) |
| **CISA Insider Threat Mitigation Guide** | 2026 Edition | September 9, 2026 | [cisa.gov](https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide) |
| **CERT Common Sense Guide** | 7th Edition (22 practices) | September 8, 2022 | [SEI digital library](https://www.sei.cmu.edu/documents/619/2022_019_001_886876.pdf) |
| **IIDES** | v1.0 (+ PyIIDES) | June 12, 2025 | [github.com/cmu-sei/iides](https://github.com/cmu-sei/iides) |
| **EO 13587** | — | October 2011 | [dni.gov/NCSC-NITTF](https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-nittf) |
| **National Insider Threat Policy & Minimum Standards** | — | November 2012 | [dni.gov/NCSC-NITTF](https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-nittf) |
| **NITTF Maturity Framework** | 19 elements | November 1, 2018 | [dni.gov PDF](https://www.dni.gov/files/NCSC/documents/features/NITTF_MaturityFramework_web.pdf) |
| **NISPOM rule** | 32 CFR Part 117 | Effective February 24, 2021 | [ecfr.gov](https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117) |
| **NIST SP 800-53** | Rev 5, release 5.2.0 | August 27, 2025 | [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) |

---

## Sources

- CTID Insider Threat TTP Knowledge Base — [repo](https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb) · [project site](https://center-for-threat-informed-defense.github.io/insider-threat-ttp-kb/) · [case analysis](https://center-for-threat-informed-defense.github.io/insider-threat-ttp-kb/analysis/) · [CTID project page](https://ctid.mitre.org/projects/insider-threat-ttp-knowledge-base/) · [v2.0 release announcement (MITRE-Engenuity)](https://medium.com/mitre-engenuity/insider-threat-knowledge-base-2-0-more-techniques-new-mitigations-and-the-human-touch-d246f5ef1135)
- CISA Insider Threat Mitigation — [topic hub](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation) · [defining insider threats](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats) · [2026 guide](https://www.cisa.gov/resources-tools/resources/insider-threat-mitigation-guide) · [2026 release announcement](https://www.cisa.gov/news-events/news/cisa-releases-updated-insider-threat-guide-new-insights-mitigate-physical-and-cyber-threats)
- SEI CERT — [Common Sense Guide, 7th Ed. (PDF)](https://www.sei.cmu.edu/documents/619/2022_019_001_886876.pdf) · [release announcement](https://www.sei.cmu.edu/news/new-edition-of-common-sense-guide-to-mitigating-insider-threats-released/) · [IIDES](https://github.com/cmu-sei/iides)
- ODNI/NCSC — [NITTF](https://www.dni.gov/index.php/ncsc-how-we-work/ncsc-nittf) · [Maturity Framework PDF](https://www.dni.gov/files/NCSC/documents/features/NITTF_MaturityFramework_web.pdf)
- Regulation & controls — [32 CFR Part 117](https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117) · [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- MITRE ATT&CK — [version history](https://attack.mitre.org/resources/versions/)
- Ponemon Institute (DTEX-sponsored) — [2026 Cost of Insider Risks commentary](https://www.ponemon.org/news-updates/blog/security/lessons-learned-from-the-2026-global-cost-of-insider-risks.html)

---

*The Insider Threat TTP Knowledge Base is a project of the MITRE Center for Threat-Informed Defense (Apache-2.0); ATT&CK® is a trademark of The MITRE Corporation. CISA, ODNI/NCSC, and NIST publications are U.S. Government works; the Common Sense Guide is © Carnegie Mellon University. This is an independent practitioner reference, not affiliated with or endorsed by any of these organizations — consult the upstream sources for authoritative and current content. Technique counts (47/29) are sourced from CTID's official v2.0 release announcement; Ponemon figures are vendor-sponsored survey benchmarks; detection telemetry outside the KB's documented clusters is practitioner guidance, not an official CTID mapping.*
