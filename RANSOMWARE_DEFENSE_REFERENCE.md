# Ransomware Defense & Resilience Reference

> **Ransomware defense is a program, not a product — and the authoritative playbook for it is public.** [CISA's #StopRansomware program](https://www.cisa.gov/stopransomware) publishes the joint [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) (CISA, MS-ISAC, NSA, FBI — current edition October 2023), a continuous stream of per-variant joint advisories with version-pinned ATT&CK mappings, and the KEV catalog's ransomware-use flag. NIST pairs it with [IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final), a CSF 2.0 Community Profile dedicated to ransomware risk. This reference assembles that material into a defense-and-resilience program: ecosystem literacy, advisory consumption, framework alignment, backup architecture, hardening, payment policy, exercising, and metrics.

Ransomware is the one incident class where **recovery architecture decides the outcome before the incident starts**. Detection and response matter, but the difference between a bad week and an existential event is usually whether an offline, tested, attacker-unreachable copy of the data existed — and whether anyone had rehearsed restoring it.

Family-by-family profiles (LockBit, ALPHV, Conti lineage, etc.) live in [Malware Families](MALWARE_FAMILIES.md); the step-by-step response procedure lives in the [IR Playbooks](IR_PLAYBOOKS.md) ransomware playbook. This document is the program layer above both: what to build, align, exercise, and measure so those two documents are rarely needed.

**Related:** [Malware Families](MALWARE_FAMILIES.md) · [IR Playbooks](IR_PLAYBOOKS.md) · [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Threat Group Profiles](THREAT_GROUP_PROFILES.md)

---

## Scope & how to use this reference

| You need | Go to |
|---|---|
| **Profiles of specific ransomware families** (TTPs, lineage, notable incidents) | [Malware Families §2](MALWARE_FAMILIES.md) |
| **The response procedure during an active incident** | [IR Playbooks — Ransomware](IR_PLAYBOOKS.md) (Critical severity, NIST lifecycle) |
| **IR program design** (roles, severity models, comms plans) | [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md) |
| **Patch prioritization mechanics** (KEV, EPSS, CVSS) | [CVE Reference](CVE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) |
| **Detection engineering per technique** | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Detection Strategies](detections/strategies/README.md) |
| **The defense program itself** — architecture, alignment, policy, exercising, metrics | **This document** |

Everything here is defensive and policy-level. Attacker behavior is described in the language public advisories use; defender actions are described concretely.

---

## The ransomware ecosystem, in advisory language

Modern ransomware is an economy with division of labor, not a single actor with a binary. The terms below are the descriptive vocabulary used in CISA/FBI joint advisories and Europol/vendor reporting — **there is no official CISA or NIST taxonomy defining them**, so treat them as shared shorthand, not a formal framework.

| Role / term | What public reporting means by it | Defender implication |
|---|---|---|
| **RaaS operator** | Develops and maintains the ransomware, leak site, payment/negotiation infrastructure; leases them out for a revenue share | Family-level IOCs age fast; the *service* persists across rebrands |
| **Affiliate** | Independent intrusion crew that licenses the RaaS kit and performs the actual compromise | TTPs vary per affiliate even within one family — instrument behaviors, not just family signatures |
| **Initial access broker (IAB)** | Sells pre-established footholds (VPN/RDP credentials, webshells, malware installs) to affiliates | Days-to-weeks gap between initial compromise and encryption = your detection window |
| **Double extortion** | Data is exfiltrated *before* encryption; payment demanded for decryption **and** non-publication | Backups alone no longer neutralize the demand; DLP/egress monitoring and breach-notification readiness are part of ransomware defense |
| **Triple extortion** | Additional pressure layers on top: DDoS, contacting victims' customers/patients, regulator tips | Communications and legal must be in the exercise scope, not just IT |
| **Data-leak site (DLS)** | Tor-hosted site where victims are named and stolen data is staged/published to force payment | Monitor for your organization and your third parties; a DLS listing is often the first external signal |

**A live, citable example:** CISA advisory [AA26-222A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a) (August 10, 2026) describes **Gunra** — emerged April 2025 as a double-extortion variant derived from leaked Conti source code, then expanded into a structured RaaS affiliate program. One advisory, three ecosystem lessons: source-code leaks seed new families, lone operations professionalize into RaaS, and exfiltration-first is the default business model.

Each extortion layer rests on a different point of leverage, so each is blunted by a different investment:

| Extortion layer | The demand's leverage | What blunts it |
|---|---|---|
| **Encryption only** | You cannot get your data back | Offline/immutable backups with tested restores ([below](#backup-amp-recovery-architecture)) |
| **+ Data theft (double)** | Stolen data will be published | Egress monitoring, data minimization and encryption at rest, breach-notification readiness — the leverage survives a perfect restore |
| **+ Pressure campaign (triple)** | Customers, patients, or regulators hear from the actor first | DDoS protection, pre-drafted stakeholder communications, a customer-notification playbook exercised in tabletops |

> **Why the economics matter to defenders:** because access is bought rather than earned per-attack, hardening the common initial access vectors (below) raises the price of *every* affiliate's operation against you — the highest-leverage spend in the whole program.

---

## The authoritative advisory stream: CISA #StopRansomware

[stopransomware.gov](https://www.cisa.gov/stopransomware) is the U.S. government's one-stop ransomware resource, operated under the **Joint Ransomware Task Force (JRTF)** — the CISA/FBI-co-chaired interagency body established by Congress under CIRCIA 2022 to coordinate the national campaign against ransomware.

### Anatomy of a #StopRansomware joint advisory

Each per-variant advisory (AA-numbered) follows a consistent, machine-consumable structure:

| Section | What you get | How to use it |
|---|---|---|
| **Overview / attribution** | Variant history, co-sealing agencies (often international) | Threat-intel context; brief leadership |
| **TTPs mapped to ATT&CK** | Technique tables **pinned to a stated ATT&CK version** (AA26-222A pins Enterprise v19.1) | Feed detection engineering; keep the version pin when you import |
| **IOCs** | Hashes, infrastructure, ransom-note artifacts — with **STIX downloads** | Load into TIP/SIEM; expect fast decay |
| **Mitigations** | Aligned to CISA's Cross-Sector Cybersecurity Performance Goals (CPGs) | Gap-assess your controls against each item |
| **Validation guidance** | Instructions to test security controls against the mapped techniques | Purple-team input — see [Purple Team](PURPLE_TEAM_REFERENCE.md) |

Current examples worth reading end-to-end:

| Advisory | Variant | Why it's instructive |
|---|---|---|
| **[AA26-222A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a)** (Aug 10, 2026) | Gunra | Six-agency international co-seal (FBI, CISA, DC3, NSA, USSS, Republic of Korea NPA); Conti-lineage double extortion; ATT&CK v19.1-pinned TTP tables |
| **AA24-242A** | RansomHub | High-volume RaaS affiliate program in advisory language |
| **Medusa** joint advisory (with FBI/MS-ISAC) | Medusa | Updated 2025–2026 — shows how advisories are revised as variants evolve |
| **[AA25-050A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a)** (Feb 19, 2025) | Ghost (Cring) | China-based actors compromising victims in 70+ countries since 2021 by exploiting **years-old unpatched vulnerabilities** in internet-facing services — the KEV-patching argument in advisory form |

**Do**
- Subscribe to the advisory feed and treat each new #StopRansomware advisory as a standing intake into detection engineering and vulnerability management.
- Record the ATT&CK version each advisory pins; re-validate mappings when you upgrade your own ATT&CK baseline.
- Run the advisory's mitigation list as a checklist against your environment within a defined SLA.

**Don't**
- Silently re-map an advisory's techniques to a different ATT&CK version and present the result as the advisory's content.
- Treat IOC ingestion as "done" — the TTP and mitigation sections are the durable value.

### The KEV ransomware flag

CISA's [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) carries a **"Known to be Used in Ransomware Campaigns"** field on every entry (JSON: `knownRansomwareCampaignUse`, values `Known`/`Unknown` — per CISA's published KEV schema). This is the single cheapest prioritization signal in ransomware defense: KEV-listed **and** ransomware-flagged **and** internet-facing → patch first, ahead of everything else. CISA also publishes a companion list of **misconfigurations and weaknesses known to be used in ransomware campaigns** (announced October 12, 2023) — worth a periodic self-assessment pass.

### The Ransomware Vulnerability Warning Pilot (RVWP)

Under CIRCIA 2022, CISA launched the [RVWP](https://www.cisa.gov/stopransomware/Ransomware-Vulnerability-Warning-Pilot) on January 30, 2023: CISA proactively scans for internet-accessible systems carrying ransomware-associated vulnerabilities and notifies the owners. The program scaled quickly: an October 12, 2023 CISA news release reported notifications initiated for over 800 vulnerable systems since launch, and CISA's [2023 Year in Review](https://www.cisa.gov/about/2023YIR) counted **1,754 RVWP notifications in CY2023**, with 49% of the notified devices patched, given a compensating control, or taken offline as a result. (The RVWP page itself posts no running totals; the Year in Review series is where the numbers appear.) If CISA can find your exposed, ransomware-associated service, so can an IAB; run your own external scans against the KEV ransomware-flagged list before someone else does.

---

## The #StopRansomware Guide: prevention and response structure

| | |
|---|---|
| **Current edition** | October 2023 (PDF on cisa.gov) |
| **Co-authors** | CISA, MS-ISAC, NSA, FBI |
| **History** | Original September 2020 (CISA + MS-ISAC); major joint update released May 23, 2023 through the JRTF, adding FBI and NSA as co-authors plus new guidance on compromised credentials, advanced social engineering, cloud backups, zero trust, and threat hunting |
| **Framing** | "Ransomware **and data extortion**" — encryption and data-theft extortion are treated as one problem |
| **Cross-references** | Mitigations aligned to CISA's CPGs — note the guide predates both CSF 2.0 (Feb 2024) and CPG 2.0 (Dec 2025), so its internal CPG references point at CPG v1.0.x |

### Part 1 — Prevention, organized by initial access vector

The guide's structural insight: prevention guidance is grouped by **how ransomware actors get in**, so you can prioritize by your own exposure rather than reading a flat control list.

| Initial access vector (guide's organization) | Representative defenses (see [Hardening](#hardening-amp-prevention-program) below) |
|---|---|
| **Internet-facing vulnerabilities & misconfigurations** | KEV-driven patching, external attack surface management, disable unused RDP/SMB exposure |
| **Compromised credentials** | Phishing-resistant MFA, credential-hygiene monitoring, disable legacy auth |
| **Phishing** | Email authentication (SPF/DKIM/DMARC), attachment sandboxing, user reporting culture |
| **Precursor malware infections** | EDR with behavioral detection; treat loader/stealer infections (QakBot-class) as ransomware precursors, not commodity noise |
| **Advanced social engineering** | Help-desk identity verification procedures, callback verification, vishing awareness |
| **Third parties & MSPs** | Least-privilege vendor access, monitoring of remote-management tooling, contractual security requirements |

### Part 2 — Response checklist, four phases

1. **Detection & analysis** — the guide instructs responders to take the **first three checklist steps in sequence** (identify/isolate impacted systems before anything else)
2. **Reporting & notification**
3. **Containment & eradication**
4. **Recovery & post-incident activity**

The operational expansion of these phases is this library's [IR Playbooks — Ransomware](IR_PLAYBOOKS.md); keep the guide's checklist printed in the physical IR binder — it assumes, correctly, that your tooling may be unavailable during the incident it covers.

---

## Framework alignment: NIST CSF 2.0 and IR 8374r1

| Publication | Status | What it is |
|---|---|---|
| **NIST CSF 2.0** | Released February 26, 2024 | The framework baseline: 6 Functions (Govern, Identify, Protect, Detect, Respond, Recover), 22 Categories, 106 Subcategories |
| **NIST IR 8374r1** | Final June 2026 | *Ransomware Risk Management: A Cybersecurity Framework (CSF) 2.0 Community Profile* — Souppaya, Barker, Fisher, Kent; DOI 10.6028/NIST.IR.8374r1. Supersedes IR 8374 (Feb 23, 2022, which was based on CSF 1.1) |
| **NIST SP 800-61r3** | Final April 2025 | *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile* — supersedes SP 800-61r2 (2012); the current IR framework behind [IR Playbooks](IR_PLAYBOOKS.md) |

IR 8374r1 is the bridge document: it selects and interprets CSF 2.0 outcomes specifically for ransomware, mapping them to ransomware governance, identification, protection, detection, response, and recovery. If your organization already assesses against CSF 2.0, the profile turns "we do CSF" into "we can show ransomware-specific coverage per Function" — the artifact auditors, insurers, and boards increasingly ask for.

| CSF 2.0 Function | Ransomware-profile emphasis (per IR 8374r1's scope) |
|---|---|
| **Govern** | Ransomware risk appetite, payment policy decided *before* an incident, supplier requirements |
| **Identify** | Asset/data criticality (what must restore first), KEV-flagged exposure |
| **Protect** | MFA, patching, segmentation, backup protection, least privilege |
| **Detect** | Precursor-malware and backup-tampering detection, exfiltration monitoring |
| **Respond** | The Part 2 checklist, reporting obligations, negotiation/payment decision path |
| **Recover** | Restore-order runbooks, tested backups, stakeholder communications |

*(IR 8374r1's internal subcategory selections are in the PDF itself; the table above describes the profile's documented scope, not a subcategory-level crosswalk.)*

---

## Instrumenting the intrusion lifecycle with ATT&CK

### Version discipline first

MITRE ATT&CK's current release is **v19.2** (August 6, 2026), the first "Agile" release (targeted Groups/Software/Campaigns updates outside the biannual cadence). **v19** (April 28, 2026) split the former Defense Evasion tactic into two tactics — **Stealth** and **Defense Impairment** — bringing Enterprise to **15 tactics, 222 techniques, 475 sub-techniques**, with **697 Detection Strategies and 1,758 Analytics**. Two consequences:

- **Advisories pin versions.** AA26-222A maps to ATT&CK Enterprise **v19.1**. When you import an advisory's TTP table, record its version; do not silently re-map.
- **There is no official crosswalk** from the #StopRansomware Guide's practices to ATT&CK technique IDs. Per-variant mappings exist only inside individual advisories. Any guide-to-ATT&CK mapping you build internally is your own artifact — label it that way.

### The common lifecycle, as reported in advisories

The pattern below recurs across #StopRansomware advisories (Gunra, RansomHub, Medusa, Ghost among them). The technique IDs are current ATT&CK Enterprise techniques (verified against this library's [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) data); the *association* of each with ransomware operations reflects published advisory reporting, not an official consolidated mapping.

| Lifecycle stage | Representative techniques | What defenders instrument |
|---|---|---|
| **Initial access** | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application · [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services · [T1566](https://attack.mitre.org/techniques/T1566/) Phishing · [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Edge/VPN appliance logs, auth logs for impossible travel and legacy-protocol logons, email gateway verdicts |
| **Execution & persistence** | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter | PowerShell ScriptBlock logging (Event 4104), Sysmon Event 1 (process creation), new service installs (System log Event 7045), scheduled task creation (Security Event 4698) |
| **Credential access** | [T1003](https://attack.mitre.org/techniques/T1003/) OS Credential Dumping | LSASS access alerts (EDR / Sysmon Event 10), Security Events 4624/4625 patterns, new privileged account creation (4720, 4728) |
| **Lateral movement** | [T1021.001](https://attack.mitre.org/techniques/T1021.001/) Remote Desktop Protocol | LogonType 10 fan-out from a single source, SMB admin-share access spikes, remote-management tool installs where none belong |
| **Defense impairment** | [T1562.001](https://attack.mitre.org/techniques/T1562.001/) Impair Defenses: Disable or Modify Tools | EDR/AV tamper alerts, Windows Defender operational log, security-service stop events |
| **Exfiltration** (double extortion) | [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service · [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol | Egress volume baselines, cloud-storage-domain traffic (Rclone/MEGA-class patterns per advisories), [T1530](https://attack.mitre.org/techniques/T1530/) for cloud data stores |
| **Impact** | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact · [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery · [T1489](https://attack.mitre.org/techniques/T1489/) Service Stop | Mass file-modification/rename rates (EDR, FIM), shadow-copy deletion (`vssadmin`/`wmic` command lines), backup-agent and database service stops |

### T1490 is the tripwire that matters most

[T1486](https://attack.mitre.org/techniques/T1486/) (Data Encrypted for Impact) and [T1490](https://attack.mitre.org/techniques/T1490/) (Inhibit System Recovery) both sit under the **Impact** tactic (TA0040) and were both last modified May 12, 2026. T1490 explicitly covers deletion of **volume shadow copies, backup catalogs, and "online" cloud backups** — making it the canonical ATT&CK anchor for backup-destruction detection. Operationally: encryption (T1486) is the *end* of the intrusion; recovery inhibition (T1490) happens minutes-to-hours **before** it. A high-fidelity alert on shadow-copy deletion or backup-catalog tampering is frequently the last automated warning before mass encryption — page a human on it, 24/7.

Concrete tripwires to build (require command-line process auditing — Security Event 4688 with command line, or Sysmon Event 1):

| Tripwire | Telemetry source | Alert posture |
|---|---|---|
| **Shadow-copy deletion** (`vssadmin delete shadows`, `wmic shadowcopy delete`, equivalent WMI/PowerShell) | Security 4688 / Sysmon 1 command lines | Page immediately — near-zero legitimate volume on most fleets |
| **Backup service/agent stops** ([T1489](https://attack.mitre.org/techniques/T1489/)) | System log 7036/7040 (service state/start-type changes) on backup servers | Page on backup infrastructure; investigate elsewhere |
| **Security tooling disabled** ([T1562.001](https://attack.mitre.org/techniques/T1562.001/)) | EDR tamper alerts; Windows Defender Operational log (real-time protection disabled events) | Page — advisories consistently report AV/EDR tampering pre-encryption |
| **Event log cleared** | Security Event 1102 | Investigate urgently; correlate with the above |
| **Backup-console actions**: job deletion, retention shortened, repository credentials changed, snapshot mass-delete | Backup platform audit log (forward it to the SIEM — most deployments don't) | Page; require change-ticket correlation |
| **Boot-recovery tampering** (`bcdedit` disabling recovery, `wbadmin delete catalog`) | Security 4688 / Sysmon 1 command lines | Page — no routine business use |

Detection logic per technique: [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Detection Strategies](detections/strategies/README.md) · [Endpoint Security Reference](ENDPOINT_SECURITY_REFERENCE.md) (Sysmon/audit-policy configuration).

---

## Backup & recovery architecture

The single most consequential section of this document. Design assumption: **the adversary has Domain Admin and is actively hunting your backups** — that is what T1490 documents and what advisories describe.

### The government baseline: 3-2-1

CISA's official backup guidance ([Back Up Business Data](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/back-up-business-data)) defines **3-2-1** as:

| Element | Requirement |
|---|---|
| **3** | Three copies of important files (production + two backups) |
| **2** | Two different types of storage media |
| **1** | One copy stored off-site |
| *plus* | Encryption of backups, **offline copies**, automatic scheduling, and restore testing — full and partial, with the ability to roll back **at least seven days** |

Current advisory language goes further: AA26-222A's mitigations call for **"offline, immutable backups"** and **"multiple copies of sensitive or proprietary data … in a physically separate, segmented, and secure location."** The #StopRansomware Guide likewise requires offline, encrypted backups of critical data with regular restore and integrity testing.

**3-2-1-1-0** (add **1** offline/immutable copy, **0** backup-verification errors) is a widely adopted **industry extension** popularized by Veeam — useful as an operating target, but it has no official CISA or NIST definition. Present it internally as practice, not as government guidance.

### Reference topology

```
 PRODUCTION                BACKUP TIER 1              BACKUP TIER 2              BACKUP TIER 3
 (domain-joined)           (online, fast restore)     (immutable / off-site)     (offline / air gap)

 ┌────────────┐   backup   ┌────────────────┐  copy   ┌──────────────────┐ rotate ┌──────────────┐
 │ Servers,   ├───────────►│ Local backup    ├────────►│ Object storage    ├───────►│ Offline media │
 │ VMs, SaaS, │            │ repository /    │         │ with object lock  │        │ or vaulted,   │
 │ endpoints  │            │ snapshots       │         │ (WORM), separate  │        │ network-      │
 └────────────┘            │                 │         │ cloud tenant/acct │        │ isolated copy │
                           └────────────────┘         └──────────────────┘        └──────────────┘
       ▲                    NOT domain-joined ── separate credentials + MFA ── one-way push only
       │                                                                             │
       └───────────────────────────  tested restore path  ◄─────────────────────────┘
```

### Protecting the backup system itself

**Do**
- Run backup infrastructure **outside the production identity domain** — no domain-joined backup servers, dedicated non-federated admin accounts, MFA on every console.
- Use **immutability** at Tier 2: object-lock/WORM storage, vendor immutable repositories, or snapshot retention that software (and a stolen admin credential) cannot shorten.
- Keep at least one copy genuinely **offline** — if a live credential can reach it over the network, it is "online" in the T1490 sense, whatever the vendor calls it.
- Back up the things people forget: identity (AD/Entra), configuration, SaaS data, and the **backup catalog itself**.
- Alert on backup-job deletion, retention-policy shortening, repository credential changes, and snapshot mass-deletion — backup-console audit logs are a first-class detection source.
- **Test restores on a schedule**: full and partial, timed, from each tier, including one exercise per year that assumes Tier 1 is attacker-destroyed. Record pass/fail — that number is a board metric ([Resilience metrics](#resilience-metrics-amp-program-measurement)).
- Define **restore order** in advance: identity and DNS first, then the systems the business ranked, in writing, as most critical.

**Don't**
- Count replicated or synced copies (DFS-R, storage replication, OneDrive sync) as backups — replication faithfully replicates encryption.
- Leave backup consoles reachable from the general user network, or exposed to the internet.
- Let retention silently shrink below the CISA seven-day rollback floor — many intrusions dwell longer than short retention windows; size retention to your realistic dwell time, not the default.
- Declare victory on "backup completed successfully" — an untested backup is a hypothesis.

### Recovery execution: decide restore order in peacetime

A ransomware restore is not one restore — it is hundreds, under pressure, in an order somebody has to choose. Choose it now, with the business in the room, and write it into a DR plan the IR team can still reach when the document-management system is encrypted.

| Restore wave | What | Why first |
|---|---|---|
| **0 — Trust foundation** | Identity (AD/Entra — rebuilt or verified-clean, not blindly restored), DNS, DHCP, time | Nothing else authenticates or resolves without it; restoring a compromised DC restores the compromise |
| **1 — Recovery enablers** | Backup infrastructure itself, hypervisor management, out-of-band admin access, the SIEM | You cannot run waves 2–3 without the machinery to do it and to watch for re-encryption |
| **2 — Business-ranked critical services** | The systems the business ranked, in writing, before the incident (ERP, EHR, payment processing…) | This ranking is a governance decision (CSF 2.0 Govern/Identify), not an IT guess made at 3 a.m. |
| **3 — Everything else** | General file services, workstations, convenience systems | Accept days-to-weeks; communicate the schedule rather than promising "soon" |

Two rules that recur in post-incident reviews: **restore into a clean, segmented network** (not the still-compromised flat one), and **validate each wave against the tripwire detections above** before opening it to users — re-encrypting freshly restored systems is a documented failure mode when eradication was declared too early. Full procedure: [IR Playbooks — Ransomware](IR_PLAYBOOKS.md).

---

## Hardening & prevention program

Organize prevention the way the guide does — by initial access vector — and gap-assess against CISA's CPGs. Note the version split: the guide (Oct 2023) references CPG v1.0.x; **CPG 2.0** (released December 11, 2025) is aligned to NIST CSF 2.0 and adds a governance component. Separately from the cross-sector goals, CISA and the Sector Risk Management Agencies publish **Sector-Specific Goals (SSGs)** in phases: Chemical, Energy, and IT SSGs are published by CISA, healthcare's goals are published by HHS, and CISA lists Financial Services as coming soon — check the [CPG page](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) for current status. Assess against 2.0; read the guide's CPG pointers as pointing at their v1 equivalents.

| Vector | Priority controls | Library deep dive |
|---|---|---|
| **Internet-facing vulns & misconfigs** | Patch KEV entries (ransomware-flagged first) on an aggressive SLA; external attack-surface scanning; remove exposed RDP/SMB/management interfaces; review against CISA's ransomware misconfigurations list | [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [CVE Reference](CVE_REFERENCE.md) |
| **Compromised credentials** | Phishing-resistant MFA on all remote access and admin accounts; disable legacy authentication; monitor credential dumps for corporate domains; tiered admin model | [Identity Security](IDENTITY_SECURITY_REFERENCE.md) · [Password Security](PASSWORD_SECURITY_REFERENCE.md) |
| **Phishing** | Enforced DMARC; attachment detonation; macro blocking from internet files; one-click user reporting with SOC feedback loop | [Email Security](EMAIL_SECURITY_REFERENCE.md) · [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md) |
| **Precursor malware** | EDR in block mode on every endpoint and server; treat loader/stealer detections as P1 ransomware precursors with mandatory scoping, not auto-closed commodity alerts | [Endpoint Security](ENDPOINT_SECURITY_REFERENCE.md) · [Malware Families](MALWARE_FAMILIES.md) |
| **Advanced social engineering** | Help-desk verification procedures for password/MFA resets; out-of-band callback for privileged requests; executive and IT-staff vishing training | [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md) |
| **Third parties / MSPs** | Least-privilege, MFA-gated, logged vendor access; inventory and restrict remote-management tools; contractual incident-notification clauses | [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) |
| **Blast-radius limitation** (cross-cutting) | Network segmentation between user/server/backup zones; least privilege; zero-trust access for the crown jewels | [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) |

The 2023 guide update's additions — compromised credentials, advanced social engineering, cloud backups, zero trust, threat hunting — are a reliable signal of where the threat actually moved. Weight your roadmap accordingly.

---

## Payment policy considerations

Decide the payment question **in peacetime, in writing, with legal counsel** — never for the first time at 3 a.m. of day one. This section is policy-level orientation, not legal advice.

### OFAC sanctions exposure

The controlling U.S. document is OFAC's [Updated Advisory on Potential Sanctions Risks for Facilitating Ransomware Payments](https://ofac.treasury.gov/system/files/126/ofac_ransomware_advisory.pdf) (September 21, 2021, superseding the October 1, 2020 advisory; no superseding ransomware advisory identified as of this writing):

| Policy point | What it means |
|---|---|
| **Payment is strongly discouraged** | U.S. government position, full stop — payment funds the ecosystem and does not guarantee recovery |
| **Strict liability** | A payment that reaches a sanctioned party violates sanctions **even if nobody knew** — intent and knowledge are not required |
| **Presumption of denial** | License applications to pay a sanctioned party are presumed denied |
| **Applies to facilitators** | Victims **and** everyone in the chain — insurers, DFIR firms, negotiators, payment processors |
| **Mitigating factors** | A risk-based sanctions compliance program; **self-initiated, timely reporting to law enforcement** (CISA/FBI/USSS); full ongoing cooperation |
| **Payment rails can be sanctioned** | Alongside the advisory, OFAC designated the virtual-currency exchange SUEX OTC — the first exchange sanctioned for laundering ransomware proceeds |

The practical takeaway is built into the mitigating factors: **early law-enforcement engagement is not just civic virtue — it is documented sanctions-enforcement mitigation.**

### The rest of the payment picture

- **Law enforcement engagement.** Report to the FBI via [IC3](https://www.ic3.gov/) and to CISA; establish the local FBI field office relationship *before* an incident. LE may hold decryption keys, victim notifications, or actor intelligence you cannot get elsewhere.
- **Cyber insurance.** Know your policy's ransomware terms in advance: notification deadlines, approved-vendor panels (DFIR, negotiators), consent requirements before payment, and sanctions-compliance obligations that flow through the insurer. Insurers are themselves "facilitators" under the OFAC advisory — their process will reflect that.
- **No More Ransom.** [nomoreransom.org](https://www.nomoreransom.org/) — launched July 2016 by the Dutch National Police (NHTCU), Europol's EC3, Kaspersky, and McAfee — hosts free decryptors; its **Crypto Sheriff** matches a ransom note plus encrypted sample to any available tool. At its 2022 six-year milestone it offered 136 free tools with 10M+ downloads and 188 partners; counts grow, so check the live site *before* any payment discussion.
- **Payment does not end the incident.** Decryptors are slow and imperfect, stolen data remains stolen, and the intrusion path remains open until eradicated — see [IR Playbooks](IR_PLAYBOOKS.md).

**Do**
- Write the payment-decision path into the IR plan: who decides, who must be consulted (legal, insurer, LE), and what the OFAC screening step looks like.
- Pre-negotiate DFIR and (if your policy contemplates it) negotiation-firm retainers.

**Don't**
- Let an external party pay "on your behalf" outside your compliance review — strict liability follows the payment.
- Assume a backup-only strategy answers double extortion — the non-publication demand survives a perfect restore.

---

## Exercising readiness

An unexercised ransomware plan is a document, not a capability.

| Resource | What it gives you |
|---|---|
| **[CISA Tabletop Exercise Packages (CTEP)](https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages)** | 100+ self-run exercise kits, including ransomware situation manuals — each with sample objectives, a scenario narrative, and discussion questions; cybersecurity CTEPs align to the NIST CSF in a roughly three-hour format |
| **NIST SP 800-61r3** (April 2025) | The current incident-response framing to exercise against — IR as part of CSF 2.0 risk management, not a standalone silo |
| **This library** | [IR Playbooks](IR_PLAYBOOKS.md) as the script under test; [Purple Team](PURPLE_TEAM_REFERENCE.md) for technical validation of the detections in the [lifecycle table](#instrumenting-the-intrusion-lifecycle-with-attampck) |

A ransomware tabletop earns its three hours when it forces the questions technology cannot answer:

- Backups are encrypted too (T1490 succeeded) — now what?
- Exfiltration is confirmed and a DLS post names you — who briefs customers, regulators, the board, and when?
- The affiliate contacts your customers directly (triple extortion) — whose phone rings, and what do they say?
- The insurer's approved negotiator and your legal counsel disagree — who decides?
- Domain controllers are down — can the IR team even communicate? (Out-of-band comms is a perennial tabletop finding.)

**Cadence that works:** one executive tabletop per year (decision path, comms, payment policy), one technical exercise per year (restore drill against a simulated T1490 event, timed), plus purple-team validation of the Impact-stage detections whenever a major new advisory lands. Feed every finding into the [metrics](#resilience-metrics-amp-program-measurement) below.

---

## A 90-day program bootstrap

For an organization starting from "we have backups and an AV" — sequence borrowed from the same logic as the [CTEM 90-day plan](CTEM_REFERENCE.md): narrow scope, measure reality, fix the cheapest link first.

| Phase | Weeks | Do this |
|---|---|---|
| **Baseline** | 1–2 | Read the [#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) Part 1 against your environment; pull the KEV ransomware-flagged list and diff it against your external attack surface; write down (honestly) current backup tiers, retention, and last successful restore test. |
| **Close the front door** | 3–6 | Patch/remediate every KEV ransomware-flagged, internet-facing finding; enforce MFA on all remote access and admin accounts; kill exposed RDP. This is the IAB-economics play — most affiliates buy access, so make yours expensive. |
| **Wire the tripwires** | 5–8 | Deploy the Impact-stage detections (shadow-copy deletion, backup tampering, EDR tamper, log clearing) with paging; forward backup-console audit logs to the SIEM; upgrade precursor-malware alerts to P1 with mandatory scoping. |
| **Harden recovery** | 7–11 | Separate backup infrastructure from the production identity domain; add an immutable (object-lock/WORM) copy; verify retention meets the seven-day CISA rollback floor or your dwell-time assumption; run one timed, full restore test and record the result. |
| **Decide the hard things** | 9–12 | Payment-decision path in writing with legal (OFAC screening step included); insurer terms reviewed; FBI field office / IC3 reporting path documented; restore-order waves signed off by the business. |
| **Exercise & iterate** | 12–13 | Run a CISA CTEP ransomware tabletop end to end; log findings as tracked work; schedule the annual cadence. |

> **Failure modes to avoid:** buying tooling before wiring the tripwires you already have telemetry for; calling replication a backup; leaving the payment question for incident day; testing restores of single files and calling DR "validated"; and treating the #StopRansomware advisory stream as read-only news instead of a standing work intake.

---

## Resilience metrics & program measurement

Ransomware resilience is measurable. Report movement, not activity — formulas and reporting patterns in [Security Metrics](SECURITY_METRICS_REFERENCE.md).

| Metric | Why it matters |
|---|---|
| **RPO achieved vs. declared** (per critical system) | The data you will actually lose, measured — not the number in the DR document |
| **RTO achieved in last restore test** | The outage you will actually eat; timed restore drills are the only honest source |
| **Restore-test pass rate** (full + partial, per tier) | The "0 errors" of 3-2-1-1-0 as a tracked number; a failed test found in an exercise is a win |
| **% critical data with an offline/immutable copy** | Direct measure of T1490 resistance |
| **Backup retention floor vs. dwell-time assumption** | CISA floor is seven days of rollback; your number should reflect realistic dwell |
| **Patch SLA compliance for KEV ransomware-flagged CVEs** | The highest-signal subset of vulnerability management |
| **MTTD/alert coverage for Impact-stage behaviors** (shadow-copy deletion, backup tampering, mass file modification) | The last-warning tripwires — tested, not assumed |
| **Precursor-malware containment time** | Loader/stealer infection → contained; this window is where ransomware is actually prevented |
| **Exercise cadence & finding closure rate** | Proves the program learns |

**External baseline for context:** the FBI IC3 2025 Annual Report (published 2026) recorded **3,611 ransomware complaints** with reported losses exceeding **$32 million** — a figure that *excludes* downtime and remediation costs, so treat it as a floor — plus more than **2,100 ransomware incidents against U.S. critical infrastructure** and **63 new ransomware variants** identified, with Akira, Qilin, and INC/Lynx among the most-reported families. Useful for board framing: variant counts and family names churn annually; the initial-access vectors and the defense program above stay stable.

---

## Sources

- CISA — #StopRansomware program: <https://www.cisa.gov/stopransomware>
- CISA/MS-ISAC/NSA/FBI — #StopRansomware Guide (October 2023): <https://www.cisa.gov/stopransomware/ransomware-guide> · [PDF](https://www.cisa.gov/sites/default/files/2025-03/StopRansomware-Guide%20508.pdf)
- CISA — updated guide announcement, JRTF (May 23, 2023): <https://www.cisa.gov/news-events/news/cisa-fbi-nsa-ms-isac-publish-updated-stopransomware-guide>
- CISA — AA26-222A #StopRansomware: Gunra Ransomware (Aug 10, 2026): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a>
- CISA — Known Exploited Vulnerabilities catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA — KEV ransomware flag & misconfigurations resource announcement (Oct 12, 2023): <https://www.cisa.gov/news-events/alerts/2023/10/12/cisa-releases-new-resources-identifying-known-exploited-vulnerabilities-and-misconfigurations-linked>
- CISA — AA25-050A #StopRansomware: Ghost (Cring) Ransomware (Feb 19, 2025): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a>
- CISA — Ransomware Vulnerability Warning Pilot: <https://www.cisa.gov/stopransomware/Ransomware-Vulnerability-Warning-Pilot> · 2023 Year in Review (RVWP notification figures): <https://www.cisa.gov/about/2023YIR>
- CISA — Cross-Sector Cybersecurity Performance Goals (CPG 2.0, Dec 11, 2025): <https://www.cisa.gov/cross-sector-cybersecurity-performance-goals>
- CISA — Back Up Business Data (3-2-1 baseline): <https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/back-up-business-data>
- CISA — Tabletop Exercise Packages (CTEP): <https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages>
- NIST — IR 8374r1, Ransomware Risk Management: A CSF 2.0 Community Profile (June 2026): <https://csrc.nist.gov/pubs/ir/8374/r1/final>
- NIST — CSF 2.0 release (Feb 26, 2024): <https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework>
- NIST — SP 800-61r3 announcement (April 2025): <https://csrc.nist.gov/news/2025/nist-revises-sp-800-61>
- MITRE ATT&CK — release notes / updates (v19, v19.2): <https://attack.mitre.org/resources/updates/>
- MITRE ATT&CK — T1486 Data Encrypted for Impact: <https://attack.mitre.org/techniques/T1486/> · T1490 Inhibit System Recovery: <https://attack.mitre.org/techniques/T1490/>
- OFAC — Updated Advisory on Potential Sanctions Risks for Facilitating Ransomware Payments (Sept 21, 2021): <https://ofac.treasury.gov/system/files/126/ofac_ransomware_advisory.pdf>
- No More Ransom: <https://www.nomoreransom.org/> · Europol six-year milestone (2022): <https://www.europol.europa.eu/media-press/newsroom/news/hit-ransomware-no-more-ransom-now-offers-136-free-tools-to-rescue-your-files>
- FBI — IC3 2025 Annual Report: <https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf>

---

*This reference summarizes third-party government and framework publications — CISA's #StopRansomware materials, NIST IR 8374r1/CSF 2.0/SP 800-61r3, MITRE ATT&CK®, OFAC advisories, and the No More Ransom project — as an independent practitioner summary; it is not affiliated with or endorsed by those organizations, and it is not legal advice. Consult the linked originals for authoritative and current content; advisory streams, KEV entries, and decryptor availability change continuously.*
