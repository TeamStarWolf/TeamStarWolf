# Global Cyber-Regulation & Breach-Notification Reference

> **In one minute** — This is the single "who must report what, to whom, by when, in which jurisdiction" map for the major cyber-incident and breach-notification regimes a defender or GRC lead has to track: EU (NIS2, DORA, Cyber Resilience Act, AI Act), UK (Cyber Security & Resilience Bill), and US federal and state (SEC Item 1.05, CIRCIA, NYDFS Part 500, HIPAA, California). It leads with a jurisdiction × obligation × deadline matrix, then gives a concise per-regime section (scope, obligations, clocks, penalties, effective dates, source). Use it to answer "we just had an incident — which clocks are now running?" without reading ten statutes. For control frameworks (NIST, ISO, SOC 2, PCI, CMMC) see [FRAMEWORKS.md](FRAMEWORKS.md); for how to operationalize compliance see the GRC references.

| | |
|---|---|
| **Read this when** | an incident just triggered notification duties and you need every clock in one place; scoping which regimes apply to a new market or product; briefing legal/board on cross-border reporting exposure; building an incident-response runbook's notification matrix |
| **Start at** | [Obligation & Deadline Matrix](#obligation--deadline-matrix), [Conflicting Clocks](#conflicting-clocks--practical-guidance), [Regime Detail](#regime-detail) |
| **Pairs with** | [FRAMEWORKS.md](FRAMEWORKS.md), [GRC_REFERENCE.md](GRC_REFERENCE.md), [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md), [disciplines/governance-risk-compliance.md](disciplines/governance-risk-compliance.md), [CVE_REFERENCE.md](CVE_REFERENCE.md) |

> **Not legal advice.** This is a defender's operational reference, not legal counsel. Notification duties turn on facts, definitions, and national transpositions that change; confirm the current text and your specific obligations with qualified counsel before acting. Every date below carries a source or a "status to confirm" marker — verified as of **2026-09-29**.

---

## Obligation & Deadline Matrix

The centerpiece. Deadlines are the *reporting* clocks (time to notify an authority), not remediation SLAs. "Awareness" generally means the moment the entity knew or should reasonably have known — not the end of investigation.

| Regime | Jurisdiction | Who's covered | What triggers | Report to | Deadline(s) | Status / effective | Source |
|---|---|---|---|---|---|---|---|
| **NIS2** (Dir (EU) 2022/2555, Art. 23) | EU (27 MS via national law) | Essential & important entities, ~18 sectors (energy, transport, health, digital infra, public admin, ICT service mgmt); generally medium+ (≥50 staff or >€10M) | "Significant incident" — severe operational disruption, financial loss, or harm to others | National CSIRT / competent authority; recipients of services where appropriate | **Early warning 24h**; **incident notification 72h**; **final report 1 month** (progress report on request; final within 1 month of incident handling if still ongoing) | In force; transposition deadline was 17 Oct 2024 — most MS transposed by 2026, a few still finalizing (confirm per-country) | [EUR-Lex 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) · [ECSO tracker](https://ecs-org.eu/nis2-tracker/) |
| **DORA** (Reg (EU) 2022/2554, Art. 17–23) | EU (directly applicable) | Financial entities (banks, insurers, investment/payment/crypto-asset firms, etc.) + designated critical ICT third-party providers | Major ICT-related incident (voluntary: significant cyber threats) | Competent authority (via national regulator) | **Initial ≤4h from major-classification & ≤24h from awareness**; **intermediate 72h**; **final 1 month** | Applies since **17 Jan 2025** | [EUR-Lex 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) |
| **EU Cyber Resilience Act** (Reg (EU) 2024/2847, Art. 14) | EU | Manufacturers of products with digital elements (PDEs) placed on the EU market | Actively exploited vulnerability, or severe incident affecting product security | ENISA + national CSIRT, via single reporting platform (SRP) | **Early warning 24h**; **notification 72h**; **final 14 days after a fix is available** (severe incident: 1 month after 72h) | Art. 14 reporting **live 11 Sep 2026**; full CRA obligations apply 11 Dec 2027 | [EUR-Lex 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) · [Crowell alert](https://www.crowell.com/en/insights/client-alerts/its-live-the-cyber-resilience-act-reporting-is-mandatory-as-of-today-11-september-2026) |
| **EU AI Act** (Reg (EU) 2024/1689, amended by Digital Omnibus Reg (EU) 2026/1744) | EU | Providers/deployers of high-risk AI; GPAI providers; AI with transparency duties | Serious incident (high-risk systems); transparency to users | Market surveillance authority | Serious-incident reporting attaches to high-risk obligations, now **deferred: Annex III high-risk 2 Dec 2027, Annex I 2 Aug 2028**; transparency (Art. 50) applies **2 Aug 2026** | In force; Omnibus in force 27 Jul 2026 deferred high-risk dates | [EUR-Lex 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) · [Hunton on Omnibus](https://www.hunton.com/privacy-and-cybersecurity-law-blog/eu-digital-omnibus-on-ai-enters-into-force) |
| **UK Cyber Security & Resilience Bill** | UK | CNI operators of essential services + relevant digital service providers (amends NIS Regs 2018); adds NHS, rail, aviation, MSPs | Significant incidents (thresholds to be set) | Competent authorities / ICO | **Not yet law** — timelines TBD in final Act | Introduced to Commons **12 Nov 2025**; report stage & 3rd reading targeted 10 Jun 2026 (status to confirm) | [Commons Library CBP-10442](https://commonslibrary.parliament.uk/research-briefings/cbp-10442/) |
| **US SEC Item 1.05** (17 CFR; Form 8-K) | US (SEC registrants) | Public companies filing with the SEC | Cybersecurity incident **determined material** | SEC, via Form 8-K (public filing) | **4 business days from the materiality determination** (not from discovery) | Effective **18 Dec 2023**; smaller reporting companies since 15 Jun 2024 | [SEC 2023-139](https://www.sec.gov/newsroom/press-releases/2023-139) |
| **US CIRCIA** (6 U.S.C. 681b) | US federal | Covered entities in the 16 critical-infrastructure sectors above SBA small-business size | Covered "substantial cyber incident"; ransom payment | CISA | **72h (incident)**; **24h (ransom payment)** — *not yet enforceable* | Statute enacted 2022; **final rule targeted Sep 2026** (NPRM Apr 2024) | [CISA CIRCIA](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/circia) |
| **US NYDFS Part 500** (23 NYCRR 500) | New York State | DFS-licensed financial-services "covered entities" | Reportable cybersecurity event; ransom payment | NYDFS, via online portal | **72h notification**; ransom-payment notice **24h**, plus **30-day** written explanation | 2nd Amendment effective **1 Nov 2023**; phase-ins through **1 Nov 2025** | [NYDFS 23 NYCRR 500](https://www.dfs.ny.gov/industry-guidance/cybersecurity) |
| **US California breach law** (Cal. Civ. Code §1798.82 / .29) | California | Any person/business/agency holding CA residents' personal info | Breach of unencrypted PI (or encrypted + key) | Affected residents; AG if >500 residents | **30 days to residents** (per SB 446); **AG within 15 days** of notifying residents; sample copy to AG if >500 | SB 446 firm deadlines effective **1 Jan 2026** (previously "expedient, without unreasonable delay") | [Cal. Civ. Code §1798.82](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82.&lawCode=CIV) · [CA OAG reporting](https://oag.ca.gov/privacy/databreach/reporting) |
| **US HIPAA Breach Notification** (45 CFR 164.400–414) | US healthcare | Covered entities & business associates | Breach of unsecured PHI | Individuals + HHS (+ media if ≥500 in a state/jurisdiction) | **≤60 days** to individuals & HHS for ≥500; **<500** logged and reported to HHS annually | In force | [HHS Breach Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html) · [GRC_REFERENCE.md](GRC_REFERENCE.md) |
| **GDPR** (Reg (EU) 2016/679, Art. 33–34; UK GDPR mirrors) | EU/EEA (+ UK) | Controllers (processors notify their controller) | Personal data breach | Supervisory authority; data subjects if high risk | **72h to the supervisory authority**; data subjects "without undue delay" if high risk | In force since 25 May 2018 | [GDPR Art. 33](https://gdpr-info.eu/art-33-gdpr/) · [FRAMEWORKS.md](FRAMEWORKS.md) |

**Reading the matrix:** most EU regimes now share a **24h / 72h / longer-form** cascade, but the *trigger* differs (network incident vs. financial ICT incident vs. exploited product vulnerability vs. personal-data breach), so a single event can start several clocks at once. See [Conflicting Clocks](#conflicting-clocks--practical-guidance).

---

## Regime Detail

### NIS2 — Directive (EU) 2022/2555

- **Scope.** Replaces the 2016 NIS Directive. Splits regulated organizations into **essential** and **important** entities across ~18 sectors (energy, transport, banking, financial market infra, health, drinking/waste water, digital infrastructure, ICT service management, public administration, space, postal, waste, chemicals, food, manufacturing, digital providers, research). Size-cap rule: generally applies to medium-sized and larger entities (≥50 staff or >€10M turnover), with sector carve-ins.
- **Key obligations.** Risk-management measures (Art. 21), governance/management accountability, supply-chain security, and incident reporting (Art. 23).
- **Reporting timeline (Art. 23).** **24h** early warning → **72h** incident notification (initial assessment, severity, IoCs) → **1-month** final report (root cause, mitigations, cross-border impact). Competent authority may request an intermediate/progress report; if the incident is ongoing at one month, a final report follows within a month of handling completion.
- **Penalties.** Minimum caps of **€10M or 2% of global annual turnover** (whichever higher) for essential entities; **€7M or 1.4%** for important entities; plus management-liability provisions.
- **Status.** In force at EU level. National transposition deadline was **17 Oct 2024**; by 2026 the large majority of member states had transposed and several had begun enforcement (early fines reported), but a handful were still completing legislation as of mid-2026. **Confirm the specific member-state law that binds you** — obligations live in national transpositions, not the Directive itself.
- **Source.** [EUR-Lex Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) · transposition status via [ECSO NIS2 tracker](https://ecs-org.eu/nis2-tracker/).

### DORA — Regulation (EU) 2022/2554 (Digital Operational Resilience Act)

- **Scope.** Directly applicable EU regulation (no transposition) covering ~20+ types of **financial entities** — banks, payment/e-money institutions, investment firms, insurers/reinsurers, crypto-asset service providers, trading venues, CCPs, and more — plus an oversight regime for **critical ICT third-party providers** (e.g., major cloud providers).
- **Key obligations.** ICT risk management, ICT third-party risk management including a mandatory **Register of Information** on all ICT third-party contractual arrangements, digital operational resilience testing (incl. threat-led penetration testing for significant entities), incident classification and reporting, and information sharing.
- **Reporting timeline.** For a **major ICT-related incident**: initial notification **within 4 hours of classifying it as major and no later than 24 hours from awareness**; **intermediate report within 72 hours**; **final report within 1 month**. Significant cyber threats may be reported voluntarily.
- **Register of Information.** Financial entities compile the RoI on ICT third parties; first supervisory submissions ran from spring 2025 (national timing varies).
- **Status.** **Applies since 17 January 2025.**
- **Source.** [EUR-Lex Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj).

### EU Cyber Resilience Act — Regulation (EU) 2024/2847

- **Scope.** Horizontal cybersecurity requirements for **products with digital elements (PDEs)** — hardware and software with a data connection — placed on the EU market. Obligations fall mainly on manufacturers, with importer/distributor duties.
- **Key obligations.** Secure-by-design/default, vulnerability handling across the support period, SBOM, conformity assessment and CE marking, and **Article 14 reporting**.
- **Reporting timeline (Art. 14).** For an **actively exploited vulnerability or a severe incident** affecting product security: **24h** early warning → **72h** notification (with an initial assessment and corrective/mitigating measures taken) → for an exploited vulnerability, a **final report within 14 days of a corrective or mitigating measure becoming available** (for a severe incident, within 1 month of the 72h notification). Reports go to **ENISA and the relevant national CSIRT via the single reporting platform (SRP)**.
- **Penalties.** Up to **€15M or 2.5% of global turnover** for breaches of the essential requirements/obligations.
- **Status.** **Article 14 reporting obligations became mandatory 11 September 2026**; the main body of CRA obligations (secure design, conformity, CE marking) applies from **11 December 2027**. Article 14 notably reaches products already on the market, not only those placed after Dec 2027.
- **Source.** [EUR-Lex Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) · go-live confirmation: [Crowell & Moring](https://www.crowell.com/en/insights/client-alerts/its-live-the-cyber-resilience-act-reporting-is-mandatory-as-of-today-11-september-2026).

### EU AI Act — Regulation (EU) 2024/1689 (as amended by Digital Omnibus Reg (EU) 2026/1744)

- **Scope.** Risk-tiered rules for AI systems: prohibited practices, high-risk systems (Annex III use-cases and Annex I product-embedded), general-purpose AI (GPAI) models, and limited-risk systems subject to **transparency** duties (Art. 50).
- **Incident relevance.** Providers of **high-risk** AI must report **serious incidents** to the relevant market-surveillance authority; the trigger and precise clock attach to the high-risk obligations, whose application dates have shifted.
- **What the Digital Omnibus changed.** Regulation (EU) 2026/1744 (in force **27 July 2026**) **deferred** high-risk application: **Annex III high-risk to 2 December 2027** and **Annex I product-embedded high-risk to 2 August 2028**. It did **not** change the risk-classification architecture or Article 50, and it extended SME-style lower penalty caps to small mid-caps (≤500 employees). Earlier milestones already applied: prohibited practices and AI-literacy from 2 Feb 2025; GPAI obligations from 2 Aug 2025; **transparency (Art. 50) from 2 August 2026**.
- **Penalties.** Up to **€35M or 7%** of global turnover for prohibited-practice breaches; lower tiers for other violations.
- **Status.** In force; high-risk serious-incident duties deferred per above.
- **Source.** [EUR-Lex Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) · Omnibus: [Hunton](https://www.hunton.com/privacy-and-cybersecurity-law-blog/eu-digital-omnibus-on-ai-enters-into-force). *(High-risk deferral dates and Omnibus number independently verified 2026-09-29.)*

### UK Cyber Security & Resilience (Network and Information Systems) Bill

- **Scope.** Amends and broadens the UK **NIS Regulations 2018** — extending coverage toward more critical national infrastructure and digital services (reporting includes bringing in bodies such as the NHS, and rail/aviation infrastructure, plus managed service providers), with stronger regulator powers and enforcement.
- **Status.** **Not yet law.** Introduced to the House of Commons as the *Cyber Security and Resilience (Network and Information Systems) Bill 2024-26* on **12 November 2025**; report stage and third reading were scheduled for **June 2026**. Treat all thresholds and reporting clocks as **provisional until Royal Assent** — status to confirm.
- **Source.** [House of Commons Library CBP-10442](https://commonslibrary.parliament.uk/research-briefings/cbp-10442/).

### US SEC Cybersecurity Disclosure — Item 1.05 of Form 8-K

- **Scope.** SEC registrants (public companies). Two pieces: **Item 1.05 (Form 8-K)** incident disclosure and **Regulation S-K Item 106** annual risk-management/governance disclosure in Form 10-K.
- **Reporting timeline.** File an Item 1.05 Form 8-K **within four business days of determining that a cybersecurity incident is material** — the clock runs from the **materiality determination, not discovery**, and the determination must be made "without unreasonable delay." Disclose nature, scope, timing, and material impact; may withhold specifics that would impede response, and (per DOJ process) delay for national-security/public-safety.
- **2024–26 guidance.** SEC staff (2024 statements and C&DIs) clarified that Item 1.05 is for **material** incidents; voluntary disclosure of non-material incidents should use a different item (e.g., 8.01). If impact isn't yet known, disclose and amend later. No change to the four-business-day rule as of 2026-09-29.
- **Status.** Effective **18 Dec 2023**; smaller reporting companies since **15 Jun 2024**.
- **Source.** [SEC press release 2023-139](https://www.sec.gov/newsroom/press-releases/2023-139).

### US CIRCIA — Cyber Incident Reporting for Critical Infrastructure Act of 2022

- **Scope (proposed).** Covered entities in the **16 critical-infrastructure sectors** that exceed the SBA small-business size standard (plus certain sector-based criteria); CISA estimated 300,000+ entities under the NPRM.
- **Reporting timeline (statutory).** **72 hours** to report a covered substantial cyber incident; **24 hours** to report a ransom payment. Preservation-of-data and supplemental-report duties also apply.
- **Status — important.** **The reporting mandate is not yet enforceable.** CISA published the NPRM in **April 2024**, missed the October 2025 statutory deadline for a final rule, and (per the mid-2026 Unified Agenda) **targeted September 2026** for the final rule. Confirm whether the final rule has published and set an effective/enforcement date before relying on the 72h/24h clocks as binding.
- **Source.** [CISA CIRCIA](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/circia) · [CIRCIA FAQs](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/circia/faqs).

### US NYDFS Part 500 — 23 NYCRR 500

- **Scope.** Entities licensed/authorized under NY banking, insurance, or financial-services law ("covered entities"), with limited exemptions for the smallest.
- **Reporting timeline.** Notify the superintendent of a **reportable cybersecurity event within 72 hours**; for **ransom payments**, notify **within 24 hours** and provide a **written explanation within 30 days** of why payment was necessary and alternatives considered. Annual **certification of material compliance** (or acknowledgment of noncompliance) signed by the CISO **and** a senior officer.
- **Second Amendment phase-in.** Effective **1 Nov 2023**, with rolling compliance dates through **1 Nov 2025** — the final tranche (1 Nov 2025) brought universal **MFA for all information-system access** and full asset-inventory requirements. Enhanced governance and independent-audit/pen-test duties for larger "Class A" companies.
- **Penalties.** DFS enforcement; historically multi-million-dollar consent orders.
- **Source.** [NYDFS Cybersecurity](https://www.dfs.ny.gov/industry-guidance/cybersecurity).

### US State Breach-Notification Laws (California as exemplar)

All 50 states have breach-notification statutes; requirements vary by definition of personal information, timing, and AG-notification thresholds. **California** is the reference model:

- **Scope.** Any person or business that owns/licenses computerized PI of a California resident (§1798.82; §1798.29 for state agencies).
- **Trigger.** Acquisition (or reasonable belief of acquisition) of **unencrypted** PI by an unauthorized person (or encrypted PI plus the key).
- **Reporting timeline.** **SB 446** replaced the old "most expedient time possible and without unreasonable delay" standard with a firm **30 calendar days** to notify residents, effective **1 Jan 2026**; if the breach affects **>500 California residents**, notify the **Attorney General within 15 days** of notifying residents, and submit a sample copy of the notice to the AG.
- **Other states to watch.** Many states set 30–45–60-day outer limits (e.g., FL/CO/WA trend toward 30 days); a few require AG notice at lower resident counts. Maintain a per-state matrix for multi-state breaches.
- **Source.** [Cal. Civ. Code §1798.82](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82.&lawCode=CIV) · [CA OAG reporting](https://oag.ca.gov/privacy/databreach/reporting). *(SB 446 30-day/15-day rules independently verified 2026-09-29.)*

### US HIPAA Breach Notification Rule (45 CFR 164.400–414)

- **Scope.** Covered entities (health plans, clearinghouses, most providers) and business associates handling unsecured **PHI**.
- **Reporting timeline.** Notify affected individuals and HHS **without unreasonable delay, no later than 60 days** after discovery; breaches of **≥500** residents in a state/jurisdiction also require **media notice** and prompt HHS reporting; **<500** are logged and reported to HHS **annually**. Business associates notify the covered entity (typically within 60 days).
- **Detail.** Full technical/administrative safeguard and BAA guidance lives in [GRC_REFERENCE.md](GRC_REFERENCE.md#hipaa) and [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md) — this doc carries only the notification clock.
- **Source.** [HHS Breach Notification Rule](https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

### GDPR / UK GDPR (Reg (EU) 2016/679, Art. 33–34)

- **Scope.** Controllers processing personal data of EU/EEA (and, via UK GDPR, UK) data subjects.
- **Reporting timeline.** **72 hours** to the supervisory authority after becoming aware of a personal-data breach (unless unlikely to result in risk to rights and freedoms); **data subjects "without undue delay"** where the breach is likely to result in **high** risk. Processors notify their controller without undue delay.
- **Penalties.** Up to **€20M or 4%** of global turnover.
- **Detail.** Security-of-processing context in [FRAMEWORKS.md](FRAMEWORKS.md#gdpr).
- **Source.** [GDPR Art. 33](https://gdpr-info.eu/art-33-gdpr/).

---

## Conflicting Clocks — Practical Guidance

A single incident routinely trips several regimes with **overlapping but non-identical** windows. Design your IR runbook to the tightest clock and fan out.

- **The 24-hour tier is now common in the EU.** NIS2 early warning, DORA initial notification (≤24h from awareness), and CRA Article 14 early warning all land at **24 hours** — but to *different* recipients (national CSIRT/authority, financial competent authority, ENISA+CSIRT via SRP). A connected-product maker that is also an essential entity can owe **two or three** 24h notices for one event.
- **72 hours is the crowded middle.** GDPR (supervisory authority), NIS2 (incident notification), DORA (intermediate report), CRA (detailed notification), and NYDFS all cluster at or near **72 hours** — again to different regulators. GDPR's 72h is triggered by a *personal-data* breach; NIS2/CRA by a *network/product* incident; the same event can be both.
- **US is trigger-timed, not discovery-timed.** SEC's 4-business-day clock starts at the **materiality determination**; California's 30-day and HIPAA's 60-day clocks start at **discovery**. CIRCIA's 72h/24h are **statutory but not yet enforceable** (final rule pending — see [CIRCIA](#us-circia--cyber-incident-reporting-for-critical-infrastructure-act-of-2022)).
- **Ransom payments have their own fast clocks.** NYDFS **24h** (plus 30-day explanation) and CIRCIA **24h** (once effective) apply specifically to paying a ransom — a decision that must loop in counsel and check OFAC sanctions exposure.
- **Runbook design.** Maintain a pre-mapped notification matrix keyed to (a) data types involved, (b) sectors/jurisdictions of operation, (c) product-on-market status, and (d) entity classification (essential/important, financial, SEC registrant). Pre-stage authority contacts and portal accounts; the 24h tier leaves no time to discover *where* to file.

---

## Adjacent Regimes (contractual / control-framework, not statutory breach reporting)

These carry their own reporting or attestation duties but are covered in depth elsewhere in the library:

| Regime | What it adds | Where |
|---|---|---|
| **PCI DSS v4.0.1** | Contractual (card brands/acquirers), not statutory; breach → notify acquirer/brands per contract; v4.0.1 sole active version since 31 Dec 2024 | [FRAMEWORKS.md](FRAMEWORKS.md#pci-dss-v401), [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md) |
| **CMMC 2.0** | DoD contract requirement; L1 = 15 requirements (FAR 52.204-21); CUI incidents also carry DFARS 72h reporting to DoD | [FRAMEWORKS.md](FRAMEWORKS.md#cmmc-20) |
| **CISA Cross-Sector CPGs** | Voluntary baseline (not a reporting duty); **CPG v2.0 released Dec 2025**, aligned to NIST CSF 2.0 with a new Govern function | [CISA CPGs](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals-cpgs) |
| **CISA BOD 26-04 / KEV** | US federal remediation directive (10 Jun 2026) — risk-based tiers superseding BOD 22-01's KEV deadlines; a remediation SLA, not a reporting clock | [CVE_REFERENCE.md](CVE_REFERENCE.md#_5-cisa-kev-catalog) |

---

## Related Resources

- [FRAMEWORKS.md](FRAMEWORKS.md) — control frameworks (NIST, ISO, SOC 2, PCI, CMMC, GDPR/CCPA) these regimes map onto
- [GRC_REFERENCE.md](GRC_REFERENCE.md) — operational GRC: compliance calendar, HIPAA/PCI detail, contract breach-notification clauses
- [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md) — framework-by-framework compliance implementation
- [disciplines/governance-risk-compliance.md](disciplines/governance-risk-compliance.md) — GRC discipline page
- [CVE_REFERENCE.md](CVE_REFERENCE.md) — CISA KEV, BOD 26-04, and vulnerability-prioritization pipeline

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
