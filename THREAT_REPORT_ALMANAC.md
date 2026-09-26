# Annual Threat Report Almanac

> **Nobody can read every annual threat report; everybody should know what the big ones can and cannot tell them.** Each spring the industry buries practitioners under hundreds of pages of vendor and government reporting, and most of it gets skimmed for one chart and forgotten. This almanac is an annotated index of the reports that earn their reading time — who publishes each one, what evidence it stands on, when it lands, and the one question it answers better than anything else — plus a method for reading any of them critically. The most important column in every table below is the **methodology basis**: incident casework, product telemetry, surveys, and official statistics are four different instruments, and each can support only certain kinds of conclusion.

Every report indexed here is **free** — "form" in the access column means an email-registration gate, never payment. Names, publishers, release dates, and landing pages were verified against the publishers' own announcements in September 2026; several reports have rebranded or changed hands recently (M-Trends now ships under Google Cloud, X-Force under IBM, Red Canary under Zscaler, Recorded Future under Mastercard), so links point at the current official landing pages.

**Related:** [Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md) · [CTEM](CTEM_REFERENCE.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Threat Actors](THREAT_ACTORS.md) · [ATT&CK Priority Gaps](scores/attack_priority_gaps.md)

---

## Methodology determines meaning

Before the findings, ask what the instrument was. A report's evidence base decides which conclusions it can carry — and most misuse of threat reports is a category error: quoting a casework statistic as if it were a base rate, or a survey perception as if it were a measurement.

| Basis | What it actually measures | Can support | Cannot support | Majors built on it |
|---|---|---|---|---|
| **Incident casework** | Breaches bad enough that someone hired responders | Attacker TTPs in confirmed compromises; dwell time; initial-access mix *within the caseload* | Base rates ("X% of organizations were breached"); anything about intrusions that never triggered an engagement | DBIR (contributed incident data), M-Trends, Unit 42, Sophos |
| **Product telemetry** | Detections across one vendor's install base | Technique prevalence at scale; speed metrics; trend direction | Threats the product cannot see; customers the vendor does not have | CrowdStrike, Microsoft, Red Canary, X-Force (hybrid) |
| **Survey / cost model** | What respondents say in structured interviews | Perceived costs, budgets, program adoption; economic framing | Objective incident frequency; anything respondents cannot accurately recall | Cost of a Data Breach, Ponemon/DTEX insider risk |
| **Official statistics** | Incidents and complaints reported to authorities | Reported-crime trends; loss floors; regulatory context | True totals — unreported crime is invisible by construction | IC3, ENISA, CISA |
| **Analyst synthesis** | Curated intelligence across many sources | Geopolitical narrative, actor intent, forecasts | Falsifiable measurement — there is no denominator at all | Recorded Future, national annual reviews |

The practical rule: **triangulate**. A claim worth acting on shows up in at least two instrument types — when IR casework, telemetry, and official statistics all point at identity abuse and edge-device exploitation, that is signal; when one vendor's survey says its product category is underfunded, that is marketing.

### Lineage and custody

The long-running reports are valuable *because* they are long-running — a consistent instrument read over a decade beats any single year's headline. But several have changed hands recently, which moves landing pages, sometimes changes branding, and occasionally changes the telemetry base underneath the trend line:

| Report | Lineage | Current custody |
|---|---|---|
| M-Trends | Published by Mandiant since 2010 (the 2026 edition is the 17th) | Google Cloud, since Google's 2022 acquisition of Mandiant |
| X-Force Threat Intelligence Index | Descends from IBM's ISS X-Force research line | IBM |
| Threat Detection Report | Red Canary annual since 2019 (2026 is the eighth) | Red Canary, acquired by Zscaler in 2025 |
| State of Security | Successor branding for Insikt Group's annual threat-landscape report | Recorded Future, a Mastercard company since December 2024 |
| Cost of a Data Breach / Cost of Insider Risks | Ponemon Institute research, in publication since the mid-2000s; sponsors have changed over the years | Sponsored and published by IBM and DTEX Systems respectively |

When custody changes, re-read the methodology section before trusting the year-over-year line: a new corporate parent can mean a new sensor fleet, a new customer mix, or a quietly different definition of "incident."

---

## The majors

### Incident-response casework

What responders saw in real engagements. Strongest evidence for *how* attackers operate once inside; weakest for how often anyone gets attacked.

| Report | Publisher | Access | Typically lands | Landing page |
|---|---|---|---|---|
| Data Breach Investigations Report (DBIR) | Verizon Business | Free, no form | Late April–May | [verizon.com/dbir](https://www.verizon.com/business/resources/reports/dbir/) |
| M-Trends | Mandiant, part of Google Cloud | Free (form; exec edition ungated) | March–April | [cloud.google.com — M-Trends](https://cloud.google.com/security/resources/m-trends) |
| Global Incident Response Report | Unit 42, Palo Alto Networks | Free (form) | February–March | [paloaltonetworks.com — Unit 42 IR Report](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report) |
| Active Adversary Report | Sophos | Free, no form | Early in the year (2026: 24 Feb) | [sophos.com — Active Adversary](https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report) |

- **Verizon DBIR** — the closest thing the industry has to a shared statistical baseline: breach and incident data contributed by a large roster of external partners (law enforcement, CERTs, vendors), normalized into the VERIS schema and analyzed with unusual statistical honesty, confidence intervals included. Uniquely good for **patterns by industry and by attack pattern over time** — it is the default citation for "how do breaches in my sector happen." The 2026 edition, published May 2026, covers incidents from 1 November 2024 to 31 October 2025; read the methodology appendix first, because the contributor mix changes year to year.
- **M-Trends (Google Cloud / Mandiant)** — the annual distillation of Mandiant's global IR engagements, and the origin of the industry's **dwell-time** benchmark. Uniquely good for state-sponsored tradecraft and detection-source trends. M-Trends 2026 (March 2026) reported global median dwell time rising to 14 days from 11, pulled upward by long-dwell espionage and DPRK IT-worker cases — a caseload artifact worth understanding before quoting.
- **Unit 42 Global Incident Response Report** — Palo Alto Networks' IR casework (the 2026 edition draws on 750+ incidents from October 2024 to September 2025). Uniquely good for **attack-speed data**: the 2026 report's headline is that the fastest quartile of intrusions reached data exfiltration in 72 minutes, down from 285 the year before.
- **Sophos Active Adversary Report** — IR plus MDR casework (661 cases across 70 countries in the 2026 edition) with a mid-market skew that complements the enterprise-heavy reports above. Uniquely good for the **defender-workflow view**: dwell time by detection route, tooling abused, and where MFA was missing. Its 2026 finding that 67% of cases were rooted in identity attacks, with median dwell time down to three days, pairs instructively with M-Trends' 14 days — see [instrument bias](#how-to-read-a-threat-report-critically).

### Product and platform telemetry

What sensors saw at scale. Strongest for prevalence and speed among the vendor's customer base; silent about everything outside it.

| Report | Publisher | Access | Typically lands | Landing page |
|---|---|---|---|---|
| Global Threat Report | CrowdStrike | Free (form) | Late February | [crowdstrike.com — Global Threat Report](https://www.crowdstrike.com/en-us/global-threat-report/) |
| Microsoft Digital Defense Report | Microsoft | Free, no form | October | [microsoft.com — MDDR](https://www.microsoft.com/en-us/security/business/security-intelligence-report) |
| X-Force Threat Intelligence Index | IBM | Free (form) | February–April | [ibm.com — X-Force Index](https://www.ibm.com/reports/threat-intelligence) |
| Threat Detection Report | Red Canary (a Zscaler company) | Free (web open; PDF form) | March | [redcanary.com — Threat Detection Report](https://redcanary.com/threat-detection-report/) |

- **CrowdStrike Global Threat Report** — Falcon telemetry plus the OverWatch hunting team and adversary tracking; the source of the **breakout time** metric (foothold to lateral movement). The 2026 edition (24 February 2026) put average eCrime breakout at 29 minutes, the fastest observed at 27 seconds. Uniquely good for named-adversary tracking and eCrime ecosystem trends; remember its naming scheme (SPIDERs, BEARs, PANDAs) is proprietary — map to your own actor names via [Threat Actors](THREAT_ACTORS.md).
- **Microsoft Digital Defense Report** — the largest telemetry aperture in the industry (Windows, Entra, M365, Azure) plus MSTIC/DART nation-state tracking. Uniquely good for **identity-attack statistics and nation-state activity at platform scale**: the 2025 edition (October 2025, covering July 2024–June 2025) reported 52% of attacks financially motivated and password attacks making up more than 97% of identity attacks. Long and policy-flavored — read the chapter you need, not the whole volume.
- **IBM X-Force Threat Intelligence Index** — a hybrid of X-Force IR engagements, managed-security telemetry, and dark-web tracking; the long-running **initial-access-vector share** tables are its trademark. The 2026 edition (25 February 2026) reported a 44% jump in attacks beginning with exploitation of public-facing applications. Uniquely good for regional and industry attack-share comparisons.
- **Red Canary Threat Detection Report** — the most operationally reusable of the set: confirmed threats (110,000+ across 1,700 organizations in the 2026 edition) ranked into **top ATT&CK techniques and top threats, with detection and testing guidance per technique**. Uniquely good for feeding detection-engineering backlogs directly — it is the natural annual companion to [ATT&CK Priority Gaps](scores/attack_priority_gaps.md).

### Surveys and cost models

What respondents reported. The only instrument that reaches costs and program behavior — and the one most exposed to recall bias, sampling choices, and sponsor framing.

| Report | Publisher | Access | Typically lands | Landing page |
|---|---|---|---|---|
| Cost of a Data Breach Report | IBM, research by Ponemon Institute | Free (form) | Late July | [ibm.com — Cost of a Data Breach](https://www.ibm.com/reports/data-breach) |
| Cost of Insider Risks Global Report | DTEX Systems, research by Ponemon Institute | Free (form) | Late February | [ponemon.dtex.ai](https://ponemon.dtex.ai/) |

- **IBM Cost of a Data Breach** — Ponemon Institute interviews with organizations that actually suffered breaches (602 of them, March 2025–February 2026, in the 2026 edition), converted to cost via activity-based estimation. Uniquely good for the **board and budget conversation**: cost per record, cost by industry and by control. The 2026 report (29 July 2026) put the global average at $4.99M and the US average at $11.5M. It is an average of *studied* breaches — not your expected loss, and not a breach-probability measure.
- **Ponemon / DTEX Cost of Insider Risks** — the insider-threat counterpart, surveying thousands of practitioners on incident counts, containment time, and annualized cost. The 2026 edition (24 February 2026) reported an average annual insider-risk cost of $19.5M and containment down to 67 days. Uniquely good for justifying insider-risk programs — pair it with [Insider Threat](INSIDER_THREAT_REFERENCE.md) and treat every self-reported count as a perception, not a measurement.

### Government and official statistics

What was reported to authorities. Authoritative floors, systematic undercounts.

| Report | Publisher | Access | Typically lands | Landing page |
|---|---|---|---|---|
| ENISA Threat Landscape (ETL) | ENISA (EU Agency for Cybersecurity) | Free, no form | September–October | [enisa.europa.eu — Threat Landscape](https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape) |
| IC3 Internet Crime Report | FBI Internet Crime Complaint Center | Free, no form | April | [ic3.gov — Annual Reports](https://www.ic3.gov/AnnualReport/Reports) |
| CISA Year in Review | CISA | Free, no form | January–February | [cisa.gov — 2025 Year in Review](https://www.cisa.gov/about/2025YIR) |

- **ENISA Threat Landscape** — the EU's official annual synthesis, built on open-source collection of publicly reported incidents (4,875 of them, July 2024–June 2025, in the 2025 edition, published 1 October 2025). Uniquely good for the **European regulatory and sectoral view** — it is the report to cite in NIS2-adjacent work, and its threat taxonomy is a useful neutral vocabulary. Its counts reflect what became public, not what happened.
- **FBI IC3 Internet Crime Report** — victim complaints filed with the FBI: the 2025 report (April 2026) logged 1,008,597 complaints and $20.9B in reported losses, both records. Uniquely good for **fraud and cybercrime loss trends** — BEC, investment scams, ransomware complaints, elder fraud — and the only major built on victim self-reporting at population scale. Losses are a floor; most victims never file.
- **CISA Year in Review** — the agency's own account of its year (the 2025 edition landed in early February 2026). Read it honestly for what it is: an accomplishments report, not a threat-statistics report. Uniquely good for discovering **free CISA services, exercises, and joint advisories** your program is not yet using.

### Sector deep dives and intelligence synthesis

| Report | Publisher | Access | Typically lands | Landing page |
|---|---|---|---|---|
| OT/ICS Cybersecurity Year in Review | Dragos | Free (form) | February | [dragos.com — Year in Review](https://www.dragos.com/ot-cybersecurity-year-in-review) |
| State of Security Report | Recorded Future (a Mastercard company) | Free (form) | February | [recordedfuture.com — State of Security](https://www.recordedfuture.com/research/state-of-security) |

- **Dragos OT/ICS Year in Review** — the reference report for industrial and critical-infrastructure defense, built on Dragos IR casework, OT telemetry, and its own vulnerability re-analysis. The 2026 edition (17 February 2026, ninth year) found 25% of ICS advisories carried incorrect CVSS scores and 26% shipped with no patch or mitigation — the kind of data nobody else publishes. Uniquely good for OT threat-group tracking; feed it into [ICS/OT Security](ICS_OT_SECURITY_REFERENCE.md) and the [ICS ATT&CK Atlas](ICS_ATTACK_ATLAS.md).
- **Recorded Future State of Security** — Insikt Group's annual threat-landscape analysis (the 2026 edition launched 12 February 2026 at the Munich Cyber Security Conference), synthesizing state-sponsored, criminal, and emerging-technology trends into a geopolitical narrative. Uniquely good for **strategic-tier intelligence** — briefing leadership on the year ahead — rather than for any single defensible statistic.

### Honorable mentions by sector and region

| Report | Publisher | Focus | Typically lands | Access |
|---|---|---|---|---|
| [NCSC Annual Review](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025) | UK NCSC (GCHQ) | UK national picture | October–December | Free |
| [ASD Annual Cyber Threat Report](https://www.cyber.gov.au/about-us/view-all-content/reports-and-statistics/annual-cyber-threat-report-2024-2025) | Australian Signals Directorate (ACSC) | Australia; strong SMB guidance | October–November (AU financial year) | Free |
| [Global Cybersecurity Outlook](https://www.weforum.org/publications/global-cybersecurity-outlook-2026/) | World Economic Forum, with Accenture | C-suite risk perception, 90+ countries | Mid-January, before Davos | Free |
| [Cloud Threat Horizons Report](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026) | Google Cloud Office of the CISO | Cloud-specific threats | Twice yearly (H1/H2 editions) | Free |
| [Health Sector Annual Threat Report](https://health-isac.org/annual-threat-report-health-sector-2026/) | Health-ISAC | Healthcare sector | January–February (members first) | Free |
| [ENISA Space Threat Landscape](https://www.enisa.europa.eu/publications/enisa-space-threat-landscape-2025) | ENISA | Space segment; pairs with [Space Security](SPACE_SECURITY_REFERENCE.md) | Periodic sectoral companion to the ETL | Free |

Survey-heavy vendor "state of X" reports beyond these exist by the hundred; apply the [critical-reading test](#how-to-read-a-threat-report-critically) before letting one into a deck.

---

## Cover year versus data window

A report's cover year is a marketing label; its data window is a methodology fact, and the two rarely match. Most "2026" reports describe calendar 2025 — or an offset year that ends the previous autumn — so two same-year covers can describe periods that barely overlap. The windows below are as stated by the publishers for the current editions:

| Edition | Actual data window |
|---|---|
| Verizon DBIR 2026 | 1 Nov 2024 – 31 Oct 2025 |
| M-Trends 2026 | Investigations conducted during calendar 2025 |
| Unit 42 Global IR Report 2026 | Oct 2024 – Sep 2025 |
| Sophos Active Adversary Report 2026 | 1 Nov 2024 – 31 Oct 2025 |
| Microsoft Digital Defense Report 2025 | Jul 2024 – Jun 2025 |
| ENISA Threat Landscape 2025 | 1 Jul 2024 – 30 Jun 2025 |
| IBM Cost of a Data Breach 2026 | Breaches suffered Mar 2025 – Feb 2026 |
| FBI IC3 Internet Crime Report 2025 | Calendar 2025 |
| ASD Annual Cyber Threat Report 2024–25 | Australian financial year, Jul 2024 – Jun 2025 |
| UK NCSC Annual Review 2025 | 1 Sep 2024 – 31 Aug 2025 |

Two consequences. First, when a February report and a May report disagree about "last year," check whether they even measured the same year. Second, a fast-moving development (a new exploitation wave, a takedown) can be present in one report's window and absent from another's — absence of a finding is often just a calendar artifact.

---

## How to read a threat report critically

Four traps account for most bad citations of good reports.

| Trap | What it looks like | The test |
|---|---|---|
| **The denominator problem** | "40% of attacks used X" — 40% of *what*? Cases the vendor worked? Detections its product fired on? Complaints filed? | Find the denominator sentence in the methodology section. If you cannot restate it ("of 661 Sophos IR/MDR cases…"), do not quote the number |
| **Instrument bias** | Survey respondents overweight what is salient; telemetry overweights what the sensor sees; casework overweights breaches bad enough to hire help | Ask what the instrument is structurally blind to — MDR telemetry cannot observe long-dwell espionage it already evicted; surveys cannot observe unnoticed breaches |
| **Vendor incentive** | The threat the vendor's product addresses is, reliably, the year's defining threat | Discount the framing, keep the data; prefer numbers that survive across competing vendors' reports |
| **Year-over-year comparability** | "Ransomware up 30%" after the vendor grew its customer base 40%, changed taxonomy, or gained new data contributors | Check whether the report itself flags methodology changes (the DBIR and M-Trends do); compare rates and shares, not raw counts |

Three subtler failure modes, worth naming because they survive even careful readers:

- **Definitional drift.** "Ransomware incident," "identity-based attack," and "AI-enabled breach" have no industry-standard definitions; each publisher draws its own boundary, and some redraw it between editions. A category that grows 50% the year it was redefined has not grown 50%. The newer the category (anything AI-labeled since 2025), the softer the definition.
- **Composition effects.** A vendor's telemetry trend rides on its customer mix: expand into healthcare and "attacks on healthcare" rise in the data with no change in the world. Casework has the same problem — one large multi-victim campaign (a file-transfer exploitation wave, a single prolific actor) can dominate a year's caseload and masquerade as a broad trend.
- **Precision theater.** Two decimal places on a statistic derived from a few hundred interviews implies a precision the sample cannot carry. Reports that publish confidence intervals or explicitly rounded figures are signaling methodological honesty; reward them.

**The dwell-time object lesson.** In the same season, Sophos reported median dwell time of 3 days (2026) and Mandiant reported 14 days (2026) — and both are right. Sophos's caseload is MDR-heavy (detection is the product); Mandiant's 2025 caseload was espionage-heavy, with edge-device persistence and DPRK IT-worker cases stretching the tail. Neither number is "the" dwell time; each measures its own caseload. Any metric quoted without its caseload is an anecdote with decimals.

**Do**

- Read the methodology section first, findings second; the appendix decides what the headline means.
- Extract technique-level and vector-level findings (portable) rather than cost or percentage headlines (caseload-specific).
- Note each report's **data window** — most "2026" reports describe calendar 2025 or an offset year like November–October; two reports with the same cover year can describe different periods.
- Keep last year's edition; the deltas within one report's consistent methodology are worth more than comparisons across reports.

**Don't**

- Average statistics across reports with different denominators — a 3-day and a 14-day median do not make an 8.5-day truth.
- Cite a survey finding as a measurement, or vendor telemetry as an industry base rate.
- Treat report release week (February–March clusters ahead of spring conference season) as if threat activity itself were seasonal.

---

## The reading calendar

Reports cluster hard in late winter. Spread the load: assign each quarter's arrivals an owner who extracts findings into the library workflows below within two weeks of release.

| Quarter | What lands | Reading priority |
|---|---|---|
| **Q1 (Jan–Mar)** | WEF Outlook (Jan) · Recorded Future State of Security, Dragos YIR, CrowdStrike GTR, X-Force Index, Sophos AAR, Unit 42 GIRR, Ponemon/DTEX Insider (Feb) · Red Canary TDR, M-Trends (Mar–Apr) · CISA YIR, Health-ISAC (Jan–Feb) | Heaviest quarter — triage by role: detection engineers take the TDR, OT takes Dragos, leadership takes WEF and State of Security |
| **Q2 (Apr–Jun)** | FBI IC3 (Apr) · M-Trends if not already out · **Verizon DBIR (late Apr–May)** | The DBIR is the one report worth a full team read-through |
| **Q3 (Jul–Sep)** | IBM Cost of a Data Breach (late Jul) | Refresh board-deck cost figures; recheck the year's Q1 claims against DBIR/IC3 data |
| **Q4 (Oct–Dec)** | Microsoft Digital Defense Report, ENISA ETL, NCSC Annual Review, ASD ACTR (Oct–Dec) | The government-and-platform quarter; feed annual planning and next year's PIRs |

### A starter stack by role

Nobody should read all fifteen majors. Five, chosen for the seat you sit in, cover most of the value:

| Role | Read these | Because |
|---|---|---|
| **SOC / detection engineering** | Red Canary TDR · CrowdStrike GTR · M-Trends · Sophos AAR · MDDR | Technique prevalence, speed benchmarks, and per-technique detection guidance map straight to backlog items |
| **Vulnerability / exposure management** | DBIR · X-Force Index · M-Trends · Dragos YIR (if any OT) · ENISA ETL | Initial-access vector shares and exploitation trends are the *threat relevance* input to prioritization ([CTEM](CTEM_REFERENCE.md) Stage 3) |
| **CISO / leadership** | DBIR · Cost of a Data Breach · WEF Outlook · Recorded Future State of Security · MDDR | Board-legible cost, risk-perception, and geopolitical framing with defensible sourcing |
| **OT / ICS** | Dragos YIR · MDDR · ENISA ETL · ASD ACTR or sector ISAC · IC3 | One deep OT source plus the general landscape it sits inside |
| **GRC / insider risk** | Cost of a Data Breach · Ponemon/DTEX Insider · ENISA ETL · IC3 · NCSC or ASD annual | Regulatory context and economic framing for risk registers ([Insider Threat](INSIDER_THREAT_REFERENCE.md), [GRC](GRC_REFERENCE.md)) |

---

## Feeding the threat-informed workflow

An annual report earns its shelf space only when its findings land in a workflow. In this library:

| Library workflow | Reports that feed it | What to extract |
|---|---|---|
| **Strategic CTI and PIRs** — [Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md) | Recorded Future, MDDR, ENISA, national reviews | Actor intent and sector targeting for next year's priority intelligence requirements; strategic-tier briefing material |
| **ATT&CK technique prioritization** — [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ATT&CK Priority Gaps](scores/attack_priority_gaps.md) | Red Canary TDR, M-Trends, Unit 42, X-Force | Top-technique lists and initial-access shares → re-weight the technique priority scores and the ATTACK-Navi layers |
| **CTEM scoping and prioritization** — [CTEM](CTEM_REFERENCE.md) (Stages 1 and 3) | DBIR industry patterns, Dragos (OT scopes), sector honorable mentions | The *threat relevance* signal: which vectors and techniques actors actually use against your sector this year |
| **Metrics context and benchmarks** — [Security Metrics](SECURITY_METRICS_REFERENCE.md) | M-Trends and Sophos (dwell), CrowdStrike (breakout), Unit 42 (time-to-exfil), Cost of a Data Breach (cost) | External context lines for your own MTTD/MTTR trend charts — always labeled with the source's caseload caveat |
| **Detection engineering** — [Detection Rules](DETECTION_RULES_REFERENCE.md) · [SIEM Content](SIEM_DETECTION_CONTENT.md) | Red Canary TDR (per-technique detection guidance), MDDR | New analytics for the year's top techniques; validation targets for purple-team cycles |
| **IR preparedness** — [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) | Unit 42, Sophos, M-Trends | Speed benchmarks (breakout, time-to-exfiltration) as tabletop scenario parameters |

The repeatable practice: for each report you adopt, extract exactly three artifacts — the techniques or vectors that moved, the metric worth using as external context, and the one finding that changes a priority in the current CTEM cycle — and file them into the references above. Everything else is reading, not intelligence.

**Worked example — one report, three artifacts.** The 2026 Red Canary Threat Detection Report lands in March. From its public findings:

1. *Techniques that moved:* identity threats at record volume and remote monitoring and management (RMM) tools as a payload of choice, frequently following paste-and-run lures → re-weight the corresponding techniques in [ATT&CK Priority Gaps](scores/attack_priority_gaps.md) and queue RMM-abuse analytics in [SIEM Content](SIEM_DETECTION_CONTENT.md).
2. *Metric for context:* its analysis base (110,000+ confirmed threats across 1,700 organizations, 2026) goes into the footnote of any chart that borrows its prevalence figures — the caseload caveat travels with the number.
3. *Priority change:* browsers called out as a primary adversary focal point → check whether the current [CTEM](CTEM_REFERENCE.md) cycle's scope statement covers browser extensions and session tokens; if not, that is a Stage 1 input for the next cycle, worked with [Browser Security](BROWSER_SECURITY_REFERENCE.md).

Fifteen minutes per report, three durable artifacts, and the report has done its job before the next one lands.

---

## Sources

Verification anchors, September 2026 — publisher announcements for the current editions:

- Verizon: [2026 DBIR landing page](https://www.verizon.com/business/resources/reports/dbir/) and [2026 announcement](https://www.verizon.com/about/news/breach-industry-wide-dbir-finds)
- Google Cloud: [M-Trends 2026 blog](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/) · [Threat Horizons H1 2026](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026)
- CrowdStrike: [2026 Global Threat Report press release](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/)
- Microsoft: [Digital Defense Report 2025](https://www.microsoft.com/en-us/corporate-responsibility/topics/cybersecurity/reports/microsoft-digital-defense-report-2025/)
- ENISA: [Threat Landscape 2025](https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025) · [Space Threat Landscape 2025](https://www.enisa.europa.eu/publications/enisa-space-threat-landscape-2025)
- IBM: [2026 X-Force Threat Index press release](https://newsroom.ibm.com/2026-02-25-ibm-2026-x-force-threat-index-ai-driven-attacks-are-escalating-as-basic-security-gaps-leave-enterprises-exposed) · [2026 Cost of a Data Breach announcement](https://newsroom.ibm.com/2026-07-29-ibm-study-one-in-four-malicious-breaches-are-ai-enabled,-costing-companies-6-million-on-average)
- Sophos: [Active Adversary Report 2026 press release](https://www.sophos.com/en-us/press/press-releases/sophos-active-adversary-report-2026-identity-attacks-dominate-as-threat-groups-proliferate)
- Red Canary: [2026 Threat Detection Report blog](https://redcanary.com/blog/threat-detection/2026-threat-detection-report/)
- Recorded Future: [2026 State of Security announcement](https://www.prnewswire.com/news-releases/recorded-future-2026-state-of-security-report-warns-cyber-operations-have-become-a-core-tool-of-global-power-302686566.html)
- CISA: [2025 Year in Review](https://www.cisa.gov/about/2025YIR) and [announcement](https://www.cisa.gov/news-events/news/cisas-2025-year-review-driving-security-and-resilience-across-critical-infrastructure)
- FBI IC3: [2025 Internet Crime Report (PDF)](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf)
- Dragos: [2026 Year in Review press release](https://www.dragos.com/resources/press-release/dragos-2026-year-in-review-new-ot-threats-ransomware)
- Palo Alto Networks: [2026 Unit 42 Global IR Report blog](https://www.paloaltonetworks.com/blog/2026/02/unit-42-global-ir-report/)
- DTEX / Ponemon: [2026 Cost of Insider Risks announcement](https://www.globenewswire.com/news-release/2026/02/24/3243891/0/en/Insider-Risk-Costs-Hit-19-5M-USD-Per-Year-as-AI-Creates-New-Blind-Spots.html)
- UK NCSC: [Annual Review 2025](https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025) · ASD: [Annual Cyber Threat Report 2024–25 release](https://www.asd.gov.au/news/2025-10-14-australian-signals-directorate-releases-annual-cyber-threat-report-2024-25)
- World Economic Forum: [Global Cybersecurity Outlook 2026](https://www.weforum.org/publications/global-cybersecurity-outlook-2026/) · Health-ISAC: [Annual Threat Report 2026](https://health-isac.org/annual-threat-report-health-sector-2026/)

---

*This almanac is an original, independent annotated index for a defensive reference library. All report names and trademarks belong to their publishers; none endorses this document. It reproduces no report content — the handful of headline findings quoted above come from the publishers' own public announcements and are attributed by edition year — and links go to official landing pages only. Release windows and access terms were verified in September 2026 and do change; when an edition matters to a decision, confirm against the publisher's page. Read every statistic here with its methodology attached.*
