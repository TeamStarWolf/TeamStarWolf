# Security-Program Management / CISO Handbook

> **In one minute** — This is the leader's field manual for *building and running* a security program, not for operating any single control. It picks up where the practitioner references leave off: your first 90 days, where the CISO should report, how much to budget and how to defend it, how to turn a risk register into a funded roadmap, how to brief a board that now has statutory oversight duties, and how to make the disclosure and escalation calls that carry personal legal weight. Everything technical (metrics formulas, GRC control detail, breach clocks, TPRM questionnaires) lives in sibling docs — this doc cross-links to them and adds the management layer on top.

| | |
|---|---|
| **Read this when** | you just took (or are interviewing for) a security-leadership role, standing up a program from zero, rebuilding one after an incident or a failed audit, defending or cutting a security budget, prepping a board deck, or deciding who declares an incident "material" |
| **Start at** | [The First 90 Days](#the-first-90-days), [Organizational Design & Reporting Lines](#organizational-design--reporting-lines), [Budgeting & Headcount](#budgeting--headcount), [Board & Executive Reporting](#board--executive-reporting) |
| **Pairs with** | [GRC_REFERENCE.md](GRC_REFERENCE.md), [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md), [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md), [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md), [CAREER_PATHS.md](CAREER_PATHS.md), [FRAMEWORKS.md](FRAMEWORKS.md) |

> **Not legal advice.** Disclosure, materiality, and personal-liability topics below are operational guidance for a security leader, not legal counsel. Materiality determinations, breach-notification duties, and director/officer exposure turn on specific facts and jurisdictions — decide them with qualified counsel and your general counsel in the room. Regulatory specifics were verified as of **2026-09-29**; confirm current text before relying on any clock or rule.

---

## The Security Leader's Job

The step from senior practitioner to security leader is a change of *unit of work*, not a promotion in the same job. A practitioner is measured on artifacts they produce; a leader is measured on outcomes a team produces, decisions made under uncertainty, and the risk the organization is willing to carry. The failure mode of new CISOs is staying the best individual contributor on the team instead of building the system that makes the team unnecessary to any single decision.

**CISO archetypes** — organizations hire for a *center of gravity*, and mismatches end tenures early. Know which one you are and which one the org actually needs:

| Archetype | Center of gravity | Hired when | Watch-out |
|---|---|---|---|
| **Technical / builder** | Architecture, detection, engineering depth | Startup/scale-up, product security company | Under-invests in governance and board fluency |
| **Transformational** | Change programs, org design, culture | Post-breach turnaround, M&A integration | Burns political capital fast; needs runway |
| **Business-aligned** | Risk in dollars, enabling revenue | Mature enterprise, regulated growth | Can drift from technical reality of controls |
| **Compliance / regulatory** | Audit, frameworks, attestation | Heavily regulated (finance, health, gov) | "Compliant but insecure" trap |
| **vCISO / fractional** | Program bootstrapping, part-time | SMB/mid-market without a full-time role | Continuity and depth limits; scope carefully |

Average CISO tenure remains short relative to peer C-suite roles, and reporting lines are shifting toward the CEO/board as security becomes an enterprise risk rather than an IT sub-function — plan your mandate, budget, and authority conversation for the *front* of your tenure, not month 18.

---

## The First 90 Days

Adapt the classic transition arc (listen → diagnose → plan) to a security context. Resist the urge to ship controls in week one; the highest-leverage early asset is an accurate, shared picture of reality and a mandate to act on it.

| Phase | Days | Goal | Key deliverables |
|---|---|---|---|
| **Listen & assess** | 0–30 | Understand the business, the crown jewels, the team, and what's actually deployed | Stakeholder map; asset & data inventory review; current-state control assessment (pick a framework — CSF 2.0 / CIS v8.1); "what would hurt us most" list |
| **Diagnose & prioritize** | 30–60 | Turn findings into a risk-ranked gap list with owners and rough cost | Risk register (top 10–15); quick-wins list; maturity baseline vs. target; draft budget ask |
| **Plan & commit** | 60–90 | Get alignment and resources; publish a strategy the org has signed off on | Strategy-on-a-page; 12–18 month roadmap; operating model & org design; first board/exec briefing; metrics baseline |

**First-30-days questions to answer honestly:**

- What are the top 5 things that, if compromised, materially threaten the business? (crown jewels / "material" systems)
- Do we have a complete-enough asset and identity inventory to make risk statements at all?
- What is our current-state maturity against a recognized framework, measured not asserted?
- What incidents, audit findings, exceptions, and near-misses are open right now?
- Where is the money going today, and is any of it buying risk reduction we can measure?
- Who are my allies (GC, CIO, CFO, business-unit leaders), and where are the landmines?

**Early anti-patterns:** rolling out a shiny tool before you have an inventory; reorganizing the team before you understand it; making the first board appearance a fear pitch; committing to a maturity target you can't staff; declaring "we're insecure" without a funded plan to fix it.

**90-day exit artifacts:** a one-page strategy, a costed roadmap, a top-risks register with named owners, a metrics baseline, and a documented mandate (reporting line, budget authority, decision rights). If you can't produce these, you haven't finished onboarding.

---

## Organizational Design & Reporting Lines

### Where the CISO should report

There is no single correct answer; the right line depends on company size, sector, and what problem the org is solving. The trade-offs:

| Reports to | Pros | Cons / conflicts |
|---|---|---|
| **CEO** | Enterprise-risk framing; independence from IT delivery pressure; direct board access | CEO bandwidth; CISO must be genuinely business-fluent |
| **CIO** | Proximity to infrastructure and delivery; common at scale | Structural conflict — security funding competes with, and is judged by, the CIO it audits |
| **CFO** | Risk/insurance/quantification alignment; budget fluency | Security seen as cost control, not enablement |
| **General Counsel / CLO** | Privilege, regulatory, and disclosure alignment | Distance from engineering reality |
| **CRO / Chief Risk Officer** | Integrates with enterprise risk management (ERM) | Can over-index on paper risk vs. deployed defense |

The empirical picture in recent surveys is mixed and depends heavily on company size: large enterprises still frequently place the CISO under the CIO, while executive-search data shows a marked rise in CISOs reporting to the CEO as security is treated as a strategic, enterprise-wide function. Whatever the line, insist on a **direct, unfiltered path to the board or a board committee** — SEC Item 106 (below) makes the board's oversight of cyber risk a disclosed governance fact, and a CISO who only reaches the board through the executive being audited is a documented governance weakness. *(Reporting-line trends: [Heidrick & Struggles 2025 Global CISO Compensation Survey](https://www.heidrick.com/en/insights/cybersecurity/2025-global-chief-information-security-officer-compensation-survey), [CIO Dive](https://www.ciodive.com/news/ciso-reporting-structure/686032/).)*

### Functional operating model

A representative mid-to-large security organization (scale down/merge for smaller orgs; a single senior generalist may own several boxes):

```
CISO
 ├── Security Operations (SOC / detection & response / threat hunting)
 ├── Security Engineering & Architecture (controls, IAM eng, cloud security)
 ├── Application / Product Security (SDLC, AppSec, DevSecOps)
 ├── Governance, Risk & Compliance (policy, audit, TPRM, risk register)
 ├── Vulnerability & Threat Management (VM, threat intel, red/purple)
 └── Business Information Security Officers (BISOs — embedded in business units)
```

The **three-lines model** (IIA, 2020 update to the older "three lines of defense") keeps roles honest: first line = the business/IT owning and operating controls; second line = security/risk/compliance setting policy and challenging; third line = internal audit providing independent assurance. Keep the CISO in the second line and preserve internal audit's independence — a CISO who both builds and audits the same controls has no independent assurance.

### Build vs. buy the team

Outsource commodity, 24×7, or scarce-skill functions; keep strategy, risk ownership, and architecture in-house. Common split:

- **Keep in-house:** strategy, risk decisions, architecture, IR command, vendor governance, detection engineering direction.
- **Outsource (MSSP / MDR / co-managed SOC):** overnight monitoring, tier-1 triage, log management scale, specialized DFIR retainer, red-team exercises.
- **Never fully outsource:** accountability. You can delegate the work; you cannot delegate the risk ownership or the board answer.

---

## Budgeting & Headcount

### Benchmarks (use as sanity checks, not targets)

Budgets are set by risk and strategy, not by copying a ratio — but leaders are expected to know where they sit against peers.

| Benchmark | Typical range | Notes / source |
|---|---|---|
| Security spend as **% of IT budget** | ~**9–11%** overall; financial services **10–14%**, retail **4–6%** | Gartner 2025 CISO survey ≈ 9.8% of IT budget; IANS/Artico ≈ 10.9% in 2025 (down from 11.9% in 2024) |
| **Budget growth** YoY | ~**4%** in 2025 — slowest in five years (down from ~8% in 2024) | [IANS/Artico 2025 Security Budget Benchmark](https://www.iansresearch.com/resources/press-releases/detail/ians-research-and-artico-search-release-security-budget-benchmark-report) |
| **Security FTE per 100 employees** | ~**1.5** (<$50M orgs) down to ~**0.9** ($600M–$1B) | IANS/Artico 2025; ratio falls as orgs scale |
| Global infosec **end-user spend** | **$213B** in 2025, forecast to keep growing ~15% YoY | [Gartner, Jul 2025](https://www.gartner.com/en/newsroom/press-releases/2025-07-29-gartner-forecasts-worldwide-end-user-spending-on-information-security-to-total-213-billion-us-dollars-in-2025) |

A frequently cited internal allocation is roughly **40% software/platforms, 30% personnel, 15% hardware, 15% outsourced services** — treat the exact split as illustrative and verify against a current benchmark for your sector and size.

### Building the budget

- **Zero-based for new programs, incremental for mature ones.** A new CISO defending an inherited budget should be able to trace every dollar to a risk it reduces.
- **Categorize by outcome, not vendor.** Group spend under prevent / detect / respond / recover / govern (mirrors CSF 2.0 functions) so cuts and adds are legible to a board.
- **Separate run-rate from change.** "Keep the lights on" (licenses, staff, MSSP) vs. transformation projects; the board should see both.
- **Model unit economics.** Cost per endpoint, per identity, per app onboarded — makes scaling costs predictable and defends against "why did security get more expensive?"

### The business case (how to win the ask)

Frame every material request as risk reduction in the board's language, not features:

1. **Risk in dollars** — use FAIR / loss-exposure estimates (see [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md#s4-risk-quantification)), not adjective risk.
2. **The gap** — current-state vs. target maturity or a specific KRI breaching threshold.
3. **The options** — do-nothing (accept), this ask (mitigate), transfer (insurance), with cost and residual risk for each.
4. **The ROI/ROSI** — expected loss avoided vs. cost, with honest confidence bounds.
5. **The regulatory or contractual hook** — where a duty (a framework, a customer contract, a breach-notification regime) makes inaction a compliance finding.

**Cutting under pressure:** when budgets are flat or shrinking (the current climate), lead with rationalization — retire overlapping tools, renegotiate at renewal, consolidate platforms, automate tier-1 toil — before cutting risk-reducing controls. Document accepted risk explicitly when a cut raises exposure; an undocumented cut becomes *your* liability at the next incident.

---

## Security Strategy & Roadmap

### Strategy on a page

A security strategy that doesn't fit on one page won't survive contact with a board. Structure:

```
MISSION      Enable <business objective> by managing cyber risk to <appetite>.
CONTEXT      Top threats · crown jewels · regulatory drivers · current maturity
PRINCIPLES   e.g. risk-based · secure-by-default · assume-breach · least privilege
PILLARS      3–5 multi-year themes (e.g. Identity, Resilience, Detection, Product Security, Governance)
OUTCOMES     Target maturity + 5–7 KPIs/KRIs per pillar with 12/24/36-month targets
ROADMAP      Sequenced initiatives mapped to pillars, cost, and risk reduced
```

### Choosing the North Star framework

Pick one primary framework as the program's spine; map others to it rather than running several in parallel.

| Framework | Best as program spine when | Version / note |
|---|---|---|
| **NIST CSF 2.0** | You want a business-legible, outcome-based common language incl. governance | Released Feb 2024; adds the **GOVERN** function → 6 functions, 22 categories, 106 subcategories ([NIST](https://www.nist.gov/cyberframework)) |
| **CIS Critical Security Controls v8.1** | You want a prioritized, technical to-do list with maturity tiers | v8.1 released Jun 2024; 18 controls, 153 safeguards; **IG1 = 56 safeguards** (basic hygiene) |
| **ISO/IEC 27001:2022** | You need a certifiable ISMS for customers/regulators | Certification standard; Annex A restructured to 93 controls in 4 themes |
| **NIST RMF (SP 800-37) + 800-53** | US federal / high-assurance authorization boundaries | Control catalog + authorization process |
| **C2M2 / CMMC** | Energy/OT maturity, or US DoD contract requirement | C2M2 for OT maturity; CMMC for DIB contractors |

Use maturity **tiers** (CSF Tiers 1–4, or CIS Implementation Groups IG1–IG3) to express *where you are and where you're going* — boards understand "we are moving IG1 → IG2 in identity over 18 months" far better than a control count. See [FRAMEWORKS.md](FRAMEWORKS.md) for the full framework detail and crosswalks.

---

## Risk-Based Prioritization

Leadership is deciding what *not* to do. Every roadmap item and every finding should route through an explicit treatment decision rather than a first-in-first-out queue.

| Risk level (likelihood × impact, ideally in $) | Default treatment | Who decides |
|---|---|---|
| Critical / imminent (e.g., exploited KEV on internet-facing crown jewel) | **Mitigate now** — emergency change | CISO / IR lead |
| High | **Plan & fund** in roadmap with SLA | CISO + risk owner |
| Medium | **Mitigate or accept** with compensating controls | Risk owner + security |
| Low | **Accept & monitor** (documented) | Risk owner |
| Any level, transferable | **Transfer** (cyber insurance, contractual) | CISO + CFO/GC |

Anchor prioritization in three inputs, not one: **asset criticality** (crown jewels / material systems), **threat context** (what adversaries actually do to orgs like yours — see [THREAT_INFORMED_DEFENSE_REFERENCE.md](THREAT_INFORMED_DEFENSE_REFERENCE.md)), and **exploitability/exposure** (KEV, EPSS, internet-facing — see [VULNERABILITY_PRIORITIZATION_REFERENCE.md](VULNERABILITY_PRIORITIZATION_REFERENCE.md)). Quantify the top risks in dollars with FAIR so the register can be sorted by loss exposure and defended to a CFO. Every accepted risk gets an owner, an expiry, and a review date; an exception register with no expirations is a liability catalog.

---

## Board & Executive Reporting

### Why the board now cares (and must)

Cyber-risk oversight is a documented board duty, not a courtesy briefing:

- **SEC Regulation S-K Item 106** requires public companies to describe the **board's oversight** of cyber risk and **management's role** in assessing/managing it (annual 10-K), alongside the **Item 1.05 Form 8-K** material-incident disclosure. The SEC **dropped** the proposed requirement to name a board cyber-expert (proposed Item 407(j) was **not** adopted) — but the oversight-description duty stands. ([SEC final-rule fact sheet](https://www.sec.gov/files/33-11216-fact-sheet.pdf))
- **NACD / Internet Security Alliance** *Director's Handbook on Cyber-Risk Oversight* — the de-facto board playbook; the **5th edition was released April 2026** with six oversight principles and board tools, foreword by CISA. Boards increasingly measure themselves against it. ([NACD 2026 handbook](https://www.nacdonline.org/all-governance/governance-resources/governance-research/director-handbooks/2026-cyber-risk-oversight/))

### Cadence

| Audience | Frequency | Content |
|---|---|---|
| Board / audit or risk committee | Quarterly (+ ad hoc on material incidents) | Posture trend, top risks, program progress, regulatory exposure, incidents, budget |
| Executive / CEO staff | Monthly | KPIs/KRIs, initiative status, decisions/escalations needed |
| Operational leadership | Weekly | SOC/vuln/ops metrics, exceptions, resourcing |

### The board reporting pack

Boards want *decisions and trends*, not dashboards. A strong pack is 5–7 top indicators with trend arrows and peer benchmarks, plus a one-page narrative. Include:

- **Posture trend** vs. last quarter and vs. peers (maturity or a small KRI set).
- **Top risks** in business terms and dollars, with what you're doing and what you need.
- **Program progress** against the roadmap the board already approved.
- **Regulatory / disclosure exposure** — which clocks and duties apply now (link the [regulatory matrix](REGULATORY_LANDSCAPE_REFERENCE.md)).
- **Incidents & near-misses** since last meeting, and lessons applied.
- **The ask** — the one or two decisions you need from them.

**Metrics that matter to a board** (the shortlist; full catalog and formulas in [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md)): MTTD/MTTR trend, critical-vuln SLA compliance, MFA/EDR coverage on crown jewels, % of KEV remediated within SLA, phishing-report rate, third-party risk exposure, and a single dollarized loss-exposure figure. Avoid vanity metrics (raw alert counts, "blocked attacks") — they don't drive decisions.

**Do:** speak in risk and dollars; show trends and benchmarks; be honest about gaps and name the plan. **Don't:** fear-monger, drown them in tooling detail, present green-only dashboards, or surprise them with a risk you sat on.

---

## Third-Party & Vendor Governance

The leadership job here is owning **portfolio** third-party risk, not each questionnaire (the vendor lifecycle, risk tiering, SIG questionnaires, and continuous-monitoring mechanics live in [GRC_REFERENCE.md](GRC_REFERENCE.md#third-party-risk-management-tprm) and [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md)). At the program level:

- **Tier by inherent risk** (data access, criticality, integration depth) and assess proportionally — deep for tier-1, lightweight for tier-3.
- **Watch concentration and 4th-party risk** — a single cloud, identity, or payroll provider can be a systemic single point of failure across many "independent" vendors.
- **Contract for security up front** — right-to-audit, breach-notification clocks, SLAs, sub-processor disclosure, secure-development and data-handling terms. It is far cheaper than renegotiating after an incident.
- **Continuously monitor** critical vendors (ratings, KEV exposure, breach news) rather than trusting a point-in-time questionnaire.
- **Pre-map vendor incidents into your IR plan** — a vendor breach is your incident when it touches your data.

---

## Incident Escalation & Disclosure Duties

The leader owns two calls the practitioner cannot make: **when does this escalate**, and **does this trigger a disclosure duty**. (Full IR mechanics: [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md); every notification clock: [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md).)

### Escalation ladder

```
SEV-4/5  Analyst handles · logged                    → SOC
SEV-3    Team lead · defined playbook                → IR on-call
SEV-2    Coordinated response · management aware      → CISO + IR commander
SEV-1    Crisis · exec + legal + comms + board        → CEO, GC, CISO, board committee
```

Define severity by business impact (data classes, systems, regulatory exposure, operational disruption), not by technical noise, and pre-stage the SEV-1 bridge: who convenes, who has authority to disclose, who talks to regulators/press.

### The disclosure decision

Disclosure is a legal determination made *with* counsel and the business, informed by security facts — not a call security makes alone:

- **Materiality (SEC registrants):** an Item 1.05 Form 8-K is due **within 4 business days of determining an incident is material** — the clock runs from the **materiality determination**, not discovery, and the determination must be made "without unreasonable delay." Establish, in advance, **who** makes it (typically a cross-functional committee: security, legal, finance, disclosure counsel) and how.
- **Breach-notification clocks** (GDPR 72h, HIPAA ≤60 days, NIS2/DORA/CRA cascades, US state laws, sector rules) often run in parallel to different regulators — design your IR runbook to the **tightest clock** and fan out. See the [obligation & deadline matrix](REGULATORY_LANDSCAPE_REFERENCE.md#obligation--deadline-matrix).
- **Ransom payments** carry their own fast clocks (e.g., NYDFS 24h) and an **OFAC sanctions check** — never a decision security makes without counsel and the CFO.
- **Privilege:** engage counsel early so IR investigation and forensics can be conducted under privilege where appropriate; document decisions, but assume anything you write may be discoverable.

A pre-built **notification RACI** and a decision log that shows a reasonable, documented process are the difference between a defensible response and a governance finding.

---

## CISO Personal Liability & Accountability

Security leadership now carries individual legal exposure. Two cases reshaped the field and should shape how you document and disclose:

- **US v. Sullivan (former Uber CSO).** Convicted in 2022 of obstructing an FTC proceeding and misprision of a felony for concealing a 2016 breach (paying attackers under an NDA framed as a bug bounty while the FTC investigated). Sentenced May 2023 to **three years' probation, 200 hours community service, and a $50,000 fine**; the **Ninth Circuit upheld the conviction in March 2025**. Lesson: concealing a breach — especially during a regulatory investigation — is a personal criminal risk, not a corporate one. ([DOJ](https://www.justice.gov/usao-ndca/pr/former-chief-security-officer-uber-convicted-federal-charges-covering-data-breach), [9th Cir. 2025](https://law.justia.com/cases/federal/appellate-courts/ca9/23-927/23-927-2025-03-13.html))
- **SEC v. SolarWinds & CISO Timothy Brown.** The SEC charged the company and its CISO (Oct 2023) over alleged misstatements about its security posture. A judge **dismissed most claims in July 2024**, leaving one claim about the customer-facing "Security Statement"; the SEC then **dismissed the remaining claims with prejudice on 20 November 2025**, ending the case. It narrowed — but did not eliminate — the risk that public security statements become securities-fraud exposure. ([Harvard/AO Shearman analysis](https://corpgov.law.harvard.edu/2025/12/07/solarwinds-dismissed-what-the-secs-u-turn-signals-for-cyber-enforcement/), [Jones Day](https://www.jonesday.com/en/insights/2025/12/sec-dismisses-remaining-solarwinds-claims))

**Protect yourself and the program (defensive, not evasive):**

- **Don't overstate.** Ensure public security statements, questionnaires, and marketing claims are accurate and reviewed — say what you actually do.
- **Document the process, not just the outcome.** A reasonable, recorded risk-decision and disclosure process is your strongest defense; accepted risks need named business owners.
- **Escalate and disclose honestly.** The through-line of both cases is that concealment and misrepresentation, not the breach itself, created the personal exposure.
- **Get the protections in writing.** Negotiate **D&O insurance coverage** that names the CISO, an **indemnification agreement**, and clarity on who holds the disclosure decision — ideally before you accept the role.
- **Keep counsel and the board in the loop** on material risks; a CISO carrying a known material risk alone is the most exposed person in the building.

---

## Talent, Team & Culture

- **Structure to maturity, not aspiration.** A 5-person team can't run the org chart above; give a few senior generalists broad remits and outsource depth. Add specialization as the program and headcount grow.
- **Hire for trajectory and gaps.** Most CISOs report being understaffed (in 2025 surveys only a small minority felt adequately staffed) — buy scarce skills (cloud security, detection engineering, IR) via MDR/retainer while you grow them internally.
- **Fight burnout deliberately.** On-call rotation hygiene, alert-fatigue reduction (tune and automate — see [SOAR_AUTOMATION_REFERENCE.md](SOAR_AUTOMATION_REFERENCE.md)), and realistic scope. Attrition in a small security team is an operational risk.
- **Culture is a control.** Security awareness, phishing-resilience, and a blameless reporting culture measurably reduce risk; publish per-business-unit engagement to drive it. Make it easy to report and safe to be wrong fast.

---

## Annual Operating Rhythm

Run the program on a predictable calendar so nothing lands as a surprise:

| Cadence | Activities |
|---|---|
| **Weekly** | Ops/SOC metrics review; exception and vuln SLA check; leadership sync |
| **Monthly** | KPI/KRI pack; roadmap status; exec briefing; risk-register review |
| **Quarterly** | Board/committee report; strategy checkpoint; tabletop or purple-team exercise; TPRM portfolio review; policy review cycle |
| **Annually** | Strategy & roadmap refresh; budget cycle; risk-appetite review; framework/maturity re-assessment; audit(s); IR plan test; BC/DR test (see [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md)); policy re-approval |

---

## Common Failure Modes (a leadership checklist)

- [ ] Buying tools before you have an asset/identity inventory to point them at
- [ ] A framework binder with no measured maturity behind it ("compliant but insecure")
- [ ] Board decks full of green and vanity metrics; no dollarized risk, no ask
- [ ] Reporting only through the executive you audit; no independent path to the board
- [ ] Accepted risks with no owner, no dollar figure, and no expiry
- [ ] A budget you can't trace to risk reduction — first to be cut, hardest to defend
- [ ] No pre-agreed materiality/disclosure decision process before the incident happens
- [ ] Overstated public security claims that outrun the controls actually deployed
- [ ] A roadmap disconnected from the top threats to *this* business
- [ ] Staying the best individual contributor instead of building the team and the system

---

## Related Resources

- [GRC_REFERENCE.md](GRC_REFERENCE.md) — governance structures, policy hierarchy, risk register mechanics, TPRM lifecycle, audit, exceptions (the operational GRC layer this doc sits on top of)
- [GRC_COMPLIANCE_REFERENCE.md](GRC_COMPLIANCE_REFERENCE.md) — framework-by-framework compliance implementation
- [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md) — metric formulas, benchmarks, FAIR risk quantification, dashboard/board reporting design
- [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md) — the full breach/incident notification clock matrix (SEC, NIS2, DORA, CRA, GDPR, HIPAA, state)
- [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md) — IR lifecycle, severity, playbooks, crisis management
- [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md) — business continuity, disaster recovery, resilience testing
- [SUPPLY_CHAIN_SECURITY_REFERENCE.md](SUPPLY_CHAIN_SECURITY_REFERENCE.md) — third-party and software supply-chain risk detail
- [FRAMEWORKS.md](FRAMEWORKS.md) — NIST CSF 2.0, CIS Controls, ISO 27001, RMF, CMMC crosswalks
- [VULNERABILITY_PRIORITIZATION_REFERENCE.md](VULNERABILITY_PRIORITIZATION_REFERENCE.md) · [THREAT_INFORMED_DEFENSE_REFERENCE.md](THREAT_INFORMED_DEFENSE_REFERENCE.md) — inputs to risk-based prioritization
- [CAREER_PATHS.md](CAREER_PATHS.md) · [CERTIFICATIONS.md](CERTIFICATIONS.md) — the CISO career path and leadership credentials (CISSP, CCISO, CISM)
- [disciplines/governance-risk-compliance.md](disciplines/governance-risk-compliance.md) — GRC discipline overview

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
