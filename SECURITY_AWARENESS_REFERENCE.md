# Security Awareness & Human Risk Program Reference

> In one minute — This is the defender's playbook for building a security-awareness and human-risk program that actually changes behavior, not a compliance checkbox. It covers the operating model (the industry's shift from awareness training to *human risk management*), a maturity model to benchmark against, the behavior-change science underneath it, defensible phishing-simulation methodology (including ethics), how to measure human risk, reporting culture and positive reinforcement, executive/board awareness, and the regulatory clauses that mandate training. It is the *program* companion to [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md), which covers the *attacks* this program defends against — read that for phishing tooling, pretext craft, and Cialdini-as-weapon detail; read this for how to design, run, and measure the defense. Backs the [security-awareness discipline](disciplines/security-awareness.md).

| | |
|---|---|
| Read this when | standing up or overhauling a security-awareness/human-risk program, designing a defensible phishing-simulation cadence, choosing metrics that survive board scrutiny, mapping training obligations across NIST/ISO/PCI/HIPAA/NIS2/DORA, or briefing executives on why annual training alone does not move risk |
| Start at | [Program Maturity Model](#program-maturity-model), [Phishing Simulation: Methodology, Metrics & Ethics](#phishing-simulation-methodology-metrics--ethics), [Measuring Human Risk](#measuring-human-risk) |
| Pairs with | [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md), [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md), [INSIDER_THREAT_REFERENCE.md](INSIDER_THREAT_REFERENCE.md), [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md), [GRC_REFERENCE.md](GRC_REFERENCE.md) |

> Not legal advice. The training-mandate section below is a defender's operational map, not legal counsel. Statutory and contractual obligations turn on facts, definitions, and national transpositions that change; confirm your specific duties with qualified counsel. Version- and date-specific claims were verified as of 2026-09-29 and carry sources.

---

## From Awareness to Human Risk Management

The human layer is still the highest-leverage attack surface. Verizon's 2026 DBIR found the human element present in 62% of breaches (up slightly from ~60% in the 2025 edition), with Social Engineering the third most common breach pattern at ~16% of breaches — and attackers moving off email: ~41% of social-engineering breaches used non-email vectors (voice, SMS, social media, chat). ([Verizon 2026 DBIR](https://www.verizon.com/business/resources/reports/dbir/)) No technical control closes that gap on its own; the program that does is increasingly framed as human risk management (HRM), not "awareness training."

Gartner calls the modern operating model a Security Behavior and Culture Program (SBCP) and structures it with the PIPE framework — Practices, Influences, Platforms, Enablers — arguing that traditional security-awareness computer-based training (SACBT) achieves compliance but does not durably change behavior. Adoption is still early: Gartner reports only a small minority of organizations run a formal SBCP. ([Gartner / Hoxhunt summary](https://hoxhunt.com/blog/gartner-top-cybersecurity-trends-of-2024)) The market moved with the language: Forrester published its inaugural Wave: Human Risk Management Solutions, Q3 2024 (naming CybSafe and Living Security Leaders), and KnowBe4 rebranded around HRM in August 2025, launching its HRM+ platform after acquiring Egress. ([Forrester Wave RES181374](https://www.forrester.com/report/the-forrester-wave-tm-human-risk-management-solutions-q3-2024/RES181374), [KnowBe4 HRM+](https://www.knowbe4.com/press/knowbe4-tackles-human-risk-management-introducing-hrm-the-all-in-one-human-risk-management-platform))

The practical takeaway: completion rate is a proxy metric, not a success metric. A program that only proves everyone clicked through an annual module satisfies an auditor and moves no risk. Design for measurable behavior change (report rates, dwell-to-report, credential submission) instead.

---

## Program Maturity Model

Use a maturity model to set expectations with leadership and to sequence investment. The SANS Security Awareness & Culture Maturity Model is the vendor-neutral standard; its five stages progress from no program to a strategic, metrics-driven culture function. ([SANS Maturity Model](https://www.sans.org/for-organizations/workforce/security-awareness-training/ssa-ebook-maturity-model))

| Stage | Name | What it looks like | Risk posture |
|---|---|---|---|
| 1 | Non-Existent | No formal program; ad-hoc emails at best | Human risk unmanaged and unmeasured |
| 2 | Compliance-Focused | Annual training to satisfy a mandate; completion tracked | Auditor satisfied; behavior largely unchanged |
| 3 | Promoting Awareness & Behavior Change | Targeted topics, phishing simulation, just-in-time nudges; behavior measured | Measurable reductions in risky behavior |
| 4 | Long-Term Sustainment & Culture Change | Program embedded in workflows and values; reinforced across the year | Secure behavior becomes the norm |
| 5 | Metrics / Optimization & Resilience | Human-risk metrics drive decisions and board reporting; program tied to business outcomes | Culture is a measurable, managed control |

Set realistic clocks. The SANS 2025 report (2,700+ practitioners across 70+ countries) found that meaningfully influencing behavior takes 3-5 years of sustained effort and embedding culture takes 5-10 years — fund and message accordingly, and do not promise a maturity jump in a single budget cycle. ([SANS 2026 Security Awareness & Culture Report](https://www.sans.org/for-organizations/workforce/resources/security-awareness-report))

---

## Behavior Change Science

Programs fail when they treat training as information delivery. Ground design in evidence-based behavior models.

- Fogg Behavior Model: B = MAP (Behavior = Motivation × Ability × Prompt). A behavior happens only when motivation and ability are both sufficient *at the moment of a prompt*. Implications: make the secure action *easy* (one-tap MFA, a pre-deployed password manager, a one-click report button); deliver the prompt *at the moment of risk* (just-in-time), not once a year; celebrate the tiny behavior (reporting) to build the habit.
- Nudge theory (Thaler & Sunstein). Engineer the choice architecture so the secure option is the default or the path of least resistance: opt-out MFA, external-sender email banners, confirmation friction on high-value wire transfers, and social-proof messaging ("most of your colleagues reported this email").
- Cialdini's principles of influence: now seven. The six classic levers (reciprocity, commitment/consistency, social proof, authority, liking, scarcity) are the attacker's toolkit; Cialdini added a seventh, Unity (shared in-group identity), in his 2016 book *Pre-Suasion*. ([Cialdini's 7th principle](https://www.rogerdooley.com/ep-134-unity-robert-cialdinis-surprising-seventh-principle/)) Teach staff to recognize these as manipulation cues — see [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md#_1-psychology-of-social-engineering) for the offensive detail.
- Just-in-time (JIT) training. A micro-lesson delivered immediately after a risky action (clicking a simulated phish, downloading an unsafe file) lands while the lesson is relevant, producing far better retention than a temporally disconnected annual module. JIT is the single highest-yield content-delivery change most programs can make.

---

## Phishing Simulation: Methodology, Metrics & Ethics

A defensible simulation program follows a repeatable cycle. Tooling detail (Gophish setup, template variables, tracking pixels, AiTM) lives in [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md#_3-phishing-infrastructure-and-tooling); this is the *program* view.

```
1. Baseline      → run an unannounced campaign; capture click, credential-submission, and report rates
2. Target        → build role-relevant templates (finance→invoice/wire, execs→board themes, IT→helpdesk)
3. Execute       → randomized cohorts to prevent word-of-mouth warning; measure delivery/click/submit/report/time-to-report
4. Analyze       → segment by department, tenure, role, and prior performance; identify repeat clickers
5. Remediate     → automatic just-in-time micro-training for clickers; targeted content for high-risk groups
6. Trend         → month-over-month and quarter-over-quarter; benchmark; report a human-risk metric to leadership
```

Difficulty ladder — climb it deliberately; do not open with a spear-phish and then punish the org for failing.

| Level | Characteristics | Indicative click target |
|---|---|---|
| 1: Very Easy | Obvious red flags, generic sender | < 30% |
| 2: Easy | Brand impersonation, generic content | < 15% |
| 3: Medium | Plausible pretext, personalized sender | < 10% |
| 4: Hard | OSINT-driven spear phish | < 5% |
| 5: Very Hard | Whaling, multi-channel (email + voice/SMS) | Benchmark only, not scored punitively |

Ethics — non-negotiable, and increasingly a program-credibility issue:
- No blame. Never punish clickers. Punishment suppresses *reporting* (the behavior you most want) and drives risk underground. Manager involvement for genuine repeat offenders should be supportive coaching, not discipline.
- Avoid emotionally exploitative lures. Fake bonuses, falsely announced layoffs, bogus salary changes, or fabricated relief/benefits have repeatedly produced public backlash and eroded workforce trust when used as simulation bait. If a lure would feel like a betrayal to receive, do not send it.
- Simulate, don't harvest. Do not capture real credentials; a simulation landing page should recognize a submission and pivot straight to teaching. Scope, authorize, and document every campaign.
- Measure the report, not just the click. With adversary-in-the-middle (AiTM) phishing now defeating one-time-code MFA (see [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md#_27-adversary-in-the-middle-aitm-phishing)), the resilient behavior is *reporting fast*, not merely *not clicking*. Pair training with phishing-resistant MFA (FIDO2/passkeys) — see [IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md).

---

## Role-Based & Just-in-Time Training

General-workforce awareness is necessary but not sufficient. NIST distinguishes awareness (broad exposure for everyone) from role-based training (skills for people with specific responsibilities). Map content to access and risk.

| Audience | Focus content | Cadence |
|---|---|---|
| All staff | Phishing/vishing/smishing/quishing recognition, MFA, reporting, data handling, acceptable use | At hire + at least annually + continuous nudges |
| Finance / AP | Business email compromise (BEC), wire-transfer callback verification, vendor-bank-change fraud | At hire + quarterly + JIT |
| Executives & assistants | Whaling, deepfake voice/video, travel-based targeting, high-value approval controls | Quarterly + JIT |
| Developers | Secure coding, OWASP Top 10, secrets handling, dependency/supply-chain risk | Continuous; tie to SDLC — see [SECURE_CODING_REFERENCE.md](SECURE_CODING_REFERENCE.md) |
| Privileged / IT admins | Credential hygiene, tiered admin, social-engineering of the helpdesk (MFA-reset fraud) | At hire + quarterly |
| Board & management body | Cyber-risk oversight, disclosure duties, their own statutory training obligations | At least annually: see [Executive & Board Awareness](#executive--board-awareness) |

---

## Measuring Human Risk

Track behavioral metrics, not just completion. Move the program's headline from "% trained" to a composite Human Risk Score (HRS) you can trend and defend.

| Metric | Definition | Target direction |
|---|---|---|
| Click rate | % of simulation recipients who clicked | Down over time; well-run programs push toward single digits |
| Credential submission rate | % who entered credentials after clicking | Down toward zero (far more dangerous than click-only) |
| Report rate | % of simulated *and real* phish reported via the button | Up: the strongest positive signal; a high report rate beats a low click rate |
| Time-to-report | Median minutes from receipt to security notification | Down: faster reporting cuts attacker dwell time |
| Repeat-clicker rate | % clicking across multiple campaigns | Down; persistent repeaters get targeted intervention |
| Completion rate | % of assigned training done on time | Maintain above compliance threshold; *not* a primary effectiveness metric |

A composite score lets you prioritize intervention by risk rather than by completion:

```
HRS (per user or per group) = weighted blend of:
    simulation performance (click, submission, repeat behavior)
  + real-world behavior      (unsafe reporting, policy exceptions, risky app usage)
  + access/blast-radius       (privilege, data access, external exposure)
  − positive behavior         (reporting, fast time-to-report)
→ segment the riskiest cohorts and route them targeted, just-in-time content.
```

Benchmark externally (e.g., KnowBe4's Phishing by Industry Benchmarking for phish-prone percentage by sector and by program tenure) but treat vendor baselines as directional, not as your target. For the broader KPI/KRI, FAIR risk-quantification, and board-reporting patterns these feed, see [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md). Correlate simulation and reporting metrics with real incident volume — a program that reduces phishing-driven incidents is the outcome that matters.

---

## Reporting Culture & Positive Reinforcement

A healthy reporting culture is the single most impactful human defense: one employee who reports a live campaign can trigger containment for everyone. Engineer for it.

- One-click reporting. A native report button (Cofense Reporter, KnowBe4 Phish Alert, Microsoft's built-in Report Phishing, Google Workspace equivalents) that submits to the SOC or SOAR queue with near-zero friction.
- Close the loop. Acknowledge every report automatically; periodically tell the workforce what their reports caught ("colleagues reported 47 real phishing attempts this week — here's what they looked like"). Recognition and visible impact reinforce the behavior.
- Reward reporting, never punish clicking. Positive reinforcement (recognition, small rewards, leaderboards done carefully) sustains behavior; shaming destroys it.
- Feed the SOC. Route reports into triage and clustering so multiple reports of one campaign auto-escalate to an IR playbook.

```
# Illustrative: cluster inbound phishing reports to surface an active campaign (Splunk)
index=phishing_reports earliest=-1h
| stats count dc(reporter) as reporters by sender_domain, subject
| where reporters > 3
| sort - reporters
# → several independent reports of the same lure within an hour = likely live campaign → trigger IR
```

See [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md) for gateway/authentication controls (SPF/DKIM/DMARC) and [SOAR_AUTOMATION_REFERENCE.md](SOAR_AUTOMATION_REFERENCE.md) for automated report triage.

---

## Executive & Board Awareness

Executives are both high-value targets (whaling, deepfake voice/video authorizing wire transfers) and, increasingly, subjects of their *own* statutory training and oversight duties.

- US: SEC disclosure governance. Regulation S-K Item 106 requires registrants to describe board oversight and management's role in assessing/managing cybersecurity risk in the annual 10-K; Item 1.05 (Form 8-K) requires disclosure of a *material* cybersecurity incident within four business days of the materiality determination. Boards need enough literacy to exercise — and evidence — that oversight. See [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md#us-sec-cybersecurity-disclosure-item-105-of-form-8-k).
- EU: NIS2 management-body training is mandatory. Directive (EU) 2022/2555 Article 20 requires management bodies of essential and important entities to *undergo* cybersecurity training (and to ensure staff are offered it), and holds management accountable for risk-management measures; Article 21(2)(g) mandates basic cyber-hygiene practices and cybersecurity training for the whole workforce. ([NIS2 Art. 20/21](https://www.cm-alliance.com/cybersecurity-blog/does-nis2-mandate-board-training-articles-20-and-21-of-nis2-explained))
- Brief in business terms. Give the board 5-7 top-level human-risk indicators with trend arrows and benchmark comparison, plus a one-page narrative — not raw completion percentages. Translate to dollars/FAIR where you can (see [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md)).

---

## Regulatory & Framework Training Requirements

Most compliance regimes mandate awareness and role-based training; several now name phishing and social engineering explicitly. Use this as a control-mapping starting point, not as legal advice.

| Authority | Clause | What it requires | Status / note |
|---|---|---|---|
| NIST SP 800-50 Rev. 1 | whole document | Life-cycle model for building a Cybersecurity and Privacy Learning Program (CPLP); folds in the withdrawn SP 800-16 role-based guidance | Published Sept 2024 ([CSRC](https://csrc.nist.gov/pubs/sp/800/50/r1/final)) |
| NIST SP 800-53 Rev. 5 | AT family (AT-2 Literacy Training & Awareness, AT-3 Role-Based, AT-4 Records, AT-6 Feedback) | Baseline + role-based training and records; AT-2 enhancements cover practical exercises, insider threat, and social engineering | Current |
| NIST CSF 2.0 | PR.AT (Awareness and Training) | Personnel provided awareness/training so they perform security duties | Released Feb 2024 |
| ISO/IEC 27001:2022 | Clause 7.2/7.3; Annex A 6.3 | Competence and "information security awareness, education and training" | Current |
| PCI DSS v4.0.1 | 12.6 / 12.6.3 (+ 12.6.3.1, 12.6.3.2) | Formal awareness program; training at hire and annually; 12.6.3.1 must cover phishing and social engineering; 12.6.3.2 acceptable use | 12.6.3.1/.2 in force since 31 Mar 2025; v4.0.1 is the sole active version ([PCI/summary](https://www.securitymetrics.com/blog/security-awareness-training)) |
| HIPAA Security Rule | 45 CFR 164.308(a)(5) | Security awareness and training (security reminders, malware protection, log-in monitoring, password management) | In force; a Jan 6 2025 NPRM proposes strengthening the Rule — final rule pending (OMB agenda ~2027), so treat the specific new provisions as *to confirm* ([HIPAA Journal](https://www.hipaajournal.com/ocr-gives-update-on-proposed-hipaa-security-rule/)) |
| EU NIS2 | Art. 20 / 21(2)(g) | Management-body training (mandatory) + cyber-hygiene and cybersecurity training for all staff | In force via national transposition: see [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md#nis2-directive-eu-20222555) |
| EU DORA | Art. 13(6) | Financial entities must run ICT security-awareness programs and digital-operational-resilience training for staff and management | Applies since 17 Jan 2025 |
| GDPR | Art. 39(1)(b) | DPO responsibilities include staff awareness-raising and training | In force |
| CMMC 2.0 / NIST SP 800-171 | Awareness & Training family | Awareness and role-based training for contractors handling FCI/CUI | DoD contractual; see [FRAMEWORKS.md](FRAMEWORKS.md#cmmc-20) |
| CIS Controls v8.1 | Control 14 | Security Awareness and Skills Training program, including role-based and social-engineering content | Current |

---

## Tooling & Platforms

Open-source simulation & program tooling:

| Tool | Role | Note |
|---|---|---|
| [Gophish](https://github.com/gophish/gophish) | Phishing-simulation framework | De-facto open-source standard; campaign mgmt, templates, landing pages, tracking. Current stable v0.12.1 ([VERSION](https://github.com/gophish/gophish/blob/master/VERSION)) |
| [King Phisher](https://github.com/rsmusllp/king-phisher) | Phishing campaign toolkit | Campaign management with detailed tracking; note the project is archived — validate before production use |
| CISA / SANS OUCH! / ENISA kits | Free awareness content | Posters, newsletters, and campaign material: see the discipline page's [free-training list](disciplines/security-awareness.md#free-training) |

Commercial human-risk / awareness platforms (evaluate against your stack; the Forrester Wave: Human Risk Management Solutions, Q3 2024 named CybSafe and Living Security Leaders and Mimecast, SoSafe among Strong Performers — [RES181374](https://www.forrester.com/report/the-forrester-wave-tm-human-risk-management-solutions-q3-2024/RES181374)):

| Platform | Strength |
|---|---|
| KnowBe4 | Largest template library; HRM+ platform + Human Risk Score; rebranded around HRM Aug 2025 after acquiring Egress |
| Proofpoint | Awareness training correlated with real threat telemetry from the Proofpoint email gateway |
| Cofense | Reporting-first; PhishMe simulation + Cofense Reporter and crowd-sourced threat intel |
| Hoxhunt | Gamified, adaptive-difficulty simulation with strong engagement metrics |
| CybSafe / Living Security / SoSafe / CultureAI | Behavioral-science-led human-risk management, integrating real-world signals beyond simulation |
| Microsoft Attack Simulation Training | Native M365 integration for orgs standardizing on Defender for Office 365 |

---

## ATT&CK & Control Mapping

Awareness is a recognized mitigation — MITRE ATT&CK M1017 (User Training) — and directly reduces the initial-access and execution techniques adversaries rely on.

| Technique | ID | How the program mitigates it |
|---|---|---|
| Phishing | T1566 | Primary target; simulation + JIT training (M1017) lowers click rate and raises report rate across all sub-techniques |
| Phishing for Information | T1598 | Verify identity before sharing credentials/data via phone, email, or web form |
| User Execution | T1204 | Train against opening unexpected attachments/macros/files; JIT triggered on simulation failure |
| Impersonation | T1656 | BEC/executive-impersonation awareness; verbal callback verification for financial requests regardless of apparent authority |

Control frameworks: NIST 800-53 AT-2/AT-3/AT-4, CSF 2.0 PR.AT, ISO 27001 A.6.3. For deployed-vs-reference control semantics and coverage scoring, see [THREAT_INFORMED_DEFENSE_REFERENCE.md](THREAT_INFORMED_DEFENSE_REFERENCE.md).

---

## A 90-Day Program Starter Plan

```
Days 0–30  · Foundation
  □ Secure executive sponsorship and a named program owner
  □ Baseline: one unannounced, moderate-difficulty phishing simulation
  □ Deploy a one-click report button wired to the SOC/SOAR queue
  □ Publish a no-blame policy in writing (reward reporting, never punish clicking)

Days 31–60 · Behavior
  □ Turn on just-in-time micro-training for simulation clickers
  □ Stand up role-based tracks for finance/AP and executives (BEC + callback verification)
  □ Define the metric set (report rate + time-to-report as headline, not completion)
  □ Recruit security champions (~1 per 10–20 staff)

Days 61–90 · Measure & report
  □ Run the second simulation; trend click/report/time-to-report vs. baseline
  □ Build a one-page human-risk dashboard for leadership (5–7 indicators, trend arrows, benchmark)
  □ Map coverage to your binding mandate(s) (PCI 12.6.3 / HIPAA / NIS2 / DORA / ISO A.6.3)
  □ Set the recurring cadence and the 12-month maturity target
```

---

## Common Anti-Patterns

- Annual-only training. Once-a-year modules are temporally disconnected from risk; without reinforcement and JIT, behavior reverts.
- Completion as the KPI. "100% trained" proves attendance, not resilience. Lead with behavior.
- Blame and shame. Punishing clickers suppresses reporting — the exact opposite of the goal.
- Manipulative simulation lures. Fake bonuses/layoffs generate backlash and destroy trust; the credibility damage outlasts any teachable moment.
- Click-rate tunnel vision. With AiTM defeating OTP MFA, "did not click" is no longer sufficient — reward fast reporting and pair with phishing-resistant MFA.
- One-size-fits-all content. Finance, developers, admins, and executives face different threats and need different training.
- No feedback loop. If the workforce never hears what their reports caught, reporting decays.

---

## Related Resources

- [SOCIAL_ENGINEERING_REFERENCE.md](SOCIAL_ENGINEERING_REFERENCE.md): the attack side: phishing/vishing/smishing/quishing craft, Gophish tooling, pretexting, AiTM
- [EMAIL_SECURITY_REFERENCE.md](EMAIL_SECURITY_REFERENCE.md): SPF/DKIM/DMARC and gateway controls that back the human layer
- [INSIDER_THREAT_REFERENCE.md](INSIDER_THREAT_REFERENCE.md): the human-risk lens for authorized-access actors and negligent behavior
- [SECURITY_METRICS_REFERENCE.md](SECURITY_METRICS_REFERENCE.md): KPIs/KRIs, FAIR risk quantification, and board-report translation for human-risk metrics
- [GRC_REFERENCE.md](GRC_REFERENCE.md) / [FRAMEWORKS.md](FRAMEWORKS.md): control frameworks and the compliance calendar these training mandates sit in
- [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md): the statutory/breach-notification regimes behind the training clauses
- [disciplines/security-awareness.md](disciplines/security-awareness.md): the discipline learning path this reference backs

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
