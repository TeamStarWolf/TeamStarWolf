# Continuous Threat Exposure Management (CTEM) Reference

> **CTEM is a program, not a product.** Introduced by [Gartner](https://www.gartner.com/en/documents/4016760) in 2022, Continuous Threat Exposure Management is a five-stage operating loop that replaces periodic, scan-and-patch vulnerability management with a continuous cycle of **scoping, discovery, prioritization, validation, and mobilization** — driven by what an attacker could actually do to your business, not by raw CVE counts.

Gartner's headline prediction, from its public article [*How to Manage Cybersecurity Threats, Not Episodes*](https://www.gartner.com/en/articles/how-to-manage-cybersecurity-threats-not-episodes) (August 2023): organizations that prioritize security investments based on a continuous exposure management program are **three times less likely to suffer a breach** by 2026. The mechanism is simple — most vulnerabilities are never exploitable in a given environment, so effort spent on undifferentiated "critical" findings is effort not spent on the handful of exposures an adversary would really use. (The prediction exists in three public wordings, and no public retrospective has validated it — see [The breach-reduction prediction](#the-breach-reduction-prediction).)

This reference maps each CTEM stage to the concrete data, tooling, and references already in this library, so the loop can be run rather than admired.

**Related:** [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Vulnerability Prioritization (SSVC, KEV, EPSS)](VULNERABILITY_PRIORITIZATION_REFERENCE.md) · [Purple Team](PURPLE_TEAM_REFERENCE.md) · [ATT&CK Priority Gaps](scores/attack_priority_gaps.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md)

---

## Why CTEM exists

Classic vulnerability management fails for structural reasons, not effort reasons:

| Problem | Consequence |
|---|---|
| **Volume** | Tens of thousands of findings; CVSS marks a large share "High/Critical" with no environmental context |
| **Point-in-time** | Quarterly scans miss an attack surface that changes daily (cloud, SaaS, shadow IT, third parties) |
| **Asset-centric, not attacker-centric** | A finding on an isolated host is treated like one on an internet-facing SSO gateway |
| **Unvalidated** | "Exploitable in theory" is treated as "exploitable here", with no test of compensating controls |
| **No ownership hand-off** | Findings pile up in a scanner nobody outside security reads |

CTEM answers each: continuous scope tied to business impact, discovery beyond CVEs (identity, misconfiguration, exposure), prioritization by real exploitability, **validation that the attack path works**, and mobilization that gets fixes owned by the teams who can make them.

### Exposure ≠ vulnerability

An **exposure** is anything that creates a viable attack path: an unpatched CVE, yes — but also an over-permissioned identity, a public S3 bucket, a stale DNS record enabling subdomain takeover, an MFA gap, a leaked credential, an unmonitored SaaS integration, or a fraud-control weakness. CTEM covers all of it. The published telemetry backs the breadth — CVEs turn out to be a small slice of the real exposure mix (see [Stage 2 — Discovery](#stage-2-discovery)).

---

## The CTEM canon

CTEM entered the public record on **July 21, 2022**, with the Gartner research note [*Implement a Continuous Threat Exposure Management (CTEM) Program*](https://www.gartner.com/en/documents/4016760) by **Jeremy D'Hoinne, Pete Shoard, and Mitchell Schneider**. The note itself is paywalled; its title, date, and authorship are public on Gartner's document page and consistently cited across licensed vendor summaries (e.g. [SafeBreach](https://www.safebreach.com/blog/gartner-implement-a-ctem-program/)).

Paraphrasing the definition as it circulates in those public summaries: CTEM is a **set of processes and capabilities** — deliberately not a product category — for **continually and consistently evaluating how accessible, exposed, and exploitable an organization's digital and physical assets are**. Two design choices follow directly from that sentence:

- **"Continually and consistently"** rules out the annual pentest and the quarterly scan as sufficient. The loop below has a cadence, and the cadence *is* the program.
- **"Accessible, exposed, and exploitable"** rules out severity-only ranking. A finding matters when an adversary can reach it, when it is actually exposed in your environment, and when exploiting it achieves something.

Practitioner analyses ([SafeBreach](https://www.safebreach.com/blog/ctem-the-5-phases/)) also stress that the cycle is **iterative rather than strictly linear**: validation results re-rank priorities mid-cycle, and discovery surprises reopen scoping questions.

### The breach-reduction prediction

The famous "3x" claim exists in three public wordings. All express the same strategic planning assumption, which traces to the July 2022 research note:

| Public wording | Where Gartner said it | Date |
|---|---|---|
| **"three times less likely to suffer a breach"** by 2026, for organizations prioritizing investments via a *continuous exposure management* program | [*How to Manage Cybersecurity Threats, Not Episodes*](https://www.gartner.com/en/articles/how-to-manage-cybersecurity-threats-not-episodes) — public gartner.com article | Aug 2023 |
| **"two-thirds fewer breaches"** by 2026 | [*Top Cybersecurity Trends for 2023*](https://www.intelligentciso.com/2023/04/12/gartner-identifies-top-cybersecurity-trends-for-2023/) announcement — CTEM named a top trend for 2023 | Apr 12, 2023 |
| **"two-thirds reduction in breaches"** | [*Gartner Identifies the Top 10 Strategic Technology Trends for 2024*](https://www.gartner.com/en/newsroom/press-releases/2023-10-16-gartner-identifies-the-top-10-strategic-technology-trends-for-2024) press release — CTEM named a top-10 strategic technology trend | Oct 16, 2023 |

Three things practitioners routinely get wrong about this quote:

- **The date.** Vendors habitually cite the "3x" wording to 2022. The verbatim public wording is from the August 2023 article; the 2022 note is the origin of the underlying assumption but is paywalled.
- **The phrase.** The public article says "continuous **exposure management** program" — not "continuous **threat** exposure management". Gartner's own public wording is looser than the acronym.
- **The status.** It is a *strategic planning assumption* — a directional forecast, not a measurement. 2026 was the target year, and no public Gartner retrospective validating the number has appeared (a gap noted publicly by, e.g., [Vectra](https://www.vectra.ai/topics/ctem)).

---

## The five stages

```
        ┌──────────────────────────────────────────────────────────┐
        │                                                          │
        ▼                                                          │
   1. SCOPING  ──►  2. DISCOVERY  ──►  3. PRIORITIZATION           │
   what matters      what exists         what to fix first         │
                                              │                    │
                                              ▼                    │
                          5. MOBILIZATION ◄── 4. VALIDATION        │
                            get it fixed       does it really work?│
                                    │                              │
                                    └──────────────────────────────┘
                                         (continuous loop)
```

Stages 1–3 form the **diagnose** half of the loop (scoping, discovery, prioritization); stages 4–5 are the **action** half (validation, mobilization). This grouping originates in Gartner's research and is documented in public vendor analyses ([Team Cymru](https://www.team-cymru.com/ctem), [Babble whitepaper](https://www.babble.cloud/hubfs/CTEM-Whitepaper.pdf)). The loop repeats on a cadence — typically monthly or quarterly per scope, with continuous discovery underneath. Different parts of the loop naturally run at different speeds:

| Rhythm | What runs at it |
|---|---|
| **Continuous** | Discovery feeds (EASM, CAASM, scanner, identity posture); KEV/EPSS ingestion |
| **Per cycle** (monthly–quarterly per scope) | Prioritization refresh, validation of the top of the queue, mobilization and re-validation |
| **Per emergency** | KEV hit or active exploitation inside scope — jumps the cycle via the emergency path (see [SLAs by exposure class](#slas-by-exposure-class)) |
| **Annual** | Scope portfolio review: retire scopes that stayed clean, add the next business-critical one |

### Diagnose vs. action

The split matters for governance: **diagnose stages produce decisions; action stages produce risk reduction** — and each half needs a different kind of owner and a different kind of budget.

| Stage | Half | Owner profile | Primary tool categories |
|---|---|---|---|
| **1. Scoping** | Diagnose | CISO / program lead + business owners | Business input first; CAASM and EASM inform the boundary |
| **2. Discovery** | Diagnose | Security engineering / VM team | EASM, CAASM, DRPS, VM/SCA scanners, CSPM/CNAPP, ITDR/ISPM |
| **3. Prioritization** | Diagnose | VM / exposure team | EAP (which subsumed VPT/RBVM), threat intel, KEV/EPSS/SSVC |
| **4. Validation** | Action | Offensive security + SOC | AEV (BAS + automated pentesting), purple teaming |
| **5. Mobilization** | Action | IT / platform / app owners, brokered by security | ITSM ticketing, SOAR, GRC workflow |

A program that staffs only the diagnose half becomes a reporting machine; one that staffs only the action half validates and fixes the wrong things.

---

### Stage 1 — Scoping

**Question:** *Which slice of the attack surface are we managing this cycle, and why does the business care?*

Scoping is a business exercise, not a scanner configuration. Pick scopes that map to something a leader would lose sleep over — "customer payment flow", "Microsoft 365 tenant + identity", "internet-facing estate", "crown-jewel data stores", "third-party/supply chain".

**Where to start.** Public summaries of Gartner's guidance ([Splunk](https://www.splunk.com/en_us/blog/learn/continuous-threat-exposure-management-ctem.html)) recommend two pilot scopes for a first cycle, precisely because both are visible to attackers and poorly covered by legacy VM: the **external attack surface** and **SaaS security posture**. Both routinely surprise — in a financial-services case study cited by [Vectra](https://www.vectra.ai/topics/ctem), **30% of external assets were missing from the organization's CMDB**.

**Stage contract**

| | |
|---|---|
| **Inputs** | Business impact analysis, crown-jewel list, threat model, regulatory map, last cycle's results |
| **Outputs** | Written scope statement (in *and* out), named exec sponsor, asset-owner roster, cycle calendar |
| **Owner** | CISO or exposure-program lead, with business-unit sign-off |
| **Done when** | A leader outside security agrees: "this is what we protect this cycle, and this is why" |

**Do**
- Start with **one or two narrow, high-value scopes** — a first CTEM cycle that tries to cover everything produces nothing actionable.
- Define scope by **business outcome** (revenue, regulatory, safety, fraud loss), then enumerate the assets that support it.
- Include **non-traditional surface**: SaaS tenants, identity providers, CI/CD, developer laptops, third-party integrations, external brand/domain exposure.
- Write down what is explicitly **out of scope** this cycle.

**Don't**
- Scope by scanner coverage or by what's easy to see — inheriting scope from a legacy scanner config is the most common way shadow IT and SaaS stay invisible for another year.
- Treat "all assets" as a scope.

**In this library:** [Enterprise Infrastructure](ENTERPRISE_INFRASTRUCTURE.md) · [Security Architecture](SECURITY_ARCHITECTURE_REFERENCE.md) · [Threat Modeling](THREAT_MODELING_REFERENCE.md) (to identify what an attacker would target) · [GRC & Compliance](GRC_COMPLIANCE_REFERENCE.md) (regulatory scopes) · [SaaS Security](SAAS_SECURITY_REFERENCE.md)

---

### Stage 2 — Discovery

**Question:** *What is actually in that scope, and what exposures does it carry?*

Discovery finds assets **and** their exposures — vulnerabilities, misconfigurations, weak identity posture, exposed secrets, and unknown/shadow assets. Volume here is expected and is *not* a measure of success; a discovery process that surfaces 40,000 findings has not achieved anything until Stage 3.

**Discovery domains**

| Domain | What you're looking for | Tooling category |
|---|---|---|
| External surface | Internet-facing hosts, forgotten subdomains, exposed admin panels, certificates | **EASM** |
| Asset inventory | Full asset/software picture, coverage gaps between tools | **CAASM** |
| Vulnerabilities | CVEs on hosts, containers, images, dependencies | VM scanners, SCA |
| Cloud posture | Misconfigurations, public storage, over-permissioned roles | **CSPM / CNAPP** |
| Identity | Stale/over-privileged accounts, MFA gaps, standing privilege, token exposure | **ITDR / ISPM** |
| Code & pipeline | Secrets in repos, insecure IaC, build system exposure | SAST/IaC/secret scanning |
| Digital risk | Leaked credentials, brand abuse, data for sale | **DRPS** |
| Third party | Vendor exposure, SBOM/dependency risk | TPRM, SBOM tooling |

**What the data says about the exposure mix.** The only published at-scale numbers are vendor telemetry — label them as such — but they consistently point the same direction. XM Cyber's *State of Exposure Management 2024* (drawn from its attack-path platform across customer environments) reports that **identity and credential misconfigurations account for roughly 80% of security exposures**, that **CVE-based vulnerabilities are under 1% of total exposures** (and about 11% of the exposures affecting critical assets, per the report's [coverage in The Hacker News](https://thehackernews.com/2024/05/new-xm-cyber-research-80-of-exposures.html)), and that a typical organization carries on the order of **15,000 exposures** ([XM Cyber press release](https://xmcyber.com/press-release/xm-cyber-report-finds-80-of-security-exposures-are-fueled-by-misconfigurations/)). A discovery process that only fetches CVEs is measuring the small slice.

**Stage contract**

| | |
|---|---|
| **Inputs** | Scope statement; access to scanners, cloud APIs, identity providers, EASM/CAASM feeds |
| **Outputs** | Asset inventory with owners; exposure list spanning CVEs, misconfigurations, identity, and secrets; tool-coverage gap notes |
| **Owner** | Security engineering / vulnerability management team |
| **Done when** | You can say what exists in scope, what it exposes, and — just as important — what your tooling *cannot* see |

**Do**
- Reconcile discovery output against the CMDB and asset owners — the deltas (unknown assets, orphaned owners) are findings in their own right.
- Cover **identity posture and misconfigurations** with the same rigor as CVEs; the telemetry above says that's where most exposure lives.
- Record **tool blind spots** (unscannable segments, SaaS tenants without API access) as explicit residual-risk entries.

**Don't**
- Report discovery volume as progress — 40,000 findings is an input, not an outcome.
- Let each tool keep its own asset list; without deduplication into one inventory, Stage 3 ranks the same exposure five times.

**In this library:** [OSINT](OSINT_REFERENCE.md) (external discovery) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Kubernetes](KUBERNETES_SECURITY_REFERENCE.md) · [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) · [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) · [DevSecOps](DEVSECOPS_REFERENCE.md)

---

### Stage 3 — Prioritization

**Question:** *Of everything we found, what would an attacker actually use — and what would it cost us?*

This is where CTEM departs hardest from legacy VM. **Do not prioritize by CVSS base score alone.** Combine signals:

| Signal | What it tells you | Source |
|---|---|---|
| **CISA KEV** | It is *being exploited in the wild right now* — inclusion requires all three of: an assigned CVE ID, reliable evidence of active exploitation, and a clear remediation action | [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **EPSS** | Probability of exploitation in the next 30 days — v4 (March 2025), scored daily for every published CVE, free CSV/API | [FIRST EPSS](https://www.first.org/epss/) |
| **SSVC** | A *decision* (Track / Track\* / Attend / Act), not a score — a CMU SEI/CISA decision tree over exploitation status, automatability, technical impact, and mission/well-being, with a free CISA calculator | [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) |
| **CVSS (env-adjusted)** | Technical severity, adjusted for your environment — v4.0 (Nov 1, 2023) renamed Temporal to Threat metrics and is explicit that prioritization means CVSS-BTE, not the Base score alone | [FIRST CVSS v4](https://www.first.org/newsroom/releases/20231101) · [CVE Reference](CVE_REFERENCE.md) |
| **NIST LEV** | Probability the CVE has *already* been exploited, compounded from historical EPSS scores — proposed in NIST CSWP 41 (May 2025) to complement KEV and EPSS | [NIST CSWP 41](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities-a-proposed-metric/final) |
| **Asset criticality** | Business value, data sensitivity, blast radius | Your CMDB / scoping work |
| **Reachability** | Is the vulnerable code path/port actually reachable? | Runtime & network context |
| **Compensating controls** | Would WAF, EDR, segmentation, or MFA already stop it? | [Coverage data](data/) · [D3FEND](D3FEND_REFERENCE.md) |
| **Attack-path position** | Does it unlock lateral movement toward crown jewels? | [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) · [choke points](#attack-path-management-and-choke-points) |
| **Threat relevance** | Do actors targeting *our sector* use this technique? | [Threat Group Profiles](THREAT_GROUP_PROFILES.md) |

The first five rows are external feeds, and they are covered feed-by-feed — semantics, misuse patterns, and a combined precedence pipeline — in [Vulnerability Prioritization (SSVC, KEV, EPSS)](VULNERABILITY_PRIORITIZATION_REFERENCE.md); this section stays at the "which signal answers which question" level. The last four rows are the local context **no external feed can supply** — they are why prioritization is a stage, not a lookup.

**A practical ranking rule:** *KEV-listed **and** reachable **and** on a critical asset **and** no compensating control* → fix now. Everything else queues behind it. To turn that queue into deadlines, see [SLAs by exposure class](#slas-by-exposure-class).

> **Attack paths beat findings.** Ten medium findings that chain into domain admin outrank one isolated critical. Prioritize the **chain**, and break it at its cheapest link — see [Attack-path management and choke points](#attack-path-management-and-choke-points).

**Do**
- Treat KEV as a mandatory floor: CISA advises every sector to require immediate handling of KEV entries in its vulnerability management plan, combined with a framework like SSVC — KEV remediation actions are "apply vendor updates" or, for end-of-life products, removal.
- Use EPSS for what it is — a 30-day exploitation *probability* — and re-pull it daily; scores move as exploitation evidence lands.
- Record the *reason* each item ranked where it did; a priority you can't explain to an asset owner won't survive Stage 5.

**Don't**
- Rank on CVSS Base alone — FIRST's own v4.0 guidance is that prioritization uses the full CVSS-BTE (Base + Threat + Environmental) score.
- Read EPSS as severity, or a low EPSS as safety; it says nothing about impact, and targeted exploitation is exactly what a population-level model underweights.
- Rebuild the feed logic from scratch — the precedence pipeline (KEV, then EPSS, then context) is worked through in [Vulnerability Prioritization (SSVC, KEV, EPSS)](VULNERABILITY_PRIORITIZATION_REFERENCE.md).

**In this library:** [Vulnerability Prioritization (SSVC, KEV, EPSS)](VULNERABILITY_PRIORITIZATION_REFERENCE.md) (the deep dive) · [ATT&CK Priority Gap Analysis](scores/attack_priority_gaps.md) (most-used, least-covered techniques) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [CVE Reference](CVE_REFERENCE.md) · [Controls Mapping](CONTROLS_MAPPING.md) · [Coverage gaps](scores/coverage_gaps.md)

---

### Stage 4 — Validation

**Question:** *If an attacker tried this, would it actually work — and would we see it?*

Validation is the stage most programs skip, and the one that makes CTEM credible. It answers three things:

1. **Is the exposure genuinely exploitable** in this environment?
2. **How far does it get** — what's the real blast radius along the attack path?
3. **Would we detect and respond** to it?

**Techniques**

| Method | Use it for |
|---|---|
| **Breach & Attack Simulation (BAS)** | Continuous, safe, automated technique execution at scale |
| **Adversarial Exposure Validation (AEV)** | Gartner's 2024 consolidation category: BAS + automated pentesting/red teaming — see [Validation governance](#validation-governance) |
| **Atomic Red Team** | Per-technique tests mapped to ATT&CK — cheapest way to start |
| **Purple team exercises** | Validating detection *and* response with the SOC in the loop — [PTEF](https://github.com/scythe-io/purple-team-exercise-framework) gives a free methodology |
| **Penetration testing / red team** | Depth, creativity, and full attack-path proof |
| **Control testing** | Does the WAF/EDR/segmentation rule actually fire? |

Validation output feeds **back into prioritization** — an "exposure" that is provably blocked by a compensating control gets deprioritized; one that walks straight to a crown jewel gets escalated.

**Stage contract**

| | |
|---|---|
| **Inputs** | Prioritized exposure list; written rules of engagement; safe test scenarios mapped to ATT&CK |
| **Outputs** | Per-exposure verdict (proven / blocked-by-control / untestable) with evidence; detection and response outcomes; re-ranked priorities |
| **Owner** | Offensive security / purple team, with the SOC in the loop |
| **Done when** | Every top-priority exposure carries a verdict backed by a test artifact, not an assumption |

**In this library:** [Purple Team](PURPLE_TEAM_REFERENCE.md) · [Detection Strategies](detections/strategies/README.md) (does telemetry exist?) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Pentest Checklists](PENTEST_CHECKLISTS.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md)

---

### Stage 5 — Mobilization

**Question:** *How does this actually get fixed, by people who don't report to security?*

Gartner is explicit that mobilization **cannot be fully automated** — the bottleneck is organizational, not technical. Security rarely owns the systems that need changing; the work is making action frictionless for the owners.

**Risk responses.** [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final) (*Guide to Enterprise Patch Management Planning*, April 2022) grounds the decision vocabulary: every confirmed exposure gets exactly one of four responses, recorded with an owner and a date —

| Response | Meaning | Examples |
|---|---|---|
| **Mitigate** | Reduce or eliminate the exposure | Patch, upgrade, disable the feature, tighten the config, add a compensating control |
| **Accept** | A documented decision to live with it | Signed risk acceptance with expiry and review date |
| **Transfer** | Move the consequence elsewhere | Cyber insurance, outsourcing the exposed service |
| **Avoid** | Remove the exposed thing entirely | Decommission, migrate off the platform |

SP 800-40r4 also recommends organizing assets into **maintenance groups** — sets sharing a remediation route and cadence — with **planned/scheduled** remediation for routine work and a distinct **emergency** path, so a KEV hit doesn't ride the monthly patch train.

**Who owns what.** The handoff, not the fix, is where programs die: security owns the findings, IT owns the remediation, and nobody owns the transfer between them. Route by exposure class, in the *owner's* queue:

| Exposure class | Typical owner | Route |
|---|---|---|
| **OS / software CVEs** | IT ops / platform engineering | Patch pipeline, maintenance-group SLA |
| **Cloud misconfigurations** | Platform / DevOps team | IaC pull request; policy-as-code exception |
| **Identity exposures** | IAM team | Access review, conditional-access change |
| **SaaS tenant settings** | Application owner | Admin-console change ticket |
| **Third-party exposure** | Vendor owner / TPRM | Contractual remediation clause |
| **Custom-code flaws** | Product engineering | Backlog item with a security label |

**Do**
- Give each exposure a **named owner, a deadline, and a route** (ticket in *their* system, not a PDF).
- Translate findings into the owner's language: "this lets an attacker read customer PII", not "CVE-2024-XXXX, CVSS 9.8".
- Pre-agree **SLAs by risk tier** and exception/risk-acceptance paths with sign-off — see [SLAs by exposure class](#slas-by-exposure-class).
- Track **mean time to remediate (MTTR)** per tier and per owning team; report trend, not raw counts.
- Close the loop — re-validate that the fix actually removed the exposure.

**Don't**
- Dump scanner exports on engineering teams.
- Treat "ticket created" as "risk reduced".

**In this library:** [Security Metrics](SECURITY_METRICS_REFERENCE.md) (MTTD/MTTR, SLAs, exec reporting) · [GRC Reference](GRC_REFERENCE.md) (risk acceptance, governance) · [SOAR Automation](SOAR_AUTOMATION_REFERENCE.md) (routing and workflow)

---

## Attack-path management and choke points

> **Fix the intersection, not every road.** Attack-path analysis reframes remediation economics: most exposures lead nowhere, and a small set sits where many paths converge.

Three working definitions:

- **Attack path** — a chain of exposures an adversary can traverse from a foothold to a critical asset (a phished workstation → cached credential → over-privileged service account → domain admin → data store).
- **Choke point** — an asset or exposure where multiple attack paths converge; fixing it severs many paths at once.
- **Dead end** — an exposure with no onward path to anything critical; real, but safely deprioritized.

The published numbers — vendor research from XM Cyber's platform telemetry, part of it analyzed with the Cyentia Institute, not independent measurement — make the economics concrete:

| Finding | Number | Source |
|---|---|---|
| Exposures sitting on choke points | **~2%** | [XM Cyber, 2023](https://xmcyber.com/press-release/xm-cyber-research-finds-small-number-of-exposures-put-more-than-90-of-critical-assets-at-risk/) |
| Choke points exposing 10% or more of critical assets | **~20% of choke points** | [XM Cyber 2024 report, via The Hacker News](https://thehackernews.com/2024/05/new-xm-cyber-research-80-of-exposures.html) |
| Exposures that are dead ends — no path to critical assets | **~74%** (75% in the 2023 edition) | [XM Cyber 2024 report, via The Hacker News](https://thehackernews.com/2024/05/new-xm-cyber-research-80-of-exposures.html) |
| Average exploitable exposures per organization | **~11,000** | [Cyentia Institute](https://www.cyentia.com/value-of-choke-points/) |
| Remediation-scope reduction from fixing choke points instead of individual findings | **~99.6%** | [Cyentia Institute](https://www.cyentia.com/value-of-choke-points/) |

Running it in practice:

1. **Build the graph.** For Active Directory and Entra ID — where most convergence lives, per the same telemetry — [BloodHound Community Edition](https://specterops.io/bloodhound-community-edition/) (SpecterOps; free and open source since August 2023) maps identity attack paths.
2. **Rank choke points** by the number of paths crossing them times the criticality of what those paths reach.
3. **Break the cheapest link.** The right fix is often a group membership, a delegation, or an ACL — not the highest-CVSS patch on the path.
4. **Deprioritize dead ends explicitly.** A documented "not on any path, revisit next cycle" is a program output, not negligence.
5. **Re-run after every fix batch** — paths reroute around remediations.

**In this library:** [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) · [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) · [Identity Security](IDENTITY_SECURITY_REFERENCE.md) · [Priority Gap Analysis](scores/attack_priority_gaps.md)

---

## SLAs by exposure class

Fixed remediation windows per CVSS band ("criticals in 30 days") are the legacy pattern CTEM replaces. The strongest public reference model for the replacement is CISA's [**BOD 26-04**, *Prioritizing Security Updates Based on Risk*](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) (issued June 10, 2026, superseding BOD 22-01 and BOD 19-02):

- Fixed KEV due dates are replaced by a risk matrix over **four questions**: Is the asset **publicly exposed**? Is the vulnerability **on KEV**? Is exploitation **automatable**? Does it yield **total or partial control**?
- Answers map to **tiered timelines** — the worst combination (publicly exposed + KEV + automatable + total control) gets **3 days plus forensic triage**; other combinations land in 7-, 14-, 30-, and 60-day tiers, with the lowest-risk combinations deferred to the next system upgrade. (The directive's Table 1 has more combinations than these examples — read it in full before copying it.)
- The matrix is explicitly **informed by SSVC** decision points.

BOD 26-04 binds US federal civilian agencies only; for everyone else it is a free, defensible template for SLAs tied to exposure class rather than severity band.

**Do**
- Substitute your own reachability and exposure data for "publicly exposed".
- Give compensating-control credit **only after Stage 4 has validated that the control actually blocks the technique**.
- Pre-agree the tiers with asset owners *before* the first emergency, and publish the exception path next to the SLA.

**Don't**
- Copy the federal timelines without the federal asset context.
- Let "not on KEV" mean "not urgent" — KEV is a floor, not a ceiling.

Full treatment — BOD 26-04's decision variables, SSVC decision tables, and a worked example SLA policy — lives in [Vulnerability Prioritization (SSVC, KEV, EPSS)](VULNERABILITY_PRIORITIZATION_REFERENCE.md#bod-26-04-the-federal-mandate), including its [example SLA policy](VULNERABILITY_PRIORITIZATION_REFERENCE.md#an-example-sla-policy).

---

## Validation governance

Validation runs attacker techniques against production-adjacent — and sometimes production — systems. Without governance it gets neutered ("lab only, so it proves nothing") or causes the outage it was supposed to prevent.

**The category.** Gartner consolidated BAS and automated penetration testing/red teaming into **Adversarial Exposure Validation (AEV)** in the 2024 Hype Cycle for Security Operations, then published the first *Market Guide for Adversarial Exposure Validation* on **March 11, 2025** (Eric Ahlm, Dhivya Poole, Angela Zhao, Mitchell Schneider), defining AEV as technologies delivering "consistent, continuous and automated evidence of the feasibility of an attack" — Gartner's public wording, carried on its [Peer Insights AEV market page](https://www.gartner.com/reviews/market/adversarial-exposure-validation) and quoted in [vendor summaries](https://www.safebreach.com/adversarial-exposure-validation-a-comprehensive-guide/). A second edition followed on **March 24, 2026** (Poole, Schneider, Ahlm), keeping the category name. The attached public predictions: **by 2027, 40% of organizations** will have adopted formal exposure validation initiatives (2025 guide, per [Picus's announcement](https://rss.globenewswire.com/news-release/2025/04/01/3052931/0/en/Picus-Security-Announces-Recognition-in-Gartner-Market-Guide-for-Adversarial-Exposure-Validation.html)); **by 2029, 60%** will have a structured exposure validation practice as part of CTEM (2026 guide, per [vendor releases](https://www.globenewswire.com/news-release/2026/04/10/3271747/0/en/hadrian-named-a-representative-vendor-in-the-gartner-market-guide-for-adversarial-exposure-validation.html)).

**Rules that keep validation safe and useful**

| Rule | Practice |
|---|---|
| **Written rules of engagement** | Scope (systems, techniques, time windows), abort criteria, and a named approver — agreed before any production test |
| **Production-safe scenarios** | Benign payloads and simulations with cleanup steps; a kill switch; change-freeze awareness. Test the *technique*, never the damage |
| **Blast-radius laddering** | Lab → staging → production read-only → production, with explicit promotion criteria between rungs |
| **Evidence handling** | Attack-path proof contains credentials, tokens, PII, and screenshots — classify it, set retention, redact before it lands in tickets |
| **SOC notification policy** | Decide per exercise: announced (measures the response process) vs. unannounced (measures detection) — never permanently unannounced |
| **Detection feedback** | Every validated technique that went undetected becomes a detection-engineering backlog item, not just a remediation ticket |

**Free methodology and tracking.** [SCYTHE's Purple Team Exercise Framework (PTEF)](https://github.com/scythe-io/purple-team-exercise-framework) is a free, MIT-licensed methodology for CTI-driven red/blue collaborative exercises; v4 adds a detection-engineering lifecycle, a purple-team maturity model, graded 0–5 scoring, and exercise templates, and requires no paid tooling or C2 framework. [VECTR](https://sra.io/purple-teams/) (Security Risk Advisors; free community edition) plans and tracks red/purple test cases against blue-team detection and prevention outcomes, mapped to ATT&CK. Both slot directly into this stage — see [Purple Team](PURPLE_TEAM_REFERENCE.md) for full workflows.

---

## Supporting technology categories

CTEM is tool-agnostic, but these categories map onto the stages. Treat them as capabilities to acquire (possibly from one platform), not a shopping list.

| Acronym | Full name | Primary stage |
|---|---|---|
| **EASM** | External Attack Surface Management | Discovery |
| **CAASM** | Cyber Asset Attack Surface Management | Discovery |
| **DRPS** | Digital Risk Protection Services | Discovery |
| **CSPM / CNAPP** | Cloud Security Posture Management / Cloud-Native App Protection | Discovery |
| **ITDR / ISPM** | Identity Threat Detection & Response / Identity Security Posture Mgmt | Discovery |
| **VPT** | Vulnerability Prioritization Technology | Prioritization |
| **EAP** | Exposure Assessment Platforms | Discovery + Prioritization |
| **BAS** | Breach & Attack Simulation | Validation |
| **AEV** | Adversarial Exposure Validation (BAS + autonomous pentest) | Validation |

All of the bolded acronyms except CSPM/CNAPP and ITDR/ISPM are Gartner-defined exposure-management categories; brief attributed definitions:

- **EASM** — defined in Gartner's March 2021 report *Emerging Technologies: Critical Insights for External Attack Surface Management* as the processes, technology, and services that discover internet-facing enterprise assets and systems that may present vulnerabilities (definition quoted publicly by [Threatpost](https://threatpost.com/external-attack-surface-management/167732/); the report's title and March 19, 2021 date are on the public record via [CyCognito's announcement](https://www.globenewswire.com/news-release/2021/06/02/2240504/0/en/External-Attack-Surface-Management-Recognized-as-An-Emerging-Technology-by-Gartner-CyCognito-Among-List-of-Vendors-Offering-this-Technology.html)).
- **CAASM** — debuted in 2021 in the Hype Cycles for Network Security and for Security Operations: API-driven aggregation across the tools you already own, to close persistent asset-visibility and vulnerability-coverage gaps ([Business Wire / Sevco](https://www.businesswire.com/news/home/20210728005787/en/Sevco-Security-Named-Sample-Vendor-for-Cybersecurity-Asset-Attack-Surface-Management-CAASM-in-Gartner%C2%AE-Hype-Cycle%E2%84%A2-for-Network-Security-2021-and-Hype-Cycle%E2%84%A2-for-Security-Operations-2021)).
- **DRPS** — technology plus services protecting critical digital assets, with visibility into the surface, social, deep, and dark web to identify threats and contextualize actors (2021 Hype Cycle profile, per [FireCompass's licensed reprint](https://firecompass.com/gartner-hype-cycle-for-security-operations-2021/)).
- **VPT** — the pre-2024 risk-based prioritization category, tracked in the threat-facing/SecOps Hype Cycles from the late 2010s; retired in 2024, subsumed into EAP.
- **BAS** — automated, safe execution of attack techniques to test controls; the earliest ancestor of the validation category (first Hype Cycle appearance 2017); consolidated into AEV in 2024.
- **EAP** — platforms that continuously identify and prioritize exposures — vulnerabilities *and* misconfigurations — across asset classes, contextualizing beyond CVSS with threat intelligence and asset criticality (2024 Hype Cycle, per [Rapid7's summary](https://www.rapid7.com/blog/post/2024/09/13/the-growing-importance-of-exposure-management-our-key-insights-from-gartner-r-hype-cycle-for-security-operations-2024/)).
- **AEV** — attacker's-view proof of exploitability; see [Validation governance](#validation-governance) for the definition and Market Guide history.

The pre-CTEM framing of how the discovery triad relates is also public: Gartner's March 2022 *Top Security and Risk Management Trends* made **attack surface expansion** trend #1 and positioned DRPS, EASM, and CAASM together as the technologies that help CISOs visualize internal and external business systems and automate the discovery of coverage gaps ([trade coverage](https://campustechnology.com/articles/2022/03/08/gartner-7-security-and-risk-management-trends-for-2022.aspx)).

### Category timeline

| Date | Event | Public record |
|---|---|---|
| **Jul 2017** | **BAS** debuts in the Hype Cycle for Threat-Facing Technologies — its first Hype Cycle appearance, "positioned as a technology on the rise" | [Cymulate press release](https://cymulate.com/press-releases/cymulate-listed-gartners-hype-cycle-for-threat-facing-technologies/) · [SecurityWeek](https://www.securityweek.com/fact-vs-fiction-truth-about-breach-and-attack-simulation-tools/) |
| **~2020** | **DRPS** tracked as a Hype Cycle profile (debut year approximate; the 2021 profile is the verifiable anchor); **VPT** likewise tracked by this period | [FireCompass reprint](https://firecompass.com/gartner-hype-cycle-for-security-operations-2021/) |
| **Mar 2021** | **EASM** defined in *Emerging Technologies: Critical Insights for External Attack Surface Management* | [Threatpost](https://threatpost.com/external-attack-surface-management/167732/) (definition) · [CyCognito press release](https://www.globenewswire.com/news-release/2021/06/02/2240504/0/en/External-Attack-Surface-Management-Recognized-as-An-Emerging-Technology-by-Gartner-CyCognito-Among-List-of-Vendors-Offering-this-Technology.html) (report title and date) |
| **Jul 2021** | **CAASM** debuts in the Hype Cycles for Network Security and Security Operations, 2021 | [Business Wire](https://www.businesswire.com/news/home/20210728005787/en/Sevco-Security-Named-Sample-Vendor-for-Cybersecurity-Asset-Attack-Surface-Management-CAASM-in-Gartner%C2%AE-Hype-Cycle%E2%84%A2-for-Network-Security-2021-and-Hype-Cycle%E2%84%A2-for-Security-Operations-2021) |
| **Mar 2022** | "Attack surface expansion" named Gartner's #1 security trend; DRPS + EASM + CAASM framed together | [Trade coverage](https://campustechnology.com/articles/2022/03/08/gartner-7-security-and-risk-management-trends-for-2022.aspx) |
| **Jul 21, 2022** | **CTEM** introduced: *Implement a Continuous Threat Exposure Management (CTEM) Program* (D'Hoinne, Shoard, Schneider) | [Gartner document page](https://www.gartner.com/en/documents/4016760) (note itself paywalled) |
| **Apr–Oct 2023** | CTEM named a top cybersecurity trend for 2023 and a top-10 strategic technology trend for 2024; the breach-reduction prediction published in three wordings | [Gartner press release](https://www.gartner.com/en/newsroom/press-releases/2023-10-16-gartner-identifies-the-top-10-strategic-technology-trends-for-2024) |
| **2024** | Hype Cycle for Security Operations, 2024 introduces **EAP** and **AEV**; retires VA and VPT as standalone profiles (subsumed into EAP); consolidates BAS + automated pentesting/red teaming into AEV. Positions: CAASM at the Peak of Inflated Expectations; EASM and DRPS in the Trough of Disillusionment | [Rapid7 summary](https://www.rapid7.com/blog/post/2024/09/13/the-growing-importance-of-exposure-management-our-key-insights-from-gartner-r-hype-cycle-for-security-operations-2024/) · [CISO Platform breakdown](https://www.cisoplatform.com/profiles/blogs/Insights-gartner-hype-cycle-2024-adversarial-exposure-validation) |
| **Mar 11, 2025** | First *Market Guide for Adversarial Exposure Validation* (Ahlm, Poole, Zhao, Schneider) | [Picus press release](https://rss.globenewswire.com/news-release/2025/04/01/3052931/0/en/Picus-Security-Announces-Recognition-in-Gartner-Market-Guide-for-Adversarial-Exposure-Validation.html) |
| **Mid-2025** | Hype Cycle for Security Operations, 2025 published; EAP and CAASM remain tracked profiles; detailed positions paywalled | [Gartner document page](https://www.gartner.com/en/documents/6625402) |
| **Nov 10, 2025** | First *Magic Quadrant for Exposure Assessment Platforms* (Schneider, Poole, Nunez), evaluating ~20 vendors — EAP graduates from Hype Cycle profile to formal market. Tenable, Rapid7, and Qualys announced Leader placements | [Tenable](https://www.tenable.com/press-releases/tenable-named-a-leader-in-the-2025-gartner-magic-quadrant-for-exposure-assessment) · [Rapid7](https://www.rapid7.com/about/press-releases/rapid7-recognized-as-a-leader-in-the-2025-gartner-magic-quadrant-for-exposure-assessment-platforms/) |
| **Mar 24, 2026** | Second *Market Guide for Adversarial Exposure Validation* (Poole, Schneider, Ahlm); category name unchanged | [Hadrian press release](https://www.globenewswire.com/news-release/2026/04/10/3271747/0/en/hadrian-named-a-representative-vendor-in-the-gartner-market-guide-for-adversarial-exposure-validation.html) |

Hype Cycle dot positions are paywalled; the 2024 positions above come from Gartner-licensed vendor summaries. Claims circulating about 2025/2026 positions (including "BAS marked obsolete") were not verifiable from licensed public sources and are omitted here.

### EAP and AEV

The 2024 consolidation left two complementary categories under the exposure-management umbrella — one for each half of the loop (framing per [The Hacker News](https://thehackernews.com/2024/08/ctem-in-spotlight-how-gartners-new.html), Aug 2024):

| | **EAP** (assessment) | **AEV** (validation) |
|---|---|---|
| **Question answered** | What do we have, and what should worry us most? | Which of those worries is *provably* exploitable here? |
| **Absorbed** | Vulnerability assessment (VA) + vulnerability prioritization (VPT/RBVM) | BAS + automated pentesting + automated red teaming |
| **How it works** | Continuous identification and prioritization of vulnerabilities *and* misconfigurations, contextualized beyond CVSS with threat intel and asset criticality | Safe execution of attack scenarios to prove feasibility, validate control efficacy, and surface attack paths to critical assets |
| **CTEM stages** | Discovery + Prioritization | Validation |
| **Market milestone** | First Magic Quadrant, Nov 10, 2025 | Market Guides, Mar 2025 and Mar 2026 |

They feed each other inside one cycle: the EAP hands the AEV a ranked hypothesis list; the AEV hands back proven / blocked-by-control verdicts that re-train the ranking. A program with only an EAP prioritizes theory; one with only an AEV proves things nobody prioritized.

---

## Measuring maturity

The first vendor-neutral yardstick arrived in 2025: the **SANS CTEM Maturity Model (CTEMMM)**, published July 22, 2025 (author Jonathan Risto, tied to SANS course LDR516). It organizes program capabilities across the five CTEM lifecycle stages, rates each capability domain on **five maturity levels from ad hoc to optimized**, and groups domains as **Foundational, Enhanced, or Strategic**; it ships with a Companion Guide and a Use Case and Examples document ([SANS announcement](https://www.sans.org/blog/introducing-the-ctem-maturity-model-a-blueprint-for-exposure-driven-risk-reduction)).

Vendor-published maturity models predate and accompany it — [Evolve Security's CTEM maturity model](https://www.evolvesecurity.com/blog-posts/the-ctem-chronicles-industrys-first-ctem-maturity-model) (levels beginning at "L1 Compliance Driven") and AttackIQ's CTEM maturity playbook (2026) among them. Useful as checklists; attribute them to their publishers and expect them to emphasize their publisher's stage.

Whatever model you adopt, maturity claims should reduce to the same observable facts: scopes covered per cycle, the share of priorities that carry a validation verdict, MTTR against SLA, and whether the loop has actually run more than once — which is what the [metrics below](#metrics-that-show-ctem-is-working) measure.

---

## Metrics that show CTEM is working

Avoid vanity metrics (total findings, scan counts). Track movement:

| Metric | Why it matters |
|---|---|
| **% of scope with validated exposure data** | Are we measuring reality or theory? |
| **MTTR for KEV/validated-exploitable exposures** | Speed where it counts |
| **Exposure dwell time** (discovery → remediation) | The window an attacker has |
| **Attack paths to crown jewels — open vs. closed** | The most business-legible metric available |
| **Choke-point closure rate** | Highest-leverage remediation, done or not |
| **Validation coverage** (% of priority techniques tested) | Confidence that controls actually work |
| **Detection coverage on validated paths** | If we can't block it, can we see it? |
| **Recurrence rate** | Are fixes durable or regressing? |
| **Exception volume & age** | Accumulating accepted risk |

**The quarterly executive view** is four of these, trended: open attack paths to crown jewels (down and to the right means the program works), validated-exposure MTTR vs. SLA by owning team, validation coverage of the priority technique list, and accepted-risk exceptions past their review date.

These numbers increasingly feed the SOC, not just the deck: Gartner's public prediction from the March 28, 2023 Security & Risk Management Summit in Sydney (analysts Richard Addiscott and Lisa Neubauer) was that **through 2026, more than 60% of threat detection, investigation and response (TDIR) capabilities will leverage exposure management data** to validate and prioritize detected threats, up from less than 5% ([summit coverage](https://idm.net.au/article/0014258-gartner-unveils-top-eight-cybersecurity-predictions-2023-2024)).

See [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md) for formulas and reporting patterns.

---

## Documented failure modes

Five patterns recur across practitioner post-mortems (paraphrased from public write-ups, e.g. [HackerOne's CTEM guide](https://www.hackerone.com/blog/complete-guide-to-ctem), [SL Cyber](https://slcyber.io/blog/what-are-the-four-ways-ctem-fails-without-asm/), and [Vectra](https://www.vectra.ai/topics/ctem)):

| Failure mode | What it looks like | Antidote |
|---|---|---|
| **Scanner-inherited scope** | The first cycle's scope is whatever the legacy scanner already covered; shadow IT and SaaS stay invisible | Scope from business impact (Stage 1); run an EASM/CAASM gap check against the CMDB |
| **Finding generation without remediation** | The program is measured by findings produced; nothing gets fixed. A CTEM program that cannot get findings remediated is a finding-generation program | Mobilization owns outcomes; report MTTR and closure, never raw counts |
| **One cycle, then victory** | The loop runs once, produces a big report, and stops | A published cycle calendar; continuous discovery underneath; the *second* cycle is the program's real birthday |
| **Unfunded validation** | Validation is owned on paper with no budget or time — and quietly collapses into a quarterly pentest with a new name | Fund AEV/purple time explicitly; start free with Atomic Red Team + [PTEF](https://github.com/scythe-io/purple-team-exercise-framework) |
| **Unowned handoff** | Security owns findings, IT owns remediation, nobody owns the transfer | Named owner + route per exposure class (Stage 5); the handoff is a deliverable, not a hope |

---

## A 90-day starting plan

| Phase | Weeks | Do this |
|---|---|---|
| **Pilot scope** | 1–2 | Pick one high-value scope (e.g. internet-facing estate or identity tenant). Name an exec sponsor and asset owners. |
| **Discover** | 3–5 | Inventory assets + exposures across that scope. Accept messy data; note tool coverage gaps. |
| **Prioritize** | 6–7 | Rank by KEV + EPSS + reachability + asset criticality + compensating controls. Produce a **top-20**, not a top-2000. |
| **Validate** | 8–10 | Test the top exposures with Atomic Red Team/BAS; confirm exploitability *and* detection. Re-rank on results. |
| **Mobilize** | 11–12 | Route to owners with SLAs; fix; re-validate. Report MTTR + closed attack paths to the sponsor. |
| **Iterate** | 13+ | Expand scope. Keep the cadence. |

> **Failure modes to avoid:** boiling the ocean in Stage 1; declaring victory at Stage 2 ("we found 40k issues!"); prioritizing on CVSS alone; skipping Stage 4 entirely; and treating Stage 5 as security's job alone. Each is expanded, with antidotes, in [Documented failure modes](#documented-failure-modes).

**After the first cycle**

- **Cycle 2 (the real test):** same scope, same metrics — the deltas (MTTR trend, recurrence, paths re-opened) are the program's first honest report.
- **Add the second scope** only once the first runs on calendar without heroics; SaaS posture pairs well with an external-surface pilot because the owners differ.
- **Formalize the SLA matrix** ([SLAs by exposure class](#slas-by-exposure-class)) once two cycles of MTTR data show which tiers are realistic.
- **Baseline against a maturity model** ([Measuring maturity](#measuring-maturity)) at the six-month mark, not day one — a maturity self-assessment before the loop has run twice measures ambition, not capability.

---

## Free and open tooling by stage

The loop can be run end-to-end without a procurement cycle. BloodHound CE, Infection Monkey, PTEF, VECTR, the CISA SSVC calculator, and the KEV/EPSS feeds were re-verified for this revision (September 2026); the rest are long-established open projects — confirm license and maintenance status before standardizing on one.

| Stage | Tool | What it is |
|---|---|---|
| **Discovery** | [OWASP Amass](https://github.com/owasp-amass/amass) | External asset and subdomain enumeration (EASM-adjacent) |
| | [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) | Template-driven vulnerability and misconfiguration scanning |
| | [Greenbone Community Edition](https://www.greenbone.net/en/community-edition/) | Network vulnerability scanning (OpenVAS lineage) |
| | [Prowler](https://github.com/prowler-cloud/prowler) | Cloud posture assessment (AWS, Azure, GCP, Kubernetes) |
| | [BloodHound CE](https://specterops.io/bloodhound-community-edition/) | AD / Entra ID attack-path mapping (free and open source since Aug 2023) |
| **Prioritization** | [CISA KEV feed](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited catalog, free JSON/CSV |
| | [FIRST EPSS](https://www.first.org/epss/) | Daily exploitation-probability scores for every CVE, free CSV/API |
| | [CISA SSVC calculator](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc) | Decision-tree walkthrough with PDF/JSON export |
| | [NIST LEV (CSWP 41)](https://csrc.nist.gov/pubs/cswp/41/likely-exploited-vulnerabilities-a-proposed-metric/final) | A published metric, not a tool — computable from free EPSS history |
| **Validation** | [MITRE Caldera](https://caldera.mitre.org/) | Automated adversary emulation platform |
| | [Atomic Red Team](https://atomicredteam.io/) | Per-technique, ATT&CK-mapped tests (Red Canary) |
| | [Infection Monkey](https://github.com/guardicore/monkey) | Open-source adversary emulation / BAS (Guardicore/Akamai) |
| | [PTEF](https://github.com/scythe-io/purple-team-exercise-framework) | Purple-team exercise methodology, MIT-licensed (SCYTHE) |
| | [VECTR](https://sra.io/purple-teams/) | Red/purple outcome tracking vs. blue detections, free community edition |
| **Mobilization** | [OWASP DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | Finding aggregation, deduplication, and remediation workflow |

See the [Open Source Toolkit](OPEN_SOURCE_TOOLKIT.md) for the library-wide catalog.

---

## CTEM, ATT&CK, and fraud together

This library's data lets you run the loop with real inputs:

| CTEM stage | Powered by |
|---|---|
| Scoping | [Enterprise Infrastructure](ENTERPRISE_INFRASTRUCTURE.md), [Threat Modeling](THREAT_MODELING_REFERENCE.md) |
| Discovery | [OSINT](OSINT_REFERENCE.md), [Vuln Mgmt](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Cloud](CLOUD_SECURITY_REFERENCE.md), [CWE weaknesses](CWE_REFERENCE.md) |
| Prioritization | [Vulnerability Prioritization](VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Priority Gap Analysis](scores/attack_priority_gaps.md), [CVE/KEV/EPSS](CVE_REFERENCE.md), [CAPEC patterns](CAPEC_REFERENCE.md), [coverage edge tables](data/) |
| Validation | [Purple Team](PURPLE_TEAM_REFERENCE.md), [Detection Strategies](detections/strategies/README.md), [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) |
| Mobilization | [Security Metrics](SECURITY_METRICS_REFERENCE.md), [D3FEND countermeasures](D3FEND_REFERENCE.md), [Controls Mapping](CONTROLS_MAPPING.md) |

**Extend it to fraud.** Exposure doesn't end at intrusion — for financial services and retail, the loss event is usually *monetization*. Run the same five stages against the [MITRE Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md): scope the payment/account flows, discover fraud-control gaps, prioritize by F3 monetization paths, validate whether a fraud actor could actually cash out, and mobilize the fraud + cyber teams on one shared model.

---

## Predictions and evidence base

### Adoption predictions scoreboard

Every public, dated Gartner prediction touching CTEM, in one place:

| Prediction | Source | Date | Status (Sep 2026) |
|---|---|---|---|
| Organizations prioritizing via continuous exposure management: **3x less likely to be breached** by 2026 (also stated as "two-thirds fewer breaches" / "two-thirds reduction") | Public article + 2023 trends announcements — see [The breach-reduction prediction](#the-breach-reduction-prediction) | Apr–Oct 2023 | Target year reached; no public retrospective validation |
| Through 2026, **>60% of TDIR capabilities** will leverage exposure management data (up from <5%) | Top 8 Cybersecurity Predictions 2023–24, Security & Risk Management Summit, Sydney ([coverage](https://idm.net.au/article/0014258-gartner-unveils-top-eight-cybersecurity-predictions-2023-2024)) | Mar 28, 2023 | No public follow-up measurement |
| By 2027, **40% of organizations** will have adopted formal exposure validation initiatives, mostly via AEV and MSPs | First AEV Market Guide, via [vendor release](https://rss.globenewswire.com/news-release/2025/04/01/3052931/0/en/Picus-Security-Announces-Recognition-in-Gartner-Market-Guide-for-Adversarial-Exposure-Validation.html) | Mar 11, 2025 | Open |
| By 2029, **60% of organizations** will have a structured exposure validation practice as part of CTEM | Second AEV Market Guide, via [vendor release](https://www.globenewswire.com/news-release/2026/04/10/3271747/0/en/hadrian-named-a-representative-vendor-in-the-gartner-market-guide-for-adversarial-exposure-validation.html) | Mar 24, 2026 | Open |

### The honest evidence base

Independent evidence that CTEM programs reduce breaches is thin, and a reference library should say so. What actually exists, in descending order of independence:

- **One peer-review-track study:** [*Measuring likelihood in cybersecurity*](https://arxiv.org/abs/2504.15395) (arXiv 2504.15395) builds a graph-based cyber exposure profile and reports an evaluation across 15 real organizations in five sectors, with reduced incident frequency and faster detection/response. It is a preprint — the closest thing to non-vendor empirical support.
- **Vendor telemetry at scale:** the XM Cyber / Cyentia exposure and choke-point statistics cited above — real data, but drawn from one vendor's platform and customer base.
- **Analyst planning assumptions:** Gartner's predictions in the scoreboard — directional forecasts, none publicly validated after the fact.
- **Vendor-sponsored surveys** ("X% of leaders recognize CTEM…") — marketing instruments with small samples; this reference does not rely on them.

### Sourcing notes

Three tiers of Gartner material feed any CTEM write-up, and it pays to know which one a claim sits in:

1. **Public gartner.com** — press releases and the August 2023 article. Safe to quote with attribution. (Gartner.com blocks automated retrieval, so verbatim wordings here were cross-checked against wire-service mirrors and licensed reprints.)
2. **Gartner-licensed vendor reprints and quotes** — category definitions, Hype Cycle positions, Market Guide excerpts republished under Gartner's quote policy. Cite the vendor page as the public record alongside the underlying Gartner document.
3. **Fully paywalled research** — the July 2022 CTEM note's text, the Market Guides, the Magic Quadrant, Hype Cycle dot positions. This document paraphrases and attributes; it never reproduces that text.

One trap worth naming: search engines surface a Wikipedia article for "Continuous Threat Exposure Management" that does not exist (the URL 404s, verified September 2026). Do not cite it.

---

*CTEM and the technology categories summarized here — EASM, CAASM, DRPS, VPT, BAS, EAP, and AEV — are Gartner-defined research categories; Gartner, Magic Quadrant, Hype Cycle, and Peer Insights are trademarks of Gartner, Inc. This reference is an independent practitioner summary, is not affiliated with or endorsed by Gartner, quotes only Gartner's public statements, and paraphrases rather than reproduces paywalled research. Vendor category names are used descriptively. Consult Gartner's published research for the authoritative definitions.*
