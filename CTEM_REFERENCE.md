# Continuous Threat Exposure Management (CTEM) Reference

> **CTEM is a program, not a product.** Introduced by [Gartner](https://www.gartner.com/en/articles/how-to-manage-cybersecurity-threats-not-episodes) in 2022, Continuous Threat Exposure Management is a five-stage operating loop that replaces periodic, scan-and-patch vulnerability management with a continuous cycle of **scoping, discovery, prioritization, validation, and mobilization** — driven by what an attacker could actually do to your business, not by raw CVE counts.

Gartner's headline prediction: organizations that prioritize security investments based on a continuous exposure management program are **three times less likely to suffer a breach**. The mechanism is simple — most vulnerabilities are never exploitable in a given environment, so effort spent on undifferentiated "critical" findings is effort not spent on the handful of exposures an adversary would really use.

This reference maps each CTEM stage to the concrete data, tooling, and references already in this library, so the loop can be run rather than admired.

**Related:** [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [ATT&CK Priority Gaps](scores/attack_priority_gaps.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md)

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

An **exposure** is anything that creates a viable attack path: an unpatched CVE, yes — but also an over-permissioned identity, a public S3 bucket, a stale DNS record enabling subdomain takeover, an MFA gap, a leaked credential, an unmonitored SaaS integration, or a fraud-control weakness. CTEM covers all of it.

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

Stages 1–2 define the **diagnosis** scope; 3–5 turn it into **action**. The loop repeats on a cadence (typically monthly or quarterly per scope, with continuous discovery underneath).

---

### Stage 1 — Scoping

**Question:** *Which slice of the attack surface are we managing this cycle, and why does the business care?*

Scoping is a business exercise, not a scanner configuration. Pick scopes that map to something a leader would lose sleep over — "customer payment flow", "Microsoft 365 tenant + identity", "internet-facing estate", "crown-jewel data stores", "third-party/supply chain".

**Do**
- Start with **one or two narrow, high-value scopes** — a first CTEM cycle that tries to cover everything produces nothing actionable.
- Define scope by **business outcome** (revenue, regulatory, safety, fraud loss), then enumerate the assets that support it.
- Include **non-traditional surface**: SaaS tenants, identity providers, CI/CD, developer laptops, third-party integrations, external brand/domain exposure.
- Write down what is explicitly **out of scope** this cycle.

**Don't**
- Scope by scanner coverage or by what's easy to see.
- Treat "all assets" as a scope.

**In this library:** [Enterprise Infrastructure](ENTERPRISE_INFRASTRUCTURE.md) · [Security Architecture](SECURITY_ARCHITECTURE_REFERENCE.md) · [Threat Modeling](THREAT_MODELING_REFERENCE.md) (to identify what an attacker would target) · [GRC & Compliance](GRC_COMPLIANCE_REFERENCE.md) (regulatory scopes)

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

**In this library:** [OSINT](OSINT_REFERENCE.md) (external discovery) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Kubernetes](KUBERNETES_SECURITY_REFERENCE.md) · [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) · [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) · [DevSecOps](DEVSECOPS_REFERENCE.md)

---

### Stage 3 — Prioritization

**Question:** *Of everything we found, what would an attacker actually use — and what would it cost us?*

This is where CTEM departs hardest from legacy VM. **Do not prioritize by CVSS base score alone.** Combine signals:

| Signal | What it tells you | Source |
|---|---|---|
| **CISA KEV** | It is *being exploited in the wild right now* | [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **EPSS** | Probability of exploitation in the next 30 days | [FIRST EPSS](https://www.first.org/epss/) |
| **CVSS (env-adjusted)** | Technical severity, adjusted for your environment | [CVE Reference](CVE_REFERENCE.md) |
| **Asset criticality** | Business value, data sensitivity, blast radius | Your CMDB / scoping work |
| **Reachability** | Is the vulnerable code path/port actually reachable? | Runtime & network context |
| **Compensating controls** | Would WAF, EDR, segmentation, or MFA already stop it? | [Coverage data](data/) · [D3FEND](D3FEND_REFERENCE.md) |
| **Attack-path position** | Does it unlock lateral movement toward crown jewels? | [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) |
| **Threat relevance** | Do actors targeting *our sector* use this technique? | [Threat Group Profiles](THREAT_GROUP_PROFILES.md) |

**A practical ranking rule:** *KEV-listed **and** reachable **and** on a critical asset **and** no compensating control* → fix now. Everything else queues behind it.

> **Attack paths beat findings.** Ten medium findings that chain into domain admin outrank one isolated critical. Prioritize the **chain**, and break it at its cheapest link.

**In this library:** [ATT&CK Priority Gap Analysis](scores/attack_priority_gaps.md) (most-used, least-covered techniques) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [CVE Reference](CVE_REFERENCE.md) · [Controls Mapping](CONTROLS_MAPPING.md) · [Coverage gaps](scores/coverage_gaps.md)

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
| **Adversarial Exposure Validation (AEV)** | Gartner's newer umbrella: BAS + autonomous pentesting |
| **Atomic Red Team** | Per-technique tests mapped to ATT&CK — cheapest way to start |
| **Purple team exercises** | Validating detection *and* response with the SOC in the loop |
| **Penetration testing / red team** | Depth, creativity, and full attack-path proof |
| **Control testing** | Does the WAF/EDR/segmentation rule actually fire? |

Validation output feeds **back into prioritization** — an "exposure" that is provably blocked by a compensating control gets deprioritized; one that walks straight to a crown jewel gets escalated.

**In this library:** [Purple Team](PURPLE_TEAM_REFERENCE.md) · [Detection Strategies](detections/strategies/README.md) (does telemetry exist?) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Pentest Checklists](PENTEST_CHECKLISTS.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md)

---

### Stage 5 — Mobilization

**Question:** *How does this actually get fixed, by people who don't report to security?*

Gartner is explicit that mobilization **cannot be fully automated** — the bottleneck is organizational, not technical. Security rarely owns the systems that need changing; the work is making action frictionless for the owners.

**Do**
- Give each exposure a **named owner, a deadline, and a route** (ticket in *their* system, not a PDF).
- Translate findings into the owner's language: "this lets an attacker read customer PII", not "CVE-2024-XXXX, CVSS 9.8".
- Pre-agree **SLAs by risk tier** and exception/risk-acceptance paths with sign-off.
- Track **mean time to remediate (MTTR)** per tier and per owning team; report trend, not raw counts.
- Close the loop — re-validate that the fix actually removed the exposure.

**Don't**
- Dump scanner exports on engineering teams.
- Treat "ticket created" as "risk reduced".

**In this library:** [Security Metrics](SECURITY_METRICS_REFERENCE.md) (MTTD/MTTR, SLAs, exec reporting) · [GRC Reference](GRC_REFERENCE.md) (risk acceptance, governance) · [SOAR Automation](SOAR_AUTOMATION_REFERENCE.md) (routing and workflow)

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

---

## Metrics that show CTEM is working

Avoid vanity metrics (total findings, scan counts). Track movement:

| Metric | Why it matters |
|---|---|
| **% of scope with validated exposure data** | Are we measuring reality or theory? |
| **MTTR for KEV/validated-exploitable exposures** | Speed where it counts |
| **Exposure dwell time** (discovery → remediation) | The window an attacker has |
| **Attack paths to crown jewels — open vs. closed** | The most business-legible metric available |
| **Validation coverage** (% of priority techniques tested) | Confidence that controls actually work |
| **Detection coverage on validated paths** | If we can't block it, can we see it? |
| **Recurrence rate** | Are fixes durable or regressing? |
| **Exception volume & age** | Accumulating accepted risk |

See [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md) for formulas and reporting patterns.

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

> **Failure modes to avoid:** boiling the ocean in Stage 1; declaring victory at Stage 2 ("we found 40k issues!"); prioritizing on CVSS alone; skipping Stage 4 entirely; and treating Stage 5 as security's job alone.

---

## CTEM, ATT&CK, and fraud together

This library's data lets you run the loop with real inputs:

| CTEM stage | Powered by |
|---|---|
| Scoping | [Enterprise Infrastructure](ENTERPRISE_INFRASTRUCTURE.md), [Threat Modeling](THREAT_MODELING_REFERENCE.md) |
| Discovery | [OSINT](OSINT_REFERENCE.md), [Vuln Mgmt](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Cloud](CLOUD_SECURITY_REFERENCE.md), [CWE weaknesses](CWE_REFERENCE.md) |
| Prioritization | [Priority Gap Analysis](scores/attack_priority_gaps.md), [CVE/KEV/EPSS](CVE_REFERENCE.md), [CAPEC patterns](CAPEC_REFERENCE.md), [coverage edge tables](data/) |
| Validation | [Purple Team](PURPLE_TEAM_REFERENCE.md), [Detection Strategies](detections/strategies/README.md), [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) |
| Mobilization | [Security Metrics](SECURITY_METRICS_REFERENCE.md), [D3FEND countermeasures](D3FEND_REFERENCE.md), [Controls Mapping](CONTROLS_MAPPING.md) |

**Extend it to fraud.** Exposure doesn't end at intrusion — for financial services and retail, the loss event is usually *monetization*. Run the same five stages against the [MITRE Fight Fraud Framework (F3)](FRAUD_FRAMEWORK_REFERENCE.md): scope the payment/account flows, discover fraud-control gaps, prioritize by F3 monetization paths, validate whether a fraud actor could actually cash out, and mobilize the fraud + cyber teams on one shared model.

---

*CTEM is a Gartner-defined framework; this reference is an independent practitioner summary and is not affiliated with or endorsed by Gartner. Vendor category names are used descriptively. Consult Gartner's published research for the authoritative definition.*
