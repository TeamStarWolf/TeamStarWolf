# Cyber Risk Quantification

Cyber risk quantification (CRQ) is the practice of translating cybersecurity risk into financial and business terms using probabilistic models and analytical frameworks. Where traditional risk management produces qualitative red/yellow/green heat maps and subjective ordinal scores, CRQ produces outputs in dollars — annualized expected loss, confidence intervals, and scenario-based loss distributions that executives, boards, and insurance underwriters can act on directly. The discipline enables security leaders to make the same kind of evidence-based, financially grounded investment decisions that other business units use for capital allocation.

The central problem CRQ solves is comparability. A "high" risk in one security program cannot be compared to a "high" risk in another. A score of 7/10 conveys no information about how much to spend on remediation. CRQ replaces these subjective scales with a common currency — expected financial loss — that makes it possible to compare risks across business units, prioritize control investments by return on security investment (ROSI), size cyber insurance coverage rationally, and communicate residual risk to boards in language they already use to govern other enterprise risks. The FAIR framework has become the dominant open standard for structured CRQ, and it underpins most commercial and practitioner-grade quantification programs.

---

## Where to Start

Begin with the FAIR ontology before touching any tools or models. FAIR (Factor Analysis of Information Risk) provides the conceptual vocabulary — threat event frequency, vulnerability, loss magnitude, primary and secondary loss — that structures every CRQ analysis. Read the FAIR Institute's free foundational materials and Jack Jones' original FAIR paper before attempting a quantitative analysis. Once the framework is clear, use Python or Excel Monte Carlo simulations to build intuition for how uncertainty ranges propagate through the model.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | FAIR ontology and decomposition, difference between qualitative and quantitative risk, loss event frequency vs. loss magnitude, basic Monte Carlo simulation concepts, annualized loss expectancy (ALE) | FAIR Institute free resources (fairinstitute.org), Jack Jones FAIR whitepaper, ISACA CRISC study materials, basic Monte Carlo tutorial in Excel or Python |
| Practitioner | Full FAIR analyses for real scenarios, calibrated probability estimation, ROSI calculations, control effectiveness analysis with FAIR-CAM, bow-tie modeling, communicating CRQ outputs to executives and boards | Jack Jones "Measuring and Managing Information Risk" textbook, RiskLens Academy free content, PyFAIR Python library, FAIR-certified practitioner (FAIR-P) exam preparation |
| Advanced | Enterprise CRQ programs across hundreds of risk scenarios, integration with threat intelligence feeds, ATT&CK-based frequency estimation, cyber insurance actuarial modeling, M&A cyber due diligence, regulatory risk appetite statements | Open FAIR Body of Knowledge, FAIR-CAM certification, ISACA CRISC, peer-reviewed actuarial literature on cyber loss distributions |

---

## Free Training

- [FAIR Institute Resources](https://www.fairinstitute.org/resources) — The authoritative source for FAIR methodology; free whitepapers, webinars, and the FAIR ontology documentation; the required starting point for anyone learning quantitative cyber risk
- [Open FAIR Body of Knowledge](https://www.theopengroup.org/open-fair) — The Open Group's formal FAIR standard documentation; defines the ontology, taxonomy, and analysis process; free to access and the basis for all FAIR certifications
- [Jack Jones FAIR White Paper](https://www.riskmanagementinsight.com/media/docs/FAIR_Introduction.pdf) — The original FAIR methodology paper from the framework's creator; concise and foundational; explains the decomposition model and the rationale for quantitative over qualitative approaches
- [RiskLens Academy](https://www.risklens.com/academy) — Free introductory CRQ content from the leading FAIR-native commercial platform; covers FAIR basics, model construction, and executive communication
- [ISACA CRISC Study Materials](https://www.isaca.org/credentialing/crisc) — Free overview content for the CRISC certification; covers risk identification, assessment, response, and reporting frameworks including quantitative approaches
- [PyFAIR Documentation](https://github.com/theFIRMkid/pyfair) — Free Python library for building FAIR risk models programmatically; documentation includes worked examples and Monte Carlo output visualization; the best hands-on tool for learning FAIR mechanics
- [Hubbard Decision Research — How to Measure Anything](https://www.howtomeasureanything.com) — Free resources accompanying Douglas Hubbard's foundational text on measurement and uncertainty quantification; calibrated estimation techniques directly applicable to CRQ
- [SecurityMetrics.org](http://securitymetrics.org) — Community resource for security metrics and measurement; free articles and frameworks for building quantitative security measurement programs

---

## The FAIR Model

### What FAIR Is and Why It Matters

FAIR (Factor Analysis of Information Risk) is an open standard for cyber risk quantification developed by Jack Jones and published by The Open Group as the Open FAIR standard. It is the dominant framework for translating cybersecurity risk into financial terms and the foundation of most commercial CRQ platforms and vendor offerings.

FAIR solves a fundamental problem with traditional risk assessment: ordinal scales (High/Medium/Low, 1-10 scores) are not additive, not comparable across programs, and cannot answer the questions executives actually need answered — "How much could this cost us?" and "How much risk reduction does this control provide for the investment?" FAIR replaces these scales with probability distributions of financial loss, expressed in dollars, which can be directly compared, aggregated, and used in financial decision-making.

### The Core Formula: LEF × LM → ALE

The FAIR model decomposes risk into two top-level factors that combine to produce Annualized Loss Expectancy (ALE):

```
ALE = LEF × LM

Where:
  LEF (Loss Event Frequency) = How often a loss event is expected per year
  LM  (Loss Magnitude)       = Expected financial impact per loss event
  ALE                        = Expected financial loss per year
```

Both LEF and LM are expressed as probability distributions (not point estimates) because uncertainty is irreducible. The model uses Monte Carlo simulation to propagate these distributions through the calculation and produce a loss distribution with a mean (ALE), a range, and percentile values (e.g., 90th percentile for insurance sizing).

**LEF is further decomposed:**
```
LEF = TEF × V

Where:
  TEF (Threat Event Frequency) = How often a threat agent acts against an asset
  V   (Vulnerability)          = Probability that a threat event results in a loss event
```

**LM is further decomposed:**
```
LM = PLM + SLM

Where:
  PLM (Primary Loss Magnitude)   = Direct costs (response, replacement, productivity loss)
  SLM (Secondary Loss Magnitude) = Indirect costs (fines, litigation, reputational damage)
```

### Monte Carlo Simulation in FAIR

Because input estimates are uncertain ranges rather than single numbers, FAIR uses Monte Carlo simulation to compute the output distribution. The process works as follows:

1. Estimate TEF as a range: e.g., "Between 1 and 10 threat events per year, most likely around 3" — expressed as a PERT distribution
2. Estimate Vulnerability as a probability range: e.g., "Between 20% and 60% chance a threat event succeeds" — expressed as a beta or PERT distribution
3. Estimate LM components as ranges: e.g., "Primary loss between $50K and $500K, most likely $150K"
4. Run 10,000 iterations, sampling randomly from each distribution in each iteration
5. The output is a histogram of 10,000 ALE values — a loss distribution showing the most likely outcome, the mean, and tail risk percentiles

The [PyFAIR library](https://github.com/theFIRMkid/pyfair) implements this directly in Python and produces standard FAIR visualizations.

### OpenFAIR Standard

OpenFAIR is the formalization of FAIR as an open standard published by [The Open Group](https://www.theopengroup.org/open-fair). It consists of two documents:

- **Open FAIR Risk Taxonomy (O-RT)** — Defines the complete ontology: all risk factors, their definitions, relationships, and decomposition hierarchy; the authoritative reference for what each FAIR term means
- **Open FAIR Risk Analysis (O-RA)** — Defines the process for conducting a FAIR analysis: scoping, asset and threat identification, factor estimation, simulation, and reporting

The OpenFAIR standard is vendor-neutral, freely available, and the basis for all FAIR certifications (FAIR-P, FAIR-CAM). Using OpenFAIR terminology ensures consistent communication between organizations, consultants, and commercial tool vendors. The standard enables organizations to move between tools (PyFAIR, RiskLens, Axio) without losing analytical continuity.

---

## Tools & Repositories

### Open Source & DIY
- [theFIRMkid/pyfair](https://github.com/theFIRMkid/pyfair) — Python implementation of the FAIR quantitative risk model; supports Monte Carlo simulation, scenario modeling, and output visualization; the best open-source tool for FAIR analysis; enables programmatic risk modeling integrated into existing data pipelines
- [Open FAIR Ontology](https://github.com/openfairorg/openfairtoolbox) — Open-source FAIR toolbox resources including templates, reference models, and calibration guidance; the community implementation of the Open Group FAIR standard
- [Monte Carlo in Python/Excel](https://numpy.org) — NumPy and scipy.stats provide all the distributions needed for Monte Carlo CRQ models; triangular, PERT, and lognormal distributions are the workhorses of FAIR frequency and magnitude estimation

### Commercial Platforms
| Platform | Strength |
|---|---|
| **[RiskLens](https://www.risklens.com/)** | The FAIR-native commercial platform; purpose-built for FAIR analysis at enterprise scale; workflow-guided scenario construction, control effectiveness modeling, and board-ready reporting; the reference implementation for mature CRQ programs |
| **[Safe Security (SAFE Platform)](https://safe.security/)** | Continuous CRQ using asset inventory, threat intelligence, and control telemetry to produce real-time financial risk scores; strong for CISO dashboards and cyber insurance quantification; uses a quantitative model informed by FAIR principles |
| **[Axio](https://axio.com/)** | FAIR-based CRQ integrated with the C2M2 (Cybersecurity Capability Maturity Model); strong for critical infrastructure and energy sector organizations; maps control maturity directly to financial risk reduction in FAIR terms |
| **[BitSight](https://www.bitsight.com/)** | Security ratings platform with financial risk quantification features; uses externally observable security signals (DNS, SSL, vulnerability scanning, breach data) to estimate breach likelihood and expected loss; widely used for third-party risk quantification |
| **[SecurityScorecard](https://securityscorecard.com/)** | Security ratings with financial loss modeling; cyber insurance integration and board-level risk communication features; strong for supply chain and vendor risk quantification |
| **[Balbix](https://www.balbix.com/)** | AI-driven cyber risk quantification using asset inventory and vulnerability data; produces financial risk scores by asset, business unit, and attack vector; strong for large-scale enterprise environments with complex asset inventories |

---

## FAIR Decomposition

The FAIR model decomposes risk into a hierarchy of measurable factors that combine to produce a probability distribution of financial loss.

| FAIR Factor | Definition | Estimation Approach |
|---|---|---|
| Loss Event Frequency (LEF) | How often a loss event is expected to occur per year | Combine Threat Event Frequency with Vulnerability |
| Threat Event Frequency (TEF) | How often a threat agent is expected to act against an asset | Threat intelligence, industry incident data, red team frequency |
| Vulnerability | Probability that a threat event results in a loss event | Control effectiveness assessment, pen test findings, configuration data |
| Loss Magnitude (LM) | Expected financial impact when a loss event occurs | Primary loss + secondary risk; tabletop scenario analysis |
| Primary Loss | Direct financial impact (response costs, productivity loss, asset replacement) | IR cost data, downtime cost modeling, data breach cost benchmarks |
| Secondary Risk | Regulatory fines, litigation, reputational damage, competitive harm | Legal counsel estimates, regulatory fine history, brand valuation |
| Annualized Loss Expectancy (ALE) | Expected loss per year across the loss distribution | LEF multiplied by LM; expressed as a range with confidence intervals |

---

## Qualitative vs. Quantitative Risk: Why It Matters

Many security programs use ordinal risk scoring (High/Medium/Low or 1-5 scales) because it is fast and requires less data. CRQ practitioners must understand why this approach has fundamental limitations and when quantitative analysis is worth the additional effort.

| Dimension | Qualitative Scoring | Quantitative (FAIR/CRQ) |
|---|---|---|
| Output format | Ordinal labels or scores (H/M/L, 1-10) | Dollar amounts with probability distributions |
| Comparability | Cannot compare "High" across programs or time | Financial values are directly comparable and aggregatable |
| Investment decisions | Cannot calculate ROI on security controls | ROSI = (ALE reduction from control) − (annualized control cost) |
| Insurance sizing | No basis for coverage limit selection | 90th percentile loss directly informs coverage limits |
| Board communication | Requires translation to business language | Outputs are already in board-familiar financial terms |
| Data requirements | Low — subjective estimates suffice | Higher — requires calibrated frequency and magnitude estimates |
| Time investment | Low for individual assessments | Higher per scenario; amortized in mature programs |

The practical guidance: use qualitative methods for rapid triage and portfolio prioritization, and apply FAIR quantitative analysis to the top risks where investment decisions, insurance sizing, or board communication require financial precision.

---

## NIST 800-53 Control Alignment

| Control | ID | CRQ Relevance |
|---|---|---|
| Risk Assessment | RA-3 | CRQ is the quantitative implementation of risk assessment; FAIR analyses directly fulfill RA-3 requirements for assessing likelihood and impact of identified risks |
| Criticality Analysis | RA-9 | Asset criticality scoring in FAIR (loss magnitude estimation) operationalizes criticality analysis by expressing asset value in financial terms |
| Risk Management Strategy | PM-9 | CRQ provides the financial evidence base for organizational risk management strategy; quantified risk tolerance statements replace qualitative risk appetite levels |
| Risk Framing | PM-28 | FAIR analysis frames organizational risk in terms executives and boards use for governance decisions; financial risk framing enables consistent risk-informed decision making |
| Development Process Standards | SA-15 | CRQ applied to software development risk quantifies the expected loss from insecure development practices; provides financial justification for secure SDLC investment |
| Continuous Monitoring | CA-7 | Continuous CRQ platforms (SAFE, Balbix) monitor changes in financial risk posture as the threat environment, asset inventory, and control effectiveness change over time |

---

## ATT&CK Coverage

CRQ and the MITRE ATT&CK framework are complementary: ATT&CK provides the threat event catalog and adversary behavior data that populates FAIR's Threat Event Frequency and Vulnerability inputs. The table below maps ATT&CK usage patterns to CRQ analytical objectives.

| ATT&CK Technique / Category | ID | CRQ Integration |
|---|---|---|
| Phishing (Initial Access) | T1566 | TEF estimation for phishing scenarios draws on industry phishing frequency data; control effectiveness (email filtering, security awareness) maps to Vulnerability reduction; financial loss magnitude combines IR cost + productivity loss + potential data breach cost |
| Exploit Public-Facing Application | T1190 | Frequency estimated from vulnerability scan data and exploit kit deployment rates in threat intelligence; Vulnerability tied to patch cadence and WAF effectiveness; high loss magnitude due to direct access to internal systems |
| Valid Accounts | T1078 | Credential abuse is the highest-frequency initial access technique; TEF estimated from identity threat intelligence and dark web credential monitoring; MFA implementation directly reduces Vulnerability |
| Data Encrypted for Impact (Ransomware) | T1486 | Produces the largest loss magnitude estimates in most verticals; LM includes ransom payment probability, IR costs, downtime, recovery, regulatory fines, and reputational damage; quantifying this scenario is often the entry point for enterprise CRQ programs |
| Exfiltration Over Web Service | T1567 | Loss magnitude dominated by regulatory fines (GDPR Article 83, state breach laws), notification costs, litigation, and reputational damage; CRQ model captures secondary risk (SLM) which often exceeds primary loss |
| Service Stop | T1489 | Business interruption loss magnitude modeled as revenue per hour of downtime multiplied by expected outage duration; directly inputs to cyber insurance ABI (Additional Business Interruption) coverage sizing |
| Supply Chain Compromise | T1195 | Third-party risk quantification applies FAIR to vendor risk scenarios; BitSight and SecurityScorecard ratings provide external frequency signals for vendor-side TEF estimation |
| Command and Scripting Interpreter | T1059 | Endpoint detection coverage against T1059 sub-techniques reduces Vulnerability in FAIR models; ROSI of EDR investment is calculated by comparing ALE before and after EDR deployment against high-frequency T1059-based attack scenarios |

---

## Key Metrics

- **ALE (Annualized Loss Expectancy)** — The expected financial loss per year expressed as a probability-weighted average across the Monte Carlo loss distribution; the primary CRQ output for risk prioritization
- **ROSI (Return on Security Investment)** — (Risk reduction in ALE from a control) minus (annualized cost of the control); positive ROSI controls are financially justified; the core metric for security investment decisions
- **Loss Exposure (90th Percentile)** — The loss amount that will not be exceeded 90% of the time; used for cyber insurance limit sizing and worst-case scenario planning
- **Residual Risk** — The ALE remaining after a control is implemented; the financially expressed risk that the organization accepts or transfers to insurance
- **Risk Reduction ROI** — The ratio of annualized risk reduction to annualized control cost; enables comparison of competing security investments using the same financial metric

---

## Certifications

- **[FAIR-P](https://www.fairinstitute.org/certifications/fair-practitioner)** (FAIR Practitioner — FAIR Institute) — The entry-level FAIR certification; validates ability to conduct FAIR analyses, estimate model inputs, and communicate quantitative risk outputs; the recommended first credential for CRQ practitioners; covers the full FAIR ontology and analysis process per the OpenFAIR standard
- **[FAIR-CAM](https://www.fairinstitute.org/certifications/fair-controls-analytics-model)** (FAIR Controls Analytics Model — FAIR Institute) — Advanced FAIR certification covering control effectiveness modeling, FAIR-CAM framework application, and portfolio-level risk analysis; the credential for senior CRQ analysts who need to quantify the financial impact of specific security controls
- **[CRISC](https://www.isaca.org/credentialing/crisc)** (Certified in Risk and Information Systems Control — ISACA) — The most widely recognized IT risk certification; covers risk identification, assessment, response, and monitoring frameworks including quantitative approaches; valued in governance and risk management roles; broader than FAIR but provides important risk management context
- **[CISM](https://www.isaca.org/credentialing/cism)** (Certified Information Security Manager — ISACA) — Information security management certification with significant risk management content; the governance-layer credential for security managers communicating risk to business stakeholders; pairs well with CRQ skills for CISO-track practitioners
- **[CISSP](https://www.isc2.org/Certifications/CISSP)** (Certified Information Systems Security Professional — ISC2) — Broad security certification with a dedicated risk management domain; the credential most commonly held by practitioners entering CRQ from a general security background; Domain 1 (Security and Risk Management) covers risk frameworks including quantitative approaches

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Measuring and Managing Information Risk (Jones & Freund)](https://www.amazon.com/Measuring-Managing-Information-Risk-Approach/dp/0124202314) | Book | The definitive FAIR textbook; the foundational reference for every CRQ practitioner; explains the full FAIR ontology with worked examples |
| [FAIR Institute](https://www.fairinstitute.org) | Community | Webinars, case studies, and the primary community for FAIR practitioners worldwide; free membership available |
| [How to Measure Anything in Cybersecurity Risk (Hubbard & Seiersen)](https://www.amazon.com/How-Measure-Anything-Cybersecurity-Risk/dp/1119085292) | Book | Applies Hubbard's measurement methodology to cyber risk; calibrated estimation and Bayesian approaches; complements FAIR with statistical rigor |
| [Open FAIR Body of Knowledge](https://www.theopengroup.org/open-fair) | Standard | The formal FAIR ontology (O-RT) and analysis process (O-RA) from The Open Group; free; the authoritative reference for OpenFAIR terminology and methodology |
| [RiskLens Academy](https://www.risklens.com/academy) | Free course | FAIR-native platform training; practical CRQ workflows and case studies; teaches FAIR analysis in a guided commercial context |
| [PyFAIR GitHub](https://github.com/theFIRMkid/pyfair) | OSS tool | Python FAIR library with worked examples; the best hands-on learning environment for understanding Monte Carlo FAIR models |
| [ISACA CRISC Resources](https://www.isaca.org/credentialing/crisc) | Certification prep | Risk and information systems control framework; quantitative risk assessment coverage |
| [SecurityMetrics.org](http://securitymetrics.org) | Community | Security metrics and measurement resources; practitioner-focused and vendor-neutral |

---

---

#### FAIR Model Deep Dive

**FAIR (Factor Analysis of Information Risk) Ontology**

Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)

**Loss Event Frequency**
- Threat Event Frequency (TEF): How often does a threat agent come in contact with your asset?
- Vulnerability: Given contact, what is the probability of a successful attack?
- LEF = TEF × Vulnerability

**Loss Magnitude**
- Primary Loss: Direct financial impact to your organization
  - Productivity loss (downtime × hourly rate)
  - Response costs (IR, legal, PR, forensics)
  - Replacement costs (hardware, software rebuild)
  - Competitive advantage loss
- Secondary Loss: Stakeholder reaction to event
  - Regulatory fines and legal settlements
  - Reputation damage (revenue reduction)
  - Stock price impact (public companies)

**Example FAIR Analysis: Ransomware Scenario**
- Asset: Finance systems with sensitive customer data
- Threat: Ransomware affiliate group
- TEF: 2 times per year (based on sector threat intel)
- Vulnerability: 40% (assume patching, EDR, backups reduce but not eliminate risk)
- LEF: 2 × 0.4 = 0.8 times per year
- Primary Loss range: $800K - $3M (IR: $200K, downtime: $500K-$1.5M, ransom/recovery: $100K-$1.3M)
- Secondary Loss range: $200K - $2M (regulatory notification, reputation)
- Annual Loss Expectancy (ALE) = LEF × Expected LM = 0.8 × $1.5M = $1.2M per year
- Conclusion: Any control costing <$1.2M/year with >0% risk reduction is net positive

#### Monte Carlo Simulation

**Why Monte Carlo for Cyber Risk**
- Range inputs (min, most likely, max) instead of point estimates
- Captures uncertainty and model sensitivity
- Output: Probability distribution of potential losses — "90th percentile loss is $4.2M"
- Industry tools: RiskLens (FAIR-native), FAIR-U (free simulation), @RISK (Excel add-in), Python scipy/numpy

**Python FAIR Monte Carlo Example**
```python
import numpy as np

np.random.seed(42)
n_simulations = 100_000

# Loss Event Frequency — PERT distribution (min, likely, max)
tef = np.random.triangular(0.5, 2, 5, n_simulations)      # threat event frequency per year
vulnerability = np.random.triangular(0.1, 0.35, 0.6, n_simulations)
lef = tef * vulnerability

# Loss Magnitude — log-normal (realistic for financial losses)
primary_loss = np.random.lognormal(mean=13.5, sigma=1.0, size=n_simulations)  # ~$730K median
secondary_loss = np.random.lognormal(mean=12.5, sigma=0.8, size=n_simulations) # ~$270K median
total_loss = primary_loss + secondary_loss

# Annual loss
annual_loss = lef * total_loss

print(f"Expected Annual Loss (mean): ${annual_loss.mean():,.0f}")
print(f"90th percentile annual loss: ${np.percentile(annual_loss, 90):,.0f}")
print(f"95th percentile annual loss: ${np.percentile(annual_loss, 95):,.0f}")
```

#### Communicating Risk to the Board

**Board-Level Metrics**
- Cyber Value at Risk (CyVaR): Dollar amount at risk at specific confidence interval (like financial VaR)
- Annual Loss Expectancy by business unit: Which units carry the most cyber risk?
- Risk reduction per dollar: Which controls generate the highest risk reduction per dollar invested?
- Coverage metrics: % of critical assets covered by EDR, backup, vulnerability management
- Top 5 scenarios: Board wants to understand the biggest potential impacts, not 300 risk register rows

**CISO Board Presentation Template**
1. Current threat landscape (1 slide): What threats are most active in our sector?
2. Top 3 risk scenarios (1 slide per): FAIR quantification, P50/P90 loss estimates, current controls
3. Control effectiveness metrics (1 slide): How well are our investments working?
4. Risk reduction investment request (1 slide): This program reduces ALE by $X for $Y cost
5. Regulatory posture (1 slide): Where do we stand on material obligations?

**Business Risk vs Technical Risk Communication**
- Technical: "We have a critical unpatched RCE in our customer portal"
- Business: "There is a $2.3M expected annual loss exposure from an exploitable web vulnerability that enables unauthorized access to 800,000 customer records — representing CCPA notification and regulatory penalty risk"

#### ROSI (Return on Security Investment)

Formula: ROSI = (Risk Reduction Amount × Asset Value) - Control Cost
Or alternatively: ROSI = (ALE Before - ALE After) - Annual Control Cost

**Example**:
- ALE before EDR: $3.2M (based on FAIR model)
- ALE after EDR deployment: $1.1M (65% reduction)
- Risk reduction: $2.1M/year
- EDR annual cost: $400K
- ROSI: $2.1M - $400K = $1.7M/year positive return
- ROI %: ($2.1M - $400K) / $400K = 425%

---

## Related Disciplines

- [Governance, Risk & Compliance](governance-risk-compliance.md) — CRQ is the quantitative engine inside GRC programs; it transforms qualitative risk registers into financially expressed risk portfolios that governance frameworks can act on
- [Security Architecture](security-architecture.md) — CRQ provides the financial justification for architecture decisions; ROSI calculations determine which security architecture investments are economically rational
- [Threat Intelligence](threat-intelligence.md) — Threat intelligence feeds provide empirical data for FAIR Threat Event Frequency estimation; CTI teams are the primary source of adversary capability and frequency data for CRQ models
- [Threat Modeling](threat-modeling.md) — Threat modeling identifies the risk scenarios that CRQ quantifies; the two disciplines are complementary — threat modeling scopes and structures the scenarios, CRQ assigns financial values
- [Security Operations](security-operations.md) — SOC detection coverage and incident metrics provide empirical Vulnerability and frequency data for FAIR models; CRQ quantifies the financial value of SOC investment and detection engineering
