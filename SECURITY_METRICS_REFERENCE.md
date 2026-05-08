# SECURITY METRICS REFERENCE

## S1: Security Metrics Fundamentals

### Why Metrics Matter

Security metrics are the bridge between technical operations and business decision-making. Without quantifiable data, security leaders are forced to rely on anecdote and intuition when justifying budgets, prioritizing investments, and communicating risk to boards and executives. A mature metrics program accomplishes four critical business objectives:

**Budget Justification**: Security budgets compete against revenue-generating initiatives. Metrics provide the evidentiary basis for investment decisions. When a CISO can demonstrate that the organization's Mean Time to Detect (MTTD) is 47 days compared to the industry benchmark of 194 days — and can link each day of dwell time to an estimated loss of $145,000 based on FAIR analysis — budget requests transform from cost center arguments into risk-reduction ROI calculations. Boards understand dollars; metrics translate security into that language.

**Board Communication**: Board members and C-suite executives need a concise view of the organization's security posture. The right metrics provide a rolling narrative: where are we, where were we last quarter, where is the industry, and what are we doing about the gaps? Board reporting should feature 5-7 top-level indicators with trend arrows and benchmark comparisons, supported by a one-page narrative explaining significant changes.

**Data-Driven Decisions**: Without metrics, security programs operate on subjective prioritization — the most vocal stakeholder wins resources, or the most recent breach drives reactive spending. Metrics create an objective basis for decisions: which vulnerability class causes the most risk exposure, which business unit has the highest security debt, which control is failing to reduce incidents as expected.

**Program Accountability**: Metrics create accountability loops. When remediation SLAs are tracked and reported, vulnerability owners treat deadlines seriously. When phishing click rates are published by business unit, department heads engage with awareness programs. Measurement drives behavior.

---

### Metrics vs Measurements vs KPIs vs KRIs

These terms are frequently conflated, but precise usage matters in a board-ready security program:

| Term | Definition | Example |
|------|-----------|---------|
| **Measurement** | A raw data point; no inherent meaning without context | 47 unpatched critical vulnerabilities |
| **Metric** | A measurement with context, denominator, and trend | Critical vuln density: 4.7 per 1,000 assets (up 12% from last month) |
| **KPI (Key Performance Indicator)** | A metric tied to a strategic objective with a defined target | Patch SLA compliance: 87% (target: 95%) |
| **KRI (Key Risk Indicator)** | A metric that signals emerging risk before it materializes | External-facing assets with unpatched KEV entries: 3 (threshold: 0) |

KPIs measure program performance against internal goals. KRIs serve as early warning systems — they rise before incidents occur. A healthy metrics program maintains both: KPIs for accountability and KRIs for foresight.

---

### SMART Criteria for Security Metrics

Every metric in a formal security program should pass the SMART test:

- **Specific**: What exactly is being measured? "Security posture" is not a metric. "Percentage of endpoints with EDR agent deployed and reporting telemetry within 24 hours" is specific.
- **Measurable**: Can the metric be consistently calculated from available data sources? If collection requires manual effort for each reporting cycle, the metric is fragile.
- **Achievable**: Is the target realistic given current program maturity, staffing, and tooling? Setting a 100% patch SLA compliance target in year one destroys credibility when the actual rate is 60%.
- **Relevant**: Does the metric connect to a meaningful business risk? If it does not influence decisions or communicate meaningful risk, it is vanity.
- **Time-bound**: Metrics should have defined measurement periods and trend windows. A point-in-time snapshot without a trend is context-free.

---

### Metrics Taxonomy

**Operational Metrics (Daily/Weekly — SOC, Vulnerability, IT)**
- Alert volume, queue depth, true positive rate
- Vulnerability scan freshness, new critical vulns
- EDR agent health, coverage gaps

**Tactical Metrics (Monthly — Security Manager Layer)**
- MTTD/MTTR trends by severity
- Patch SLA compliance rates
- Phishing simulation results
- Compliance control drift

**Strategic Metrics (Quarterly — CISO/Board Layer)**
- Risk posture score and trend (Bitsight/SecurityScorecard)
- FAIR-quantified risk reduction dollar value
- Program maturity level progress
- Regulatory compliance percentage by framework

---

### Lagging vs Leading Indicators

**Lagging indicators** measure outcomes that have already occurred. They are accurate but reactive:
- Number of incidents last quarter
- Average cost per breach
- Audit findings count

**Leading indicators** predict future outcomes. They enable proactive intervention:
- % endpoints without EDR (predicts detection gaps)
- Open critical vulnerabilities over 30 days (predicts exploitation risk)
- Phishing click rate trend (predicts credential compromise probability)

Best-in-class programs maintain a 70/30 split: 70% leading indicators for proactive management, 30% lagging indicators for accountability and benchmarking.

---

### GRC Frameworks Requiring Security Metrics

| Framework | Requirement |
|-----------|------------|
| NIST CSF PR.IP-8 | Effectiveness of protection technologies is shared with appropriate parties |
| ISO 27001 Clause 9.1 | Organization shall evaluate information security performance and the effectiveness of the ISMS |
| SOC 2 CC9.1 | Entity identifies, selects, and develops risk mitigation activities |
| PCI DSS 12.4.2 | Executive management establishes responsibility for security and reviews metrics at least once per year |
| NIST SP 800-137 | Continuous monitoring of security controls with automated reporting |

---

### CISO Communication Principles

1. **Avoid Vanity Metrics**: "We blocked 4.7 million threats last month" tells the board nothing about risk. The firewall is supposed to block threats. Report on what got through, how fast it was detected, and what it cost.
2. **Tie to Business Risk**: Every metric should answer "so what?" in business terms. "Our phishing click rate is 12%" becomes "12% of employees would potentially hand credentials to an attacker, exposing our $2.3M average incident cost."
3. **Show Trends, Not Snapshots**: A single data point is meaningless. A six-month trend with annotations for program changes is actionable intelligence.
4. **Benchmark Against Peers**: Internal targets without external context are self-referential. Verizon DBIR, IBM Cost of a Data Breach, and CIS Benchmarks provide sector-specific comparators.

---

### Metrics Program Maturity Model

| Level | Name | Characteristics |
|-------|------|----------------|
| Level 0 | Ad-Hoc | No formal metrics; reporting is reactive and anecdotal |
| Level 1 | Defined | Core metrics defined; manually collected; inconsistent reporting cadence |
| Level 2 | Managed | Automated collection from primary tools; regular reporting cadence; targets set |
| Level 3 | Optimized | Predictive metrics; FAIR quantification; board-level integration; continuous improvement loop |

Most organizations operate at Level 1-2. Level 3 requires investment in SIEM/GRC integration, defined data governance, and executive sponsorship.

---

### Common Pitfalls

| Pitfall | Description | Remedy |
|---------|------------|--------|
| Wrong denominator | Reporting 500 vulnerabilities without context of asset count | Report density: vulns per 1,000 assets |
| No context | Showing numbers without benchmarks or trend | Add industry benchmark and 6-month sparkline |
| Activity, not outcomes | Counting scans run vs risk reduced | Replace with SLA compliance rate |
| Dashboard overload | 50+ metrics with no prioritization | Limit executive dashboard to 7 metrics |
| Static targets | Keeping the same KPI targets year over year | Review and tighten targets annually |
| Measuring the unmeasurable | Subjective scores without defined methodology | Document formula and data sources |

---

## S2: SOC & Detection Metrics

### Mean Time to Detect (MTTD)

MTTD is the average elapsed time between when an attacker achieves initial access (or when a security event begins) and when the security team identifies the incident. It is the single most operationally significant detection metric because it directly governs attacker dwell time and, consequently, breach cost.

**Calculation**:
```
MTTD = SUM(detection_timestamp - attack_start_timestamp) / incident_count
```

Where `attack_start_timestamp` is approximated from forensic artifacts (first malicious log entry, initial beacon timestamp, earliest lateral movement event) and `detection_timestamp` is when the alert or analyst flagged the event as a confirmed security incident.

**IBM Cost of a Data Breach 2024 Benchmark**: Organizations take an average of 194 days to identify a breach. The cost differential is stark: breaches contained within 200 days cost an average of $3.93M; those taking longer cost $4.82M — a $890,000 penalty for slow detection.

**MTTD Breakdown by Attack Type**:

| Attack Type | Average Industry MTTD | High-Performing Orgs |
|-------------|----------------------|----------------------|
| Ransomware | 49 days | <7 days |
| Credential theft / ATO | 243 days | <14 days |
| Insider threat | 197 days | <30 days |
| Web application attack | 12 days | <24 hours |
| Supply chain compromise | 197 days | <30 days |

**MTTD Improvement Levers**:
- **Detection coverage expansion**: Map SIEM detection rules to MITRE ATT&CK; identify uncovered techniques and deploy targeted detections.
- **Additional log sources**: Each new high-fidelity telemetry source (EDR, cloud API logs, DNS RPZ data, network flow) reduces detection blind spots.
- **ML-based anomaly detection**: User and Entity Behavior Analytics (UEBA) identifies deviations from baseline that rule-based systems miss, particularly effective for insider threats and credential misuse.
- **Threat hunting cadence**: Proactive hunting closes the gap between automated detection capability and actual adversary behavior.

---

### Mean Time to Respond (MTTR)

MTTR measures the average time from alert generation (or incident declaration) to resolution. Two sub-metrics provide more granular operational insight:

- **Alert-to-Containment**: Time from alert creation to isolation of the affected system(s). This measures how fast the team stops the bleeding. Target: <4 hours for P1 incidents.
- **Alert-to-Remediation**: Time from alert creation to full root cause remediation and return to normal operations. This is necessarily longer and depends on the nature of the incident.

**Analyst Capacity Constraints on MTTR**: MTTR is bounded by analyst capacity. If an analyst is handling 12 simultaneous P2 incidents, MTTR will degrade regardless of playbook quality. Track analyst utilization rate (active incidents per analyst) alongside MTTR to identify whether delays are process failures or staffing constraints.

---

### Mean Time to Acknowledge (MTTA)

MTTA measures the time from alert generation to the first human acknowledgment (analyst assigns the ticket or begins investigation). High MTTA indicates queue saturation, after-hours coverage gaps, or alert routing failures.

**SLA Compliance Tracking**:

| Severity | MTTA Target | MTTR Target |
|----------|------------|------------|
| P1 (Critical) | 15 minutes | 4 hours |
| P2 (High) | 1 hour | 24 hours |
| P3 (Medium) | 4 hours | 72 hours |
| P4 (Low) | 24 hours | 14 days |

Track SLA compliance rate as: `(alerts meeting SLA / total alerts) × 100` by severity tier. Publish monthly trends broken down by shift and day-of-week to identify coverage gaps.

---

### Alert Volume Metrics

Alert fatigue is the primary driver of analyst burnout and missed detections. Alert volume metrics expose the signal-to-noise ratio of the detection stack.

**True Positive Rate (Precision)**:
```
TPR = True Positives / (True Positives + False Positives)
```
Industry average precision for SIEM alerts is 5-10%. Best-in-class SOCs achieve 30-50% after extensive rule tuning. A rising TPR with stable or declining alert volume indicates effective tuning.

**Alert Fatigue Index**:
```
AFI = False Positives / True Positives
```
Target AFI < 10:1 (no more than 10 false positives per confirmed true positive). An AFI of 50:1 or higher indicates the detection stack is generating noise faster than analysts can filter it, creating conditions for critical events to be missed.

**Alert-to-Incident Conversion Rate**:
```
Conversion Rate = Confirmed Incidents / Total Alerts × 100
```
Track this monthly. A declining conversion rate with stable incident count suggests alert quality is degrading.

**Analyst Alert Handling Capacity**: Industry benchmarks suggest 20-40 alerts per analyst per day is sustainable for thorough investigation. Above 60 alerts/analyst/day, investigation quality degrades measurably. Use this benchmark to calculate required SOC headcount given current alert volume.

---

### SOAR Automation Metrics

Security Orchestration, Automation, and Response platforms reduce analyst burden by automatically handling routine alert triage and response actions.

**Key SOAR Metrics**:

| Metric | Formula | Target |
|--------|---------|--------|
| Auto-close rate | Alerts auto-closed by SOAR / total alerts | >40% |
| Escalation accuracy | Correct escalations / total SOAR escalations | >95% |
| MTTA reduction from SOAR | (MTTA pre-SOAR - MTTA post-SOAR) / MTTA pre-SOAR | >60% |
| Playbook coverage | Alert types with automated playbook / total alert types | >70% |

---

### Detection Coverage Metrics

**MITRE ATT&CK Coverage**: Map each active detection rule to the ATT&CK technique it addresses. Report:
- % of ATT&CK techniques with at least one detection rule (coverage)
- % of ATT&CK tactics with at least one high-confidence rule (tactic coverage)
- Coverage heatmap by threat actor profile relevant to your industry

**Log Source Coverage**:
- Active log sources / expected log sources per asset inventory
- % of critical assets contributing logs to SIEM within 24 hours
- % of SIEM rules with at least one active log source supplying required field

**Escalation Accuracy Rate**:
```
Escalation Accuracy = Correctly classified escalations / total escalations × 100
```
Low escalation accuracy (analysts escalating false positives to Tier 2) indicates Tier 1 training gaps. High false-negative rate in escalation (real incidents not escalated) requires tuning of escalation criteria.

**SLA Breach Rate by Severity**:
```
SLA Breach Rate = Alerts exceeding SLA / total alerts × 100
```
Break this down by severity tier, shift, day of week, and analyst team. Patterns reveal whether breaches are systematic (process failure) or isolated (individual performance or coverage gap).

---

## S3: Vulnerability Management Metrics

### Open Vulnerability Counts and Trend Analysis

Raw vulnerability counts, segmented by CVSS severity, provide the foundational baseline for vulnerability program health. However, counts without denominator context are misleading — a large organization with 5,000 hosts will always have more absolute vulnerabilities than a small one.

**Recommended Reporting Structure**:

| Severity | CVSS Range | Open Count | 30-Day Trend | SLA |
|----------|-----------|-----------|--------------|-----|
| Critical | 9.0-10.0 | — | ↑↓→ | 14 days |
| High | 7.0-8.9 | — | ↑↓→ | 30 days |
| Medium | 4.0-6.9 | — | ↑↓→ | 90 days |
| Low | 0.1-3.9 | — | ↑↓→ | 180 days |

**Vulnerability Density**: Normalize by asset count to enable meaningful comparison across business units and over time:
```
Vulnerability Density = Open Vulnerabilities / (Total Managed Assets / 1,000)
```
A density of <5 Critical vulns per 1,000 assets is a reasonable aspirational target for mature programs; >20 per 1,000 indicates systemic patching dysfunction.

---

### Age Distribution and SLA Compliance

**Age Buckets**: Track the age distribution of open vulnerabilities to identify remediation velocity issues before they compound:
- 0-30 days: New/recently discovered; acceptable backlog
- 31-60 days: Approaching or past SLA for Critical/High
- 61-90 days: SLA breach territory for High; medium pressure for Medium
- 90+ days: Chronic backlog; highest risk; escalation required

**SLA Compliance Rate by Severity**:
```
SLA Compliance Rate = (Vulns remediated within SLA / Total vulns reaching SLA deadline) × 100
```

Industry standard SLA targets (adjust based on risk appetite):

| Severity | SLA Target | Industry Avg Compliance | Best-in-Class |
|----------|-----------|------------------------|---------------|
| Critical | 14 days | 45% | 85% |
| High | 30 days | 55% | 90% |
| Medium | 90 days | 65% | 92% |
| Low | 180 days | 70% | 95% |

**Mean Time to Patch (MTTP)**:
```
MTTP = SUM(patch_date - discovery_date) / patched_vulnerability_count
```
Track MTTP separately for Critical, High, Medium, and Low. Trend MTTP monthly — rising MTTP against stable new-vuln rate indicates remediation capacity problems.

---

### Risk-Based Vulnerability Metrics

Pure CVSS-based prioritization is increasingly inadequate. Risk-based approaches incorporate exploitability, exposure, and asset criticality.

**EPSS-Weighted Exposure Score**: The Exploit Prediction Scoring System (EPSS) provides a daily probability (0-1.0) that a given CVE will be exploited in the wild within 30 days. Combine EPSS with CVSS to prioritize the actual risk:
```
Weighted Risk Score = CVSS_Base × EPSS_Score × Asset_Criticality_Factor
```
Sort and prioritize remediation by weighted score rather than CVSS alone. A CVSS 7.5 vulnerability with EPSS 0.85 is significantly more urgent than a CVSS 9.8 with EPSS 0.02.

**KEV Catalog Coverage Rate**: CISA's Known Exploited Vulnerabilities (KEV) catalog lists CVEs with confirmed exploitation in the wild. Tracking KEV coverage provides a near-binary risk indicator:
```
KEV Coverage Rate = (Applicable KEV entries patched / Total applicable KEV entries) × 100
```
Target: 100% — every KEV entry applicable to your environment should be patched within CISA's recommended timeframe (typically 14 days for federal agencies; commercial organizations should target 30 days maximum). Any KEV entry unpatched beyond 30 days represents a documented, exploited, unmitigated risk.

**Exploitable Attack Surface Size**:
```
EAS = SUM(KEV-applicable vulns × Asset_Criticality_Weight × Internet_Exposure_Factor)
```
This metric captures the risk-weighted exposure of the most dangerous vulnerability subset. Track monthly trend.

**CVSS Score Distribution**: Track the distribution of CVSS scores across all open vulnerabilities as a histogram. A program accumulating a growing proportion of 9.0+ scores without corresponding acceleration in remediation is building dangerous risk debt.

---

### Scanning Coverage and Freshness

Vulnerability data is only as good as scanning coverage and recency.

**Asset Coverage Ratio**:
```
Coverage = Assets Scanned / Total Known Assets × 100
```
Target: >98%. Gaps between discovered and scanned assets represent blind spots. Use network discovery tools (Nmap sweeps, DHCP log correlation) to identify unmanaged assets.

**Scan Freshness**:
```
Freshness = Assets scanned within past 7 days / Total assets × 100
```
Stale scan data produces false confidence. Assets unscanned for 30+ days may have received new software, configurations, or patches that invalidate cached vulnerability data. Target: >90% of assets scanned within 7 days.

**Credentialed vs Uncredentialed Scan Ratio**: Credentialed scans (agent-based or authenticated network scans) detect significantly more vulnerabilities than uncredentialed scans. A high proportion of uncredentialed scans artificially suppresses vulnerability counts. Track:
- % of scans that are credentialed/agent-based (target: >85%)
- Delta between credentialed and uncredentialed finding counts for overlapping assets

---

### Patch Management Metrics

**Deployment Rate**: Percentage of patches successfully deployed in the reporting period vs patches released by vendors and required by policy.

**Rollback Rate**: Percentage of deployed patches that required rollback due to compatibility or stability issues. A high rollback rate indicates insufficient testing in the patch pipeline; it also creates remediation gaps when patches are rolled back and not immediately re-deployed.

**Exception Management**:

| Metric | Formula | Target |
|--------|---------|--------|
| Exception approval rate | Approved exceptions / exception requests | Tracked (no universal target) |
| Exception aging | % of exceptions >90 days old | <20% |
| Exception revalidation compliance | Exceptions revalidated within policy period / total exceptions | >95% |
| Compensating control quality score | Subjective 1-5 score; document methodology | Track trend |

**Mean Time to Patch from Vendor Release**: Measures the pipeline efficiency from the day a vendor releases a patch to the day it is fully deployed in production. Separate tracking for server vs workstation vs network device is valuable because the deployment cadence and approval processes differ.

---

### Scanner-Specific Metrics

When multiple vulnerability scanners are in use (common in heterogeneous environments), meta-metrics about scanner performance are valuable:

- **False Positive Rate per Scanner**: Percentage of findings from each scanner that are confirmed false positives upon investigation. Scanners with >15% FP rates consume disproportionate analyst time and erode trust in the program.
- **Scanner-to-Scanner Correlation**: For the same asset scanned by two tools, what percentage of findings appear in both? Low correlation suggests one scanner has significant capability gaps or configuration issues.

---

## S4: Risk Quantification

### FAIR Model: Factor Analysis of Information Risk

FAIR (Factor Analysis of Information Risk) is the international standard framework for cyber risk quantification, providing a structured method to translate technical risk data into financial loss estimates that resonate with boards and executives. FAIR decomposes risk into hierarchical factors that can be estimated from available data.

**Core FAIR Formula**:
```
Risk = Loss Event Frequency × Loss Magnitude
```

**Loss Event Frequency (LEF)**:
```
LEF = Threat Event Frequency (TEF) × Vulnerability
```
- **TEF**: How often does a threat agent attempt an action against an asset? (e.g., phishing attempts per year, external exploitation attempts)
- **Vulnerability**: Given a threat event occurs, what is the probability the threat succeeds? (e.g., probability an employee clicks a phishing link = 0.12 based on simulation data)

**Loss Magnitude Components**:

| Component | Type | Examples |
|-----------|------|---------|
| Productivity loss | Primary | Employee downtime, business process interruption |
| Response costs | Primary | Incident response, forensics, legal, PR |
| Replacement costs | Primary | System rebuild, data recovery |
| Competitive advantage loss | Secondary | IP theft impact, customer defection |
| Regulatory fines | Secondary | GDPR, HIPAA, PCI DSS penalties |
| Reputation damage | Secondary | Customer trust, brand value |

**Monte Carlo Simulation**: Because each FAIR factor is a range estimate rather than a point estimate, FAIR analyses are run through Monte Carlo simulation (typically 10,000-100,000 iterations) to produce probability-weighted loss distributions:
- **10th percentile**: Best case (optimistic) annual loss exposure
- **50th percentile (median)**: Most likely annual loss exposure
- **90th percentile**: Worst case (conservative) annual loss exposure

Example output: "Ransomware risk for manufacturing segment: $1.2M - $3.8M - $12.4M (10th/50th/90th percentile annual loss)"

**FAIR-CAM (Controls Analytics Model)**: Extends FAIR to measure the dollar value of individual security controls by modeling how each control reduces Loss Event Frequency or Loss Magnitude. Enables security investment prioritization by expected risk reduction per dollar spent. FAIR Institute (fairinstitute.org) provides training, certification (FAIR analyst), and open model resources.

---

### Practical Risk Scoring Approaches

When full FAIR quantification is not yet feasible, semi-quantitative approaches provide interim capability:

**OWASP Risk Rating Methodology**: Uses a 4×4 matrix of Likelihood × Impact, each scored 1-9:
```
Risk Score = Likelihood Factor × Impact Factor
```
- 1-3: Low risk
- 4-6: Medium risk
- 7-9: High risk
- >9: Critical risk

Likelihood factors: Threat agent skill, motivation, opportunity, and size. Impact factors: Confidentiality, integrity, availability, and financial impact.

**NIST SP 800-30 Qualitative Levels**: Five-tier qualitative assessment (Very High / High / Moderate / Low / Very Low) with defined criteria for each tier. Suitable for risk register population when quantitative data is unavailable.

**Environmental CVSS Scoring**: Adjust base CVSS scores using the Environmental metric group to account for your organization's specific context:
- Modified Attack Vector (internal vs external)
- Confidentiality/Integrity/Availability Requirements (High/Medium/Low based on asset classification)
- Modified scope based on network segmentation

---

### Risk Register Metrics

The risk register is the authoritative record of identified risks. Its health metrics reflect risk governance maturity.

**Risk Count by Tier**:

| Tier | Count | Month-over-Month |
|------|-------|-----------------|
| Critical | — | ↑↓→ |
| High | — | ↑↓→ |
| Medium | — | ↑↓→ |
| Low | — | ↑↓→ |

**Risk Treatment Progress**: Percentage of open risks with active, funded remediation plans in place. An open risk without a treatment plan is an ignored risk. Target: >85% of High and Critical risks with active treatment.

**Risk Acceptance Rate**: Percentage of risks formally accepted (documented, approved by appropriate authority) vs. under active remediation. A high risk acceptance rate without clear compensating controls and re-assessment schedules indicates risk governance breakdown.

**Risk Appetite Threshold Monitoring**: Define quantitative risk appetite thresholds (e.g., no single risk with annual loss expectancy > $5M; no more than 3 Critical risks open at any time). Assign RAG status:
- Green: All risks within appetite
- Amber: 1-2 risks approaching threshold
- Red: Risk(s) exceeding defined appetite

**Risk Velocity**: Rate at which new risks are being identified vs. closed. A high identification rate with low closure rate indicates the program is growing risk debt. Target risk velocity should be negative (closing faster than opening) during maturity improvement phases.

---

### External Attack Surface Scoring

**Bitsight**: Continuously monitors externally observable signals (TLS/SSL certificate issues, open ports, malware infections, botnet participation, web application headers, patch cadence evidence) to produce:
- Overall security rating: 250-900 (higher is better)
- Letter grade: A-F
- Factor scores across 7 categories (Compromised Systems, User Behavior, Diligence, Public Disclosures, Data Breaches, Application Security, DNS Health)
- Industry peer benchmarking and portfolio risk management

**SecurityScorecard**: Similar external monitoring approach, grades A-F across 10 factor categories:
- Network Security, DNS Health, Patching Cadence, Endpoint Security, IP Reputation, Application Security, Cubit Score, Hacker Chatter, Information Leak, Social Engineering

**Using External Scores as KRIs**: Track monthly score trends. A declining Bitsight or SecurityScorecard rating is an early warning indicator of emerging risk, often detectable before internal teams identify the underlying issue. Also use to evaluate third-party vendors and supply chain risk.

---

### Cyber Insurance Metrics

Cyber insurance has become a critical component of the risk treatment portfolio. Insurance metrics connect security program performance to premium economics.

**Coverage Limit vs Estimated Maximum Loss (EML)**:
```
Coverage Adequacy Ratio = Coverage Limit / Estimated Maximum Loss
```
Target ratio: 1.0 or higher. If FAIR analysis indicates a 90th percentile annual loss of $15M and coverage limit is $10M, the organization carries $5M of uninsured tail risk. This gap should be reported to the board.

**Premium Trends**: Year-over-year premium change is a proxy for how insurers assess your risk profile. Document what security controls led to premium reductions (MFA implementation, EDR deployment, backup testing) to build the ROI case for security investments.

**Insurability Requirements Tracking**: Most cyber insurers now require minimum security controls for coverage. Track compliance with insurer questionnaire requirements:

| Control | Insurer Requirement | Current Status |
|---------|-------------------|----------------|
| MFA on all privileged accounts | 100% | Track % |
| EDR on endpoints | >90% coverage | Track % |
| Offline backup testing | Quarterly | Track frequency |
| Incident response plan | Documented & tested | Yes/No |
| Network segmentation | Evidence required | Yes/No |

---

## S5: Endpoint & Asset Security Metrics

### EDR Coverage and Quality

EDR (Endpoint Detection and Response) coverage metrics are among the highest-value security metrics because EDR is frequently the last line of defense against ransomware, credential theft, and living-off-the-land attacks. However, EDR metrics must measure actual protection capability, not mere agent presence.

**Coverage Depth Hierarchy** (from weakest to strongest):
1. Agent installed (weakest — does not guarantee protection)
2. Agent installed AND reporting telemetry within 24 hours
3. Agent on latest N-1 or newer version (receives current detection capabilities)
4. Full protection policy enforced (not monitor-only)
5. No excessive exclusions degrading coverage (strongest — true protection)

**Key EDR Metrics**:

| Metric | Formula | Target |
|--------|---------|--------|
| Agent deployment rate | Endpoints with agent / total managed endpoints | >99% |
| Active telemetry rate | Agents reporting in last 24h / deployed agents | >98% |
| Agent currency | Agents on N-1 or newer / deployed agents | >95% |
| Full protection rate | Agents in prevent mode / deployed agents | >95% |
| Exclusion ratio | Processes/paths excluded / default detection set | <5% |

**Exclusion Quality**: Exclusions are the "holes" in EDR protection. Every process or path excluded from scanning is a potential blind spot. Track:
- Total exclusion count and trend
- Exclusions added without security review (unauthorized exclusions)
- Exclusions older than 180 days (stale, likely unnecessary)
- Exclusions applied to broad paths (e.g., entire temp directories) vs. specific binaries

---

### OS Patching and Lifecycle Metrics

**Supported OS Coverage**: Unsupported operating systems do not receive security patches, creating permanent vulnerability exposure. Track:
```
EOL Coverage Risk = Endpoints running EOL OS / Total endpoints × 100
```
Target: 0% EOL endpoints. Each EOL endpoint represents unlimited unpatched CVEs as new vulnerabilities are discovered post-EOL.

| OS Version | EOL Date | Status |
|-----------|---------|--------|
| Windows 10 (no LTSC) | Oct 2025 | EOL imminently |
| Windows 11 | 2031+ | Current |
| Server 2012/R2 | Oct 2023 | EOL — extended security updates available |
| Server 2019 | Jan 2029 | Current |

**Mean Patch Lag**: Average number of days from vendor patch release to enterprise deployment. Track separately for:
- Client OS patches (Windows Update, macOS, Linux)
- Server OS patches
- Third-party applications (browsers, Java, Office)
- Network device firmware

**Top 10 Unpatched CVEs by Endpoint Exposure**: Rather than reporting aggregate unpatched counts, identify the 10 CVEs affecting the most endpoints and track remediation progress. This format is more actionable than aggregate statistics.

---

### Configuration Compliance Metrics

**CIS Benchmark Compliance Score**: The Center for Internet Security publishes detailed hardening benchmarks for every major OS, application, and device type. Measure compliance against the appropriate benchmark:
```
CIS Compliance Score = Passing controls / Total applicable controls × 100
```
Track by implementation group:
- IG1 (Essential, <100 employees): Target 100%
- IG2 (Standard enterprise): Target >85%
- IG3 (Sensitive data / regulatory): Target >90%

**Configuration Drift Rate**: The rate at which previously compliant systems develop new compliance failures. High drift indicates that patching or software deployment processes are inadvertently modifying security configurations.
```
Drift Rate = New compliance failures per week / Total monitored systems
```

**Exception Inventory**: Track CIS controls with formally approved exceptions, including exception age, owner, and compensating control documentation.

---

### Asset Inventory Completeness

The fundamental premise of security is knowing what you're protecting. Asset inventory gaps represent unmanaged risk.

**Shadow IT Rate**:
```
Shadow IT = (Network-discovered assets - CMDB-managed assets) / Network-discovered assets × 100
```
A shadow IT rate above 10% indicates significant CMDB maintenance failures. Common causes: cloud sprawl, BYOD, IoT/OT devices, temporary lab systems that became permanent.

**CMDB Accuracy Rate**: Percentage of CMDB records that match the actual observed state of the asset (correct OS, ownership, classification, network location). Measured by periodic automated reconciliation between CMDB and endpoint management tools.

**Stale Asset Records**: Assets in CMDB that have not checked in with any management tool (SCCM/Intune, EDR, vulnerability scanner) for more than 90 days. These records may represent decomissioned assets still holding licenses and security controls, or — more dangerously — active assets that have fallen outside management visibility.

**Software Inventory Coverage**: Percentage of managed endpoints with complete, current software inventory (applications, versions, installation dates). Critical for SCA (Software Composition Analysis) and license compliance.

---

### Encryption Metrics

**Full-Disk Encryption (FDE) Compliance**:

| Metric | Formula | Target |
|--------|---------|--------|
| FDE enabled | Devices with FDE enabled / total devices | 100% |
| Key escrowed | FDE-enabled devices with recovery key in central store / FDE-enabled devices | 100% |
| Verified encryption | Devices where FDE status confirmed by management tool (not self-reported) | >99% |

Note: FDE without key escrow is nearly as bad as no FDE from an organizational risk perspective — if the device is recovered after a loss/theft incident, data may be unrecoverable. Track both metrics.

**Removable Media Controls**:
- USB storage device allow-list compliance rate (only approved devices permitted)
- USB write-blocking policy coverage
- Encrypted USB adoption rate (for organizations permitting removable media)

---

### AV/EDR Policy Health

Beyond deployment coverage, track the operational health of EDR/AV policies:

- **Real-time protection enabled rate**: % of endpoints with real-time scanning active (not disabled by user or policy misconfiguration)
- **Signature/content currency**: % of endpoints with definitions updated within 24 hours (for signature-based components)
- **Tamper protection rate**: % of endpoints with EDR tamper protection enabled (prevents malware from disabling the agent)
- **Network protection enabled**: % of endpoints with network-layer protection features active (blocks connections to known malicious IPs/domains)

---

## S6: Identity & Access Management Metrics

### Privileged Access Metrics

Privileged access represents the highest-value attack target in any environment. Attackers seek privileged accounts because they enable lateral movement, data exfiltration, and persistence with minimal additional effort. Privileged access metrics quantify the "crown jewel" exposure.

**Privileged Account Density**:
```
PA Density = Privileged accounts / Total employee count × 100
```
Benchmark: <5% is a reasonable target for most organizations. A 500-person company should have fewer than 25 domain admin-equivalent accounts. Organizations frequently discover 3-5x more privileged accounts than expected during initial PAM assessments due to accumulated access over time.

**Privileged Accounts Without MFA**: Target is absolute zero. A privileged account without MFA is one phished password away from full domain compromise. Track:
- Domain admin accounts without MFA
- Cloud IAM admin accounts without MFA
- Service accounts with interactive logon capability and no MFA

**Service Account Proliferation**:
- Service accounts per application (benchmark: <3 per application)
- Stale service accounts (no authentication activity in 90+ days)
- Service accounts with excessive privileges (DA-equivalent service accounts)
- Shared service credentials (multiple applications using the same account)

**Shared Privileged Credential Usage Rate**: When privileged credentials are shared (e.g., generic "admin" accounts used by multiple people), attribution is impossible and password rotation is operationally disruptive. Target: 0% shared privileged credentials.

---

### MFA Metrics

MFA is the highest-impact identity control available. Its effectiveness depends not just on deployment rate but on the strength of the MFA method.

**MFA Enrollment Rate by User Type**:

| User Type | MFA Enrollment Target | Current Rate |
|-----------|----------------------|--------------|
| Employees (all) | 100% | Track % |
| Contractors | 100% | Track % |
| Third-party vendors | 100% with access to internal systems | Track % |
| Privileged accounts | 100% — enforce with no exceptions | Track % |

**MFA Method Strength Distribution**: Not all MFA is created equal. SMS and voice OTP are vulnerable to SIM swapping and SS7 attacks. FIDO2/WebAuthn (hardware security keys, passkeys) is phishing-resistant by design.

| MFA Method | Phishing Resistance | Relative Risk |
|-----------|--------------------|-|
| FIDO2/WebAuthn/Passkey | Full | Lowest |
| TOTP Authenticator App | Partial (real-time phishing can steal codes) | Low |
| Push Notification | Vulnerable to MFA fatigue attacks | Medium |
| SMS/Voice OTP | Vulnerable to SIM swap, SS7 attacks | High |
| Email OTP | Vulnerable to email account compromise | High |

Track the distribution and trend toward phishing-resistant methods. CISA's phishing-resistant MFA guidance recommends FIDO2 for privileged accounts.

**MFA Bypass and Exception Tracking**:
- Count of active MFA exceptions (named users, service accounts, specific applications)
- Exception age distribution (exceptions older than 90 days indicate governance failure)
- MFA bypass events (authentication without MFA when MFA is required) logged and alerted

**MFA Push Fatigue Incidents**: Track incidents where users approved MFA push requests they did not initiate (indicating MFA fatigue attack). Each such incident should trigger investigation and user coaching.

---

### Access Review Metrics

Access reviews (certifications) are the primary mechanism for detecting and removing excessive privilege over time.

**Certification Completion Rate**:
```
Completion Rate = Reviews completed within cycle / Total reviews initiated × 100
```
Target: >95%. A completion rate below 80% indicates the access review process is not operationally sustainable — reviewers are overwhelmed, the tooling is insufficient, or management engagement is lacking.

**Mean Days to Complete Certification**: Average calendar days from certification launch to completion. Long certification cycles leave excessive access in place during the review period.

**Orphaned Account Rate**: Accounts belonging to departed employees or contractors that remain active after offboarding. This is arguably the highest-risk identity hygiene metric:
```
Orphaned Account Rate = Active accounts for departed users / Total accounts × 100
```
Target: 0 orphaned accounts within 24 hours of offboarding. Orphaned accounts with privileged access should trigger immediate escalation.

**Excessive Privilege Rate**: Percentage of users identified in access reviews as having permissions they do not use. Measure via access analytics: compare permissions granted to permissions actually exercised in the past 90 days. Users with >50% unused permissions are candidates for privilege reduction.

**Separation of Duties Violations**: Count of users with role combinations that violate SoD policies (e.g., a user who can both create and approve purchase orders; a developer who can deploy to production without review). SoD violations are commonly flagged in financial audits and represent both a fraud risk and a security risk.

---

### Password and Credential Metrics

**Credential Exposure Detection**: Monitor for organizational credentials appearing in breach databases using HaveIBeenPwned API or similar services. Track:
- Monthly count of corporate email addresses found in breach datasets
- Response time from detection to forced password reset (target: <4 hours)
- Repeat appearances (same user's credentials in multiple breaches)

**Password Spray Attack Metrics**:
- Monthly count of detected password spray attempts
- Success rate of password spray attempts (any successful authentication) — target: 0%
- Detection time for spray campaigns (MTTD for this specific threat vector)

**SSO Adoption Rate**:
```
SSO Adoption = Applications using centralized SSO / Total applications × 100
```
SSO centralizes authentication, enables centralized MFA enforcement, and simplifies offboarding. Applications using local authentication create orphaned account risks and bypass centralized monitoring. Target: >90% of business applications using SSO.

**PAM Vault Adoption Rate**: Percentage of privileged accounts managed through a PAM solution (CyberArk, BeyondTrust, Delinea, etc.) with vaulted credentials, session recording, and just-in-time access:
```
PAM Adoption = Privileged accounts in PAM vault / Total privileged accounts × 100
```
Target: 100% for administrative accounts. PAM adoption eliminates standing privileged access and provides comprehensive audit trails.

---

## S7: Application & Cloud Security Metrics

### Application Security Pipeline Metrics

Application security must be integrated into the software development lifecycle (SDLC) to address vulnerabilities when they are cheapest to fix — during development, not after production deployment. Pipeline integration metrics measure the health of this "shift left" program.

**SAST/DAST/SCA Pipeline Coverage**:

| Tool Type | Function | Coverage Metric |
|-----------|---------|----------------|
| SAST (Static Analysis) | Finds code-level vulnerabilities in source | % of repos with SAST in CI/CD pipeline |
| DAST (Dynamic Analysis) | Finds runtime/API vulnerabilities in running apps | % of web apps with DAST in deployment pipeline |
| SCA (Software Composition Analysis) | Identifies vulnerable open-source dependencies | % of repos with SCA scan in build |
| Container scanning | Finds vulnerabilities in container images | % of container builds passing critical vuln gate |
| Secrets scanning | Detects hardcoded credentials in code | % of repos with pre-commit and CI secrets scan |

Target: >90% coverage for SAST and SCA in any organization with significant software development activity.

**Scan Completion Rate**:
```
Completion Rate = Scans successfully executed / Scans scheduled × 100
```
Failed scans create false confidence. Track separately for each tool type and alert when completion rate falls below 95%.

**Mean Time to Fix AppSec Findings by Severity**:

| Severity | Target MTF | Benchmark |
|----------|-----------|-----------|
| Critical | 7 days | 14 days industry avg |
| High | 30 days | 45 days industry avg |
| Medium | 90 days | 120 days industry avg |
| Low | 180 days | Best effort |

**Security Debt Trend**: The cumulative, aging backlog of unfixed security findings. Track as a weighted score:
```
Security Debt Score = SUM(Finding_Age_Days × Severity_Weight × EPSS_Score)
```
A rising security debt score indicates the program is not keeping pace with new vulnerability introduction.

**Developer-Introduced Vulnerability Rate**: New security findings introduced per sprint or per 1,000 lines of code. This metric drives the case for developer security training and IDE-integrated SAST tooling. A declining rate indicates that developer security awareness programs are effective.

---

### SBOM (Software Bill of Materials) Metrics

SBOMs provide transparency into the components, libraries, and dependencies that make up software. Post-Log4Shell and post-SolarWinds, SBOMs have become a regulatory and contractual requirement in many sectors.

**SBOM Coverage Rate**:
```
SBOM Coverage = Software releases with machine-readable SBOM / Total software releases × 100
```
Executive Order 14028 requires SBOMs for software sold to the US federal government. Target: 100% for externally distributed software; 80%+ for internal software.

**SBOM Completeness Score**: Percentage of SBOMs meeting NTIA minimum elements:
1. Supplier name
2. Component name
3. Version of the component
4. Other unique identifiers
5. Dependency relationships
6. Author of SBOM data
7. Timestamp

**VEX (Vulnerability Exploitability eXchange) Publication Rate**: For known CVEs affecting components in your SBOM, VEX documents clarify whether the vulnerability is actually exploitable in your specific product context. Track the percentage of applicable CVEs for which VEX documents have been published.

---

### Secrets Management Metrics

Hardcoded secrets (API keys, passwords, certificates, tokens) in source code or configuration files represent a persistent, often overlooked vulnerability class. The Uber breach (2022) and Twitch breach (2021) both involved exposed secrets.

**Secrets Detection Rates**:

| Detection Point | Metric | Target |
|----------------|--------|--------|
| Pre-commit hook | Secrets blocked before commit / total detected | >80% (reduce post-commit burden) |
| CI/CD pipeline scan | Secrets caught in pipeline / total detected | Track |
| Historical repo scan | Total secrets in git history | Remediate all; track to zero |

**Mean Time to Rotate Exposed Secrets**: From the moment a secret is confirmed exposed (in code, in logs, in incident), the clock starts on rotation. Target: <1 hour for high-severity secrets (cloud admin keys, production database passwords, private keys). Track compliance with this SLA.

**Secrets Management Tool Adoption**:
- % of applications retrieving secrets from vault vs hardcoding (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- % of CI/CD pipelines using secrets management integration vs hardcoded pipeline variables

---

### Cloud Security Posture Management (CSPM) Metrics

Cloud environments introduce security risks through misconfiguration at scale — a single misconfigured policy can expose thousands of resources simultaneously.

**CSPM Finding Count by Severity and Account**:
- Total CSPM findings by severity tier across all cloud accounts/subscriptions
- Findings per account (identifies highest-risk accounts)
- New findings per week (measures misconfiguration introduction rate)
- Trend: 30-day rolling average findings by severity

**Misconfiguration Remediation Metrics**:
```
Remediation Rate = Misconfigurations remediated / Total misconfigurations identified × 100
Mean Time to Remediate (MTTR) = AVG(remediation_date - discovery_date) by severity
```

**Internet-Exposed Resource Count**: The count of cloud resources (S3 buckets, databases, VMs, storage accounts) with public internet access that should not have it. Target: 0 unintended internet-exposed resources. This is often a KRI with an immediate escalation trigger.

**IAM Over-Permissiveness Score**: In cloud environments, IAM roles and policies frequently grant far more permissions than required (violating least-privilege principle). Measure using cloud-native tools (AWS IAM Access Analyzer, Azure AD Access Reviews, GCP IAM recommender):
```
Over-permissiveness Score = AVG(permissions granted / permissions actually used in 90 days) per role/user
```
A score of 10x means principals have 10x more permissions than they use — significant attack surface for privilege escalation post-compromise.

---

### Container Security Metrics

**Image Vulnerability Gate Compliance**:
```
Gate Compliance Rate = Container builds passing critical vuln threshold / Total builds × 100
```
Define the gate threshold (e.g., no Critical CVEs, no High CVEs with EPSS > 0.5) and enforce it in CI. Track the percentage of builds that would have been blocked without the gate (historical analysis) and the actual block rate.

**Runtime Security Alert Rate**: Alerts generated by container runtime security tools (Falco, Sysdig, Aqua) per container-day. An increasing runtime alert rate indicates either a deteriorating container environment or an active attack.

**Container Escape Attempts**: Detection of processes within containers attempting to escape to the host OS. This is a high-severity event that should trigger immediate investigation. Track count and MTTD for this specific threat vector.

**Base Image Currency**: Percentage of container images using a base image (e.g., Ubuntu, Alpine, Red Hat UBI) that was released within the past 90 days. Stale base images accumulate OS-level vulnerabilities.

---

## S8: Compliance & Audit Metrics

### Compliance Posture by Framework

Regulatory and contractual compliance is both a legal obligation and a proxy for security program maturity. Tracking compliance posture across frameworks provides a comprehensive view of control effectiveness.

**CIS Controls Implementation Levels**: The CIS Controls v8 define 153 safeguards organized into three Implementation Groups:

| Implementation Group | Scope | Safeguard Count | Target Coverage |
|---------------------|-------|----------------|----------------|
| IG1 | Essential cyber hygiene (all orgs) | 56 | 100% |
| IG2 | Enterprise (most orgs with IT staff) | +74 additional | >90% |
| IG3 | Large/sensitive (full set) | +23 additional | >85% |

Report IG1 coverage as a top-level KPI — it represents the baseline of defensible security hygiene.

**SOC 2 Control Effectiveness Tracking**:
- Design effectiveness: Is the control designed to address the relevant Trust Service Criteria?
- Operating effectiveness: Is the control functioning as designed, consistently, over the audit period?

Track findings from Type II audits:
- Exception count by Trust Service Category (CC = Common Criteria, A = Availability, C = Confidentiality, PI = Processing Integrity, P = Privacy)
- Exception severity (Deficiency vs Significant Deficiency vs Material Weakness)
- Exceptions remediated before next audit vs carried forward

**ISO 27001 Nonconformity Tracking**:
- Major nonconformities (systemic ISMS failures) — target: 0
- Minor nonconformities — target: declining trend
- Observations (improvement opportunities) — track resolution rate
- Coverage: % of ISO 27001 controls implemented (Annex A, 93 controls in 2022 version)

**PCI DSS Compliance Metrics**:
- Requirement-level compliance percentage (12 requirements, each with sub-requirements)
- Compensating control count and coverage quality
- Network segmentation validation frequency (quarterly penetration testing for CDE scope reduction)
- Qualified Security Assessor (QSA) finding count and severity

---

### Audit Finding Metrics

**External Audit Finding Count by Severity**:

| Severity | Definition | Target |
|----------|-----------|--------|
| Material Weakness | Significant deficiency that could result in material misstatement | 0 |
| Significant Deficiency | Less severe than material weakness but warrants attention of those charged with governance | 0 |
| Control Deficiency | Control designed/operating effectively but with improvement opportunity | Declining trend |
| Observation | Best practice recommendation | Track resolution |

**Repeat Finding Rate**: The same finding appearing in consecutive audit periods is a significant governance failure indicator. It suggests either the remediation was inadequate or the organizational will to fix the control gap is absent.
```
Repeat Finding Rate = Findings also present in prior audit / Total current audit findings × 100
```
Target: 0%. Any repeat finding should be escalated to CISO level with a root cause analysis and committed remediation timeline.

**Audit Finding Remediation Timeliness**:
```
On-Time Remediation Rate = Findings remediated by committed date / Total findings with committed dates × 100
```
Target: >90%. Missed remediation commitments erode auditor confidence and increase scrutiny in subsequent audits.

---

### Policy & Training Metrics

**Policy Currency Rate**: Security policies that are not regularly reviewed become stale, contradictory, or non-compliant with evolving regulations.
```
Policy Currency Rate = Policies reviewed within 12 months / Total policies × 100
```
Target: >95%. Every policy should have a defined review owner and calendar reminder. ISO 27001 requires documented evidence of policy review.

**Security Awareness Training Metrics**:

| Metric | Formula | Target |
|--------|---------|--------|
| Completion rate (annual) | Users completing annual training / Total users | >95% |
| Role-based completion (admin) | Admins completing elevated training / Total admins | 100% |
| Role-based completion (dev) | Devs completing secure coding training / Total devs | >95% |
| Completion within deadline | Users completing on time / Total users | >90% |

**Phishing Simulation Metrics** (leading indicators of security culture):

| Metric | Industry Average | Target |
|--------|-----------------|--------|
| Click rate | ~10% | <5% |
| Credential submission rate | ~3% | <2% |
| Report rate | ~18% | >30% |
| Repeat clicker rate | — | <15% of prior clickers |

The phishing report rate is a particularly valuable leading indicator — it measures active security culture participation, not just passive resistance.

---

### Exception Management Metrics

Every security exception — a system out of compliance, a control not implemented, a process step bypassed — represents accepted risk. Exception proliferation is a leading indicator of security program decay.

**Exception Inventory Health**:

| Metric | Formula | Target |
|--------|---------|--------|
| Total open exceptions | Count | Declining trend |
| Exceptions >90 days | Count of exceptions older than 90 days / total | <20% |
| Exceptions without compensating control | Count | 0 |
| Exception revalidation compliance | Exceptions revalidated on schedule / total | >95% |
| Exception-to-control ratio | Total exceptions / Total monitored controls | <5% |

---

### Vendor and Third-Party Risk Metrics

Third-party breaches are responsible for approximately 15-25% of all data breaches (Verizon DBIR). Vendor risk metrics quantify the supply chain risk exposure.

**Risk Assessment Coverage**:
```
Coverage Rate = Critical vendors with completed risk assessment / Total critical vendors × 100
```
Target: 100% for Tier 1 (critical) vendors. Define criticality tiers based on data access, system integration, and service dependency.

**Vendor Security Rating Trends**: Monthly Bitsight/SecurityScorecard ratings for all critical vendors. Declining vendor ratings trigger re-assessment and enhanced monitoring.

**SOC 2 Report Currency**:
```
Report Currency = Critical vendors with SOC 2 Type II report < 12 months old / Total critical vendors × 100
```
SOC 2 reports older than 12 months are considered stale. Request bridge letters for vendors in the coverage gap between report periods.

**Fourth-Party Risk Visibility**: Percentage of critical vendors for whom you have identified and assessed their critical sub-processors (fourth parties). This is an emerging compliance requirement under DORA (EU Digital Operational Resilience Act).

---

## S9: Incident & Business Continuity Metrics

### Incident Volume and Classification Metrics

**Incident Count by Severity Tier with Trend**:

| Severity | Definition | This Month | Last Month | 6-Month Avg |
|----------|-----------|-----------|-----------|------------|
| P1 (Critical) | Business impact, data breach, active ransomware | — | — | — |
| P2 (High) | Significant control failure, confirmed compromise | — | — | — |
| P3 (Medium) | Suspected compromise, policy violation with risk | — | — | — |
| P4 (Low) | Policy violation, minor anomaly, informational | — | — | — |

Plot 12-month rolling trends with annotations for major environmental changes (new tool deployments, architecture changes, M&A activity). Increasing P1/P2 volume is a board-level KRI.

**Severity Escalation Accuracy**: Measures analyst calibration — the ability to correctly classify incident severity at initial triage. Miscalibration in both directions has costs: over-escalation wastes senior analyst time; under-escalation delays containment of serious incidents.
```
Escalation Accuracy = Incidents where initial severity = final severity / Total incidents × 100
```
Target: >80%. Track separately for over-classification and under-classification to identify whether calibration issues favor one direction.

---

### Incident Cost Metrics

**Mean Cost per Incident**: Incident cost calculation is essential for FAIR model inputs and board-level risk quantification.

**Direct Cost Components**:
- Analyst hours × loaded hourly rate (salary + benefits + overhead)
- Tool costs allocated to incident (forensic tools, cloud log storage)
- External IR retainer usage (hourly billing for DFIR firm)
- Legal counsel hours
- Regulatory notification costs
- Credit monitoring for affected customers/employees

**Indirect Cost Components**:
- Business downtime (revenue-generating systems unavailable × hourly revenue)
- Customer churn (estimated based on incident severity and sector)
- Regulatory fines (GDPR: up to 4% global annual revenue; HIPAA: up to $1.9M per violation category)
- Reputational damage (stock price impact, brand value decline)

IBM Cost of a Data Breach 2024 global average: $4.88M per breach. Track your organization's rolling 12-month mean incident cost against this benchmark.

**Incident Recurrence Rate**: The same root cause producing multiple incidents indicates systemic failure — the first incident's lessons were not applied.
```
Recurrence Rate = Incidents sharing root cause with prior incident within 12 months / Total incidents × 100
```
Target: <10%. High recurrence rates indicate post-incident action item processes are failing.

---

### Root Cause Analysis Metrics

**Root Cause Distribution**: Maintain a rolling 12-month breakdown of incident root causes:

| Root Cause Category | % of Incidents | Industry Avg (Verizon DBIR) |
|--------------------|---------------|------------------------------|
| Vulnerability exploitation | — | ~32% |
| Misconfiguration | — | ~15% |
| Human error / phishing | — | ~68% involve human element |
| Third-party / supply chain | — | ~15% |
| Insider threat | — | ~7% |
| Unknown / under investigation | — | — |

Note: categories are not mutually exclusive; incidents may have multiple contributing root causes.

**Post-Incident Action Item Metrics**:
```
Action Item Completion Rate = Action items completed / Total action items assigned × 100
On-Time Completion Rate = Action items completed by due date / Total action items × 100
```
Target: >90% completion rate; >85% on-time. Systematically track post-incident actions in a ticketing system with assigned owners and due dates. Untracked action items are reliably forgotten.

---

### Business Continuity and Disaster Recovery Metrics

BCP/DR metrics are where security intersects operational resilience. Regulators (DORA, FFIEC, NYDFS) and cyber insurers increasingly require evidence of tested recovery capabilities.

**Recovery Objective Achievement Rates**:

| Metric | Formula | Target |
|--------|---------|--------|
| RTO Achievement Rate | Tests meeting Recovery Time Objective / Total DR tests | >95% |
| RPO Achievement Rate | Tests meeting Recovery Point Objective / Total DR tests | >95% |
| BCP Test Coverage | Critical systems tested in past 12 months / Total critical systems | 100% |

**Backup Health Metrics**:

| Metric | Formula | Target |
|--------|---------|--------|
| Backup Success Rate | Successful backup jobs / Scheduled backup jobs | >99.5% |
| Restore Test Success Rate | Successful restore tests / Total restore tests | >99% |
| Restore Test Frequency | Tests per quarter | ≥1 per quarter per critical system |
| Backup Immutability | Critical backups with immutable storage / Total critical backups | 100% |
| Offline Backup Coverage | Critical data with offline/air-gapped copy / Total critical data | 100% |

Ransomware actors specifically target backup systems before encrypting production data. Immutable, offline backups are the primary technical countermeasure for ransomware recovery.

**Tabletop Exercise Coverage**:
- Number of tabletop exercises conducted per year (target: ≥4, covering different scenarios)
- Executive participation rate (% of exercises with CISO/CIO/CEO participation — target: >75%)
- Scenarios covered: ransomware, data breach, supply chain compromise, insider threat, DDoS, regulatory notification
- Action items generated per exercise and completion rate

---

### Resilience Metrics

**Mean Time Between Control Failures (MTBF)**: Track the frequency of security control failures (EDR outages, SIEM unavailability, firewall rule failures, certificate expirations causing service disruptions). Increasing MTBF indicates improving resilience; decreasing MTBF indicates control reliability deterioration.

**Security Control Availability**:
```
Control Availability = (Total minutes in period - Downtime minutes) / Total minutes × 100
```
Track for critical security controls: SIEM, EDR management console, PAM, identity provider (IdP), email security gateway. Target: >99.9% availability for controls that directly impact detection capability.

**Defense-in-Depth Coverage**:
```
DiD Coverage = Assets with ≥3 independent security control layers / Total assets × 100
```
Example control layers: network perimeter controls, host-based EDR, identity-based controls (MFA), data-level controls (encryption, DLP), monitoring (SIEM/UEBA). Assets with only a single control layer represent high-consequence single points of failure.

**Threat Landscape Currency**:
- Threat model review date (should be reviewed at least annually or after significant architectural changes)
- Threat intelligence feed freshness (last updated, coverage of relevant threat actor groups)
- MITRE ATT&CK navigator profile last updated
- Threat-informed detection rule review cycle (are detection rules reviewed against current threat intelligence quarterly?)

---

## S10: Executive Reporting & Dashboard Design

### CISO Board Reporting Principles

The transition from technical metrics to board-ready reporting is the most critical skill in security program communication. Board members are not security experts — they are experienced business leaders who think in terms of risk, dollars, reputation, and legal liability. Every metric presented to the board should be translated through this lens.

**Translation Examples**:

| Technical Metric | Board Translation |
|-----------------|------------------|
| 72% patch SLA compliance for Critical vulns | 28% of our most dangerous vulnerabilities are not fixed within our own policy deadline, leaving known attack paths open |
| MTTD of 47 days | It takes us 47 days on average to discover an attacker in our environment — during which they have unrestricted access to our systems |
| Phishing click rate of 12% | Simulated phishing attacks show that 12% of employees would potentially surrender their credentials to a realistic phishing email |
| Bitsight score of 640 (B) | Our externally observable security posture rates as a 'B' — our industry peers average 690, suggesting room for improvement in several measurable areas |

**Board Report Structure** (one-page executive summary + appendix):
1. Overall security posture: RAG status with one-sentence narrative
2. Top 3 risks with dollar estimates and treatment status
3. Key metric trends: 6-month sparklines for 5-7 KPIs
4. What changed this quarter and why (narrative)
5. Industry benchmark comparison (Verizon DBIR, IBM Cost of Breach)
6. Planned investments and expected risk reduction (ROI framing)

**Dollar-Amount Reporting**: Use FAIR model outputs to express risk in financial terms. Boards are legally responsible for risk oversight; dollar amounts engage this fiduciary responsibility in a way that technical metrics cannot. Example: "Our current ransomware risk exposure is $2.1M - $8.7M annual loss expectancy (50th-90th percentile FAIR estimate). The proposed EDR upgrade reduces this exposure by approximately $1.4M (FAIR-CAM analysis), at a cost of $340K annually — a 4:1 return on risk-reduction investment."

---

### Dashboard Design Architecture

Security dashboards should be architected for their audience, not built as single monolithic views. Three distinct dashboard tiers serve different decision-making needs.

**Executive Dashboard (CISO → Board/C-Suite)**:
- Audience: CEO, CFO, Board, General Counsel
- Refresh: Monthly/Quarterly
- Metric count: 5-7 maximum
- Recommended metrics:
  1. Overall risk posture score and trend (custom composite or Bitsight/SSC)
  2. P1/P2 incident count this period vs prior period
  3. Regulatory compliance posture % (single composite across active frameworks)
  4. Critical asset exposure (KEV-applicable vulns on Tier 1 assets)
  5. Top 3 open risks with dollar estimates
  6. Security investment utilization (budget consumed vs planned)
  7. Employee security behavior index (phishing click rate + training completion)

**Tactical Dashboard (Security Managers → CISO)**:
- Audience: Security Operations Manager, Vulnerability Manager, GRC Manager, AppSec Lead
- Refresh: Weekly
- Metric count: 15-20
- Sections: SOC performance (MTTD/MTTR, alert metrics), vulnerability SLA compliance, identity hygiene (MFA, orphaned accounts), patch coverage, phishing and training, compliance control drift

**Operational Dashboard (SOC Analysts, VM Team)**:
- Audience: Security analysts, IT operations
- Refresh: Real-time / hourly
- Metric count: As needed for operational awareness
- Key real-time metrics: Alert queue depth by severity, open P1/P2 incidents, EDR coverage current status, scan freshness, certificate expiration countdown, critical KEV-applicable vulns introduced today

---

### RAG Threshold Framework

Red/Amber/Green (RAG) status indicators require explicitly defined thresholds to be meaningful. Subjective RAG assignment destroys consistency and comparability over time.

**Example RAG Framework**:

| Metric | Green | Amber | Red |
|--------|-------|-------|-----|
| Critical patch SLA compliance | >90% | 70-90% | <70% |
| MFA enrollment (all users) | >98% | 90-98% | <90% |
| EDR active coverage | >99% | 95-99% | <95% |
| MTTD (days, P1 incidents) | <2 days | 2-7 days | >7 days |
| Phishing click rate | <5% | 5-15% | >15% |
| Bitsight score | >720 | 640-720 | <640 |
| Critical vulns in KEV unpatched | 0 | 1-2 | >2 |
| Backup restore test (last 90 days) | Pass within 30 days | Pass within 60 days | >60 days or fail |

Publish RAG threshold definitions alongside the dashboard so stakeholders understand what triggers each status.

---

### Visualization Best Practices

**Trends over point-in-time**: Always show at least 6 months of history. A single data point is meaningless context; a trend tells a story. Use sparklines in executive tables to show direction without requiring a full chart.

**Heat maps for coverage**: Coverage metrics (EDR deployment by business unit, MITRE ATT&CK detection coverage by tactic, CIS Benchmark compliance by OS type) are most effectively communicated as heat maps. Color intensity immediately reveals gaps.

**Sankey diagrams for attack path risk**: Show how risks flow from initial access vectors through controls to potential impact. Useful for communicating the effectiveness of defense-in-depth to technical and non-technical audiences.

**Avoid pie charts**: Pie charts make comparison between segments difficult and trend visualization impossible. Use bar charts with time-series comparison instead.

**Annotate anomalies**: When a metric spikes or drops significantly, annotate the chart with the cause (new tool deployment, major incident, organizational change). Without annotation, outliers generate questions that the presenter must answer from memory.

---

### Security Metrics Tooling Ecosystem

| Category | Tools |
|----------|-------|
| External attack surface | Bitsight, SecurityScorecard, UpGuard CyberRisk |
| GRC / compliance | ServiceNow GRC, Archer, OneTrust, Vanta, Drata |
| SIEM / operational | Splunk, Elastic Security, Microsoft Sentinel, IBM QRadar |
| Executive reporting | Power BI, Tableau, Looker, Grafana |
| Asset intelligence | Axonius, Armis, Lansweeper |
| Vulnerability management | Tenable, Qualys, Rapid7, Wiz (cloud) |
| AppSec metrics | Veracode, Checkmarx, Snyk, DefectDojo |
| Red team / purple team | PlexTrac, VECTR, Cobalt Strike reporting |
| Privacy + compliance | OneTrust, TrustArc, Securiti |
| Risk quantification | RiskLens (FAIR platform), Safe Security, Axio |

---

### Metrics Program Roadmap

A metrics program cannot be built overnight. The following four-year roadmap provides a phased approach from baseline measurement to advanced analytics.

**Year 1: Establish Baselines**
- Define 10-15 core metrics covering the five pillars: vulnerability, identity, endpoint, detection, compliance
- Establish manual or semi-automated data collection processes
- Set initial targets based on current state + 20% improvement
- Begin monthly reporting cadence to security leadership
- Document data sources, formulas, and collection methodology for each metric
- Identify and remediate major data quality gaps (asset inventory, CMDB accuracy)

**Year 2: Automate and Expand**
- Automate data collection for all Tier 1 metrics via API integration (SIEM, VM tool, EDR console, identity platform)
- Build tactical and operational dashboards in chosen BI platform
- Expand metric library to 25-35 metrics
- Add leading indicators and KRIs to supplement lagging KPIs
- Begin vendor risk metrics program
- Conduct first formal metrics program review with external benchmarking

**Year 3: Quantify and Elevate**
- Implement FAIR risk quantification for top 5 organizational risks
- Develop board-ready quarterly security report template
- Add predictive metrics (ML-based anomaly detection on metric trends)
- Integrate peer benchmarking (Verizon DBIR sector cuts, ISACs)
- Begin tracking metrics program ROI (what decisions were made based on metrics data?)
- FAIR analyst certification for 1-2 team members

**Year 4+: Optimize and Innovate**
- Continuous improvement: retire metrics that no longer drive decisions; add emerging threat metrics
- Advanced analytics: predictive risk modeling, control effectiveness optimization
- Real-time board-level risk dashboard
- Integration of threat intelligence into risk quantification models
- Publish subset of metrics to auditors and regulators as evidence of control effectiveness
- Consider industry working group participation to contribute to benchmark data

---

*Reference compiled for security program management. Benchmarks from IBM Cost of a Data Breach 2024, Verizon DBIR 2024, CIS Controls v8, MITRE ATT&CK v14, FAIR Institute, and CISA advisories. Targets are aspirational; adjust based on organization size, industry, and risk appetite.*
