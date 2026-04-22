# Security Metrics Reference

KPIs, dashboards, and measurement frameworks for security operations, vulnerability management, detection engineering, risk, and executive reporting.

---

## Why Metrics Matter

Security metrics answer three questions for leadership:
1. **Are we getting better?** (trend over time)
2. **How do we compare?** (benchmarks against peers/industry)
3. **Where should we invest?** (gap identification, ROI justification)

**Goodhart's Law warning**: When a measure becomes a target, it ceases to be a good measure. Pair every metric with context and leading indicators to avoid gaming.

---

## SOC Operations Metrics

### Core SLA Metrics

| Metric | Definition | Target (Tier 1) | Formula |
|---|---|---|---|
| Mean Time to Detect (MTTD) | Avg time from event occurrence to SOC detection | < 24 hours | (Sum of detection delays) / (# incidents) |
| Mean Time to Respond (MTTR) | Avg time from detection to initial containment | < 4 hours (critical) | (Sum of response times) / (# incidents) |
| Mean Time to Contain (MTTC) | Avg time from detection to full containment | < 24 hours | (Sum of contain times) / (# incidents) |
| Mean Time to Recover (MTTRec) | Avg time from incident to full service restoration | < 72 hours (critical) | Business side SLA |
| Alert Dwell Time | Avg time an alert sits unacknowledged in queue | < 1 hour | Time alert created → analyst acknowledges |
| Alert-to-Incident Conversion Rate | % of alerts that become confirmed incidents | 10-30% target | (# incidents) / (# alerts) × 100 |

### Alert Quality Metrics

| Metric | Definition | Target | Action if Out of Range |
|---|---|---|---|
| True Positive Rate (Precision) | % of alerts that are real detections | > 80% | Tune detection rules, improve filters |
| False Positive Rate | % of alerts that are benign | < 20% | Suppress noisy rules, add allow-lists |
| Alert Volume (weekly trend) | Total alerts per week | Stable/decreasing | Spike = new noise; drop = missed detections |
| Unclosed Alerts (SLA breach) | Alerts open > SLA threshold | 0% | Staff allocation, escalation review |
| Escalation Rate Tier 1→2 | % alerts Tier 1 escalates | 15-25% | High = training gap; low = escalation avoidance |
| Analyst Throughput | Alerts closed per analyst per shift | Varies by SOC | Benchmark against team average |

### Splunk SPL — SOC Dashboard Queries

```spl
# Alert volume over time (7-day trend)
index=alerts
| timechart span=1d count by severity
| rename TIMECHART as date

# MTTD calculation
index=incidents
| eval detection_lag = detection_time - event_time
| stats avg(detection_lag) as avg_mttd, max(detection_lag) as max_mttd, 
        min(detection_lag) as min_mttd by week

# MTTR calculation
index=incidents status=closed
| eval response_time = closed_time - detected_time
| stats avg(response_time) as avg_mttr by severity
| sort severity

# Alert-to-incident conversion rate (monthly)
index=alerts
| eval month=strftime(_time, "%Y-%m")
| stats count as total_alerts by month
| join month [
    search index=incidents
    | eval month=strftime(_time, "%Y-%m")
    | stats count as incidents by month
]
| eval conversion_rate=round((incidents/total_alerts)*100, 2)
| table month, total_alerts, incidents, conversion_rate
```

---

## Vulnerability Management Metrics

### Core VM KPIs

| Metric | Definition | Target | Measurement |
|---|---|---|---|
| Critical Vuln SLA Compliance | % criticals patched within SLA | > 95% | (Criticals patched on time) / (Total criticals) × 100 |
| High Vuln SLA Compliance | % highs patched within SLA | > 90% | Same formula for high severity |
| Mean Time to Patch (MTTP) Critical | Avg days to patch critical vulns | < 15 days | From CVE detection to patch verified |
| Mean Time to Patch (MTTP) High | Avg days to patch high vulns | < 30 days | Same |
| Vulnerability Backlog | Total open vulns by severity | Decreasing trend | Count open > SLA threshold |
| Patch Coverage | % of assets scanned within 30 days | > 98% | (Assets scanned) / (Total managed assets) × 100 |
| Remediation Rate | % of vulns remediated per week | > 10% backlog reduction | New remediations / Outstanding |
| EPSS-weighted Risk Score | Sum of EPSS scores for open criticals | Decreasing | Sum EPSS per open CVE |
| KEV Compliance | % CISA KEV entries remediated on time | 100% (federal mandate) | KEV entries patched by deadline |

### Patch SLA Reference

| Severity | CVSS Range | Industry Standard SLA | Federal Agency SLA (CISA BOD) |
|---|---|---|---|
| Critical + KEV | 9.0-10.0 + CISA KEV | 24-72 hours | 14 days (internet-facing) |
| Critical | 9.0-10.0 | 15 days | 30 days |
| High | 7.0-8.9 | 30 days | 60 days |
| Medium | 4.0-6.9 | 60-90 days | 90 days |
| Low | 0.1-3.9 | 180 days / next cycle | 180 days |

### VM Dashboard — KQL

```kql
// Critical vulnerability SLA compliance
let sla_days = 15;
Vulnerabilities
| where TimeGenerated > ago(90d)
| where Severity == "Critical"
| where Status == "Remediated"
| extend DaysToFix = datetime_diff('day', RemediationDate, DetectionDate)
| summarize 
    Total = count(),
    WithinSLA = countif(DaysToFix <= sla_days),
    Compliance = round(100.0 * countif(DaysToFix <= sla_days) / count(), 1)
    by bin(TimeGenerated, 7d)

// Vulnerability backlog trend (open criticals/highs over time)
Vulnerabilities
| where Status == "Open"
| where Severity in ("Critical", "High")
| summarize count() by Severity, bin(TimeGenerated, 1d)
| render timechart
```

---

## Detection Engineering Metrics

| Metric | Definition | Target |
|---|---|---|
| ATT&CK Coverage Score | % of relevant ATT&CK techniques with at least 1 detection | > 70% |
| Mean Time to Detect (detection-specific) | From attacker action to alert trigger | < 10 minutes |
| Detection-to-Hunt Ratio | # automated detections vs # manual hunts | Increasing automated |
| Rule Deprecation Rate | % of rules disabled/retired per quarter | < 5% |
| Rule FP Rate | % of alerts from rule that are FP | < 20% per rule |
| New Rules Deployed (quarterly) | Number of new detection rules created | Growth rate |
| Rules Converted from Hunts | % of hunting playbooks converted to rules | > 50% |

### ATT&CK Coverage Measurement

```python
# Measure coverage using MITRE ATT&CK Navigator layer
# Score each technique: 0 = no coverage, 1 = partial, 2 = full

def coverage_score(techniques: dict) -> dict:
    """Calculate ATT&CK coverage by tactic."""
    covered = sum(1 for v in techniques.values() if v > 0)
    total = len(techniques)
    return {
        "coverage_pct": round(covered / total * 100, 1),
        "covered_count": covered,
        "total_count": total,
        "gap_count": total - covered
    }
```

---

## Phishing and Security Awareness Metrics

| Metric | Benchmark (industry) | Good | Action if High |
|---|---|---|---|
| Phish Click Rate | 14-18% baseline | < 5% | Targeted training, simpler lures to raise awareness |
| Credential Submit Rate | 8-12% baseline | < 2% | Mandatory training for submitters |
| Phish Report Rate | 10-15% | > 25% | More phishing buttons, recognition program |
| Time to Report | 30+ min average | < 5 minutes | Speed critical for rapid takedown |
| Training Completion Rate | — | > 95% | Manager escalation for non-completers |
| Repeat Clickers | — | < 5% of workforce | Enhanced/mandatory targeted training |

---

## Risk and GRC Metrics

### Risk Posture KPIs

| Metric | Definition | Measurement |
|---|---|---|
| Residual Risk Score | Risk remaining after controls applied | FAIR model: LEF × LM after control reduction |
| Risk Treatment Completion | % of accepted risks with treatment plan implemented | (Risks with complete treatment) / (Total accepted risks) × 100 |
| Third-Party Risk Tier Compliance | % of Tier 1 vendors with current assessment | Assessment within 12 months |
| Audit Finding Closure Rate | % of findings closed within target remediation date | (On-time closures) / (Total findings due) × 100 |
| Policy Exceptions | Number of active policy exceptions | Decreasing; each > 90 days requires re-approval |
| Control Test Pass Rate | % of controls passing last test | > 90%; investigate any control failing repeatedly |
| Cyber Risk Register Items | Total open risk items by rating | Decreasing critical/high items |

### ROSI / Business Value Metrics

```python
def security_roi(
    control_cost: float,           # Annual cost of control
    incidents_prevented: float,    # Estimated incidents prevented per year
    avg_incident_cost: float       # Average cost per incident
) -> dict:
    annual_loss_avoided = incidents_prevented * avg_incident_cost
    net_benefit = annual_loss_avoided - control_cost
    roi_pct = (net_benefit / control_cost) * 100 if control_cost else 0
    return {
        "annual_loss_avoided": annual_loss_avoided,
        "control_cost": control_cost,
        "net_benefit": net_benefit,
        "roi_percentage": round(roi_pct, 1),
        "payback_months": round((control_cost / (annual_loss_avoided / 12)), 1) if annual_loss_avoided > 0 else "Never"
    }
```

---

## Executive Reporting Framework

### Security Scorecard Structure

```
Section 1: Executive Summary (1 page)
  - Overall security posture: Red/Yellow/Green + trend arrow
  - Top 3 risks requiring board attention
  - Key wins this period (incidents contained, programs launched)

Section 2: Threat Landscape (1/2 page)
  - Active threats targeting your sector
  - Relevant industry incidents
  - Threat actor activity relevant to company (sector, geography)

Section 3: Operational Metrics (1 page)
  - MTTD/MTTR trend (line chart, 12-month)
  - Incident count by severity (bar chart)
  - Phishing simulation results (trend)
  - Vulnerability SLA compliance (gauge chart)

Section 4: Investment and Roadmap (1/2 page)
  - Security spend as % of IT budget (benchmark: 8-12% of IT budget)
  - Top initiatives and status (RAG)
  - Upcoming regulatory requirements

Section 5: Risk Register Highlights (1/2 page)
  - Top 5 risks (description, rating, owner, treatment status)
  - Risks closed this quarter
```

### Benchmarking Sources

| Source | Benchmark Data Available |
|---|---|
| Verizon DBIR | Incident patterns, breach costs, time-to-detect by sector |
| IBM Cost of a Data Breach Report | Breach costs by industry, containment time |
| SANS Security Operations Survey | SOC staffing, tool spend, alert volume benchmarks |
| Gartner Security Budget Benchmarks | Security spend % of IT budget by company size |
| CIS Controls Community Defense Model | Control coverage vs threat prevention effectiveness |
| ESG/ISSA Cybersecurity Skills Survey | Staffing ratios, skills gap data |

---

## Dashboard Design Principles

### Metrics Hierarchy

```
Level 1 — Board/CEO: 3-5 KPIs (risk posture, major incidents, compliance)
Level 2 — CISO: 10-15 metrics (MTTD/MTTR, vuln SLA, phish rates, budget)
Level 3 — SOC Manager: 20-30 metrics (alert volume, analyst throughput, rule FP rates)
Level 4 — Analyst: Real-time queue depth, SLA timers, open case counts
```

### Avoiding Vanity Metrics

| Vanity Metric | Better Alternative |
|---|---|
| Total alerts generated | Alert-to-incident conversion rate |
| Number of blocked threats | MTTD for unblocked threats |
| Patches deployed this month | % of critical vulns within SLA |
| Training completions | Phish click rate reduction over time |
| Vulnerabilities scanned | % of critical assets scanned within 7 days |

## Related Resources
- [Coverage Schema](COVERAGE_SCHEMA.md) — Gap scoring model and ATT&CK coverage calculation
- [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md) — GRC measurement and risk quantification
- [Security Operations](disciplines/security-operations.md) — SOC operations and SIEM/SOAR
- [Detection Engineering](disciplines/detection-engineering.md) — Detection lifecycle and quality
- [Threat Hunting Playbooks](THREAT_HUNTING_PLAYBOOKS.md) — Hunt maturity model
