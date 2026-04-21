# Vendor Coverage Gap Scoring — Data Model & Schema

This page defines the data model for scoring vendor coverage against ATT&CK techniques through NIST 800-53 controls. It connects the Optiv market map vendor taxonomy, the NIST 800-53 control framework, and ATT&CK technique coverage into a queryable gap analysis system.

For the control-to-technique reference table, see [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md).
For pipeline context, see [SECURITY_PIPELINE.md](SECURITY_PIPELINE.md).

---

## Data Model Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     COVERAGE DATA MODEL                         │
├───────────────┬──────────────────────┬──────────────────────────┤
│  VENDOR       │  CONTROL             │  TECHNIQUE               │
│  ─────────    │  ────────            │  ─────────               │
│  name         │  nist_id             │  technique_id            │
│  normalized   │  family              │  technique_name          │
│  market_family│  description         │  tactic                  │
│  pipeline_stages│ pipeline_stage    │  subtechnique_of         │
│  confidence   │  vendor_satisfies[]  │  nist_controls[]         │
│               │  attck_techniques[]  │  coverage_vendors[]      │
└───────────────┴──────────────────────┴──────────────────────────┘

Edge Tables:
  vendor_to_control:   vendor_id → nist_control_id  (confidence: high/medium/low)
  control_to_technique: nist_control_id → technique_id  (source: CTID)
  vendor_to_technique:  vendor_id → technique_id  (derived: via control chain)
```

---

## Vendor Record Schema

```json
{
  "vendor_id": "crowdstrike-falcon",
  "vendor_name": "CrowdStrike Falcon",
  "vendor_normalized": "crowdstrike",
  "market_family": "SecOps",
  "market_subfamilies": ["EDR", "Threat Intelligence", "SOAR"],
  "pipeline_stages": [3, 4, 5, 6, 7, 8, 9],
  "nist_controls_satisfied": [
    { "control_id": "SI-3", "confidence": "high", "notes": "Malicious code protection" },
    { "control_id": "SI-4", "confidence": "high", "notes": "Information system monitoring" },
    { "control_id": "CM-7", "confidence": "high", "notes": "Least functionality" },
    { "control_id": "AU-2", "confidence": "high", "notes": "Audit events" },
    { "control_id": "IR-4", "confidence": "high", "notes": "Incident handling" },
    { "control_id": "IR-5", "confidence": "medium", "notes": "Incident monitoring" }
  ],
  "ctid_framework_mappings": [
    { "framework": "nist800-53", "url": "https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/" }
  ],
  "coverage_notes": "Covers Initial Access through Impact; strongest on Execution, Defense Evasion, Credential Access, Lateral Movement"
}
```

---

## Control Record Schema

```json
{
  "control_id": "SI-4",
  "control_family": "SI",
  "family_name": "System and Information Integrity",
  "control_name": "Information System Monitoring",
  "pipeline_stage": 5,
  "attck_techniques_mitigated": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "tactic": "Execution",
      "mapping_type": "mitigates",
      "source": "CTID NIST 800-53 v5"
    },
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "tactic": "Defense Evasion",
      "mapping_type": "detects",
      "source": "CTID NIST 800-53 v5"
    }
  ],
  "vendors_satisfying": ["crowdstrike-falcon", "sentinelone", "microsoft-defender-endpoint"],
  "ctid_url": "https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/"
}
```

---

## Coverage Edge Schema (Graph Model)

### vendor_to_control edges
```json
{
  "edge_type": "vendor_satisfies_control",
  "vendor_id": "crowdstrike-falcon",
  "control_id": "SI-4",
  "pipeline_stage": 5,
  "confidence": "high",
  "evidence": "Falcon sensor monitors process execution, network connections, file operations, and registry changes in real time"
}
```

### control_to_technique edges (from CTID)
```json
{
  "edge_type": "control_mitigates_technique",
  "control_id": "SI-4",
  "technique_id": "T1059.001",
  "tactic": "Execution",
  "mapping_type": "mitigates",
  "source": "CTID NIST 800-53 v5 → ATT&CK v16.1",
  "ctid_url": "https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/"
}
```

### vendor_to_technique edges (derived)
```json
{
  "edge_type": "vendor_covers_technique",
  "vendor_id": "crowdstrike-falcon",
  "technique_id": "T1059.001",
  "tactic": "Execution",
  "coverage_type": "detect+prevent",
  "via_control": "SI-4",
  "confidence": "high",
  "pipeline_stage": 5
}
```

---

## Optiv Vendor Row Schema (for 753-row dataset)

This schema normalizes the raw Optiv market map vendor rows for joining against the control and technique tables.

```json
{
  "row_id": "optiv_0042",
  "vendor_raw": "CrowdStrike",
  "vendor_normalized": "crowdstrike",
  "market_family": "SecOps",
  "market_subfamily": "EDR",
  "pipeline_stage_primary": 4,
  "pipeline_stage_secondary": [3, 5, 7, 8],
  "coordinate_ref": "x:412,y:280",
  "coordinate_confidence": "high",
  "nist_controls_inferred": ["SI-3", "SI-4", "CM-7", "AU-2", "IR-4"],
  "attck_techniques_covered": ["T1059", "T1055", "T1078", "T1021", "T1071"],
  "coverage_confidence": "high",
  "notes": "Coordinate verified against market map; vendor confirmed in EDR family"
}
```

---

## Gap Scoring Logic

### Coverage Score by Tactic

```python
def coverage_score_by_tactic(vendor_stack: list[str], attck_matrix: dict) -> dict:
    """
    vendor_stack: list of vendor_normalized IDs in your environment
    attck_matrix: full ATT&CK technique list keyed by tactic
    returns: dict of tactic -> (covered_count, total_count, coverage_pct, gap_techniques)
    """
    covered = set()
    for vendor in vendor_stack:
        vendor_techniques = get_vendor_techniques(vendor)  # via control chain
        covered.update(vendor_techniques)
    
    scores = {}
    for tactic, techniques in attck_matrix.items():
        technique_ids = {t["technique_id"] for t in techniques}
        covered_in_tactic = technique_ids & covered
        gap = technique_ids - covered
        scores[tactic] = {
            "covered": len(covered_in_tactic),
            "total": len(technique_ids),
            "coverage_pct": round(len(covered_in_tactic) / len(technique_ids) * 100, 1),
            "gap_techniques": sorted(gap)
        }
    return scores
```

### Gap Priority Scoring

```python
def score_gap_priority(technique_id: str, kev_list: set, epss_scores: dict) -> dict:
    """
    Prioritize uncovered techniques by real-world exploitation activity.
    kev_list: set of CVE IDs from CISA KEV that map to this technique
    epss_scores: dict of CVE -> EPSS probability
    """
    kev_cves = get_technique_cves(technique_id) & kev_list
    max_epss = max([epss_scores.get(cve, 0) for cve in kev_cves], default=0)
    
    return {
        "technique_id": technique_id,
        "actively_exploited": len(kev_cves) > 0,
        "kev_cve_count": len(kev_cves),
        "max_epss": max_epss,
        "priority": "critical" if kev_cves else "high" if max_epss > 0.1 else "medium"
    }
```

### Redundancy Scoring

```python
def vendor_redundancy(vendor_stack: list[str]) -> dict:
    """
    Identify techniques covered by more than one vendor in the stack.
    Returns redundancy map and single-vendor dependencies.
    """
    technique_vendor_map = defaultdict(list)
    for vendor in vendor_stack:
        for technique in get_vendor_techniques(vendor):
            technique_vendor_map[technique].append(vendor)
    
    redundant = {t: vs for t, vs in technique_vendor_map.items() if len(vs) > 1}
    single_coverage = {t: vs[0] for t, vs in technique_vendor_map.items() if len(vs) == 1}
    
    return {
        "redundant_techniques": redundant,
        "single_vendor_dependencies": single_coverage,
        "redundancy_ratio": len(redundant) / max(len(technique_vendor_map), 1)
    }
```

---

## Recommended File Structure for Data

```
/data/
  vendors.jsonl                    # Normalized vendor records (1 per line)
  optiv_vendor_rows.jsonl          # 753 raw Optiv rows with normalization
  nist800-53_to_attck.json         # CTID NIST 800-53 → ATT&CK mappings (download from CTID)
  aws_to_attck.json                # CTID AWS → ATT&CK
  azure_to_attck.json              # CTID Azure → ATT&CK
  gcp_to_attck.json                # CTID GCP → ATT&CK
  m365_to_attck.json               # CTID M365 → ATT&CK
  csa_ccm_to_attck.json            # CTID CSA CCM → ATT&CK
  kev_to_attck.json                # CTID KEV → ATT&CK

/edges/
  vendor_to_control.jsonl          # vendor_id → nist_control_id edges
  control_to_technique.jsonl       # nist_control_id → technique_id (from CTID)
  vendor_to_technique.jsonl        # derived: vendor_id → technique_id

/scores/
  coverage_by_tactic.json          # ATT&CK tactic coverage scores
  coverage_by_stage.json           # Pipeline stage coverage scores
  gap_list.json                    # Uncovered techniques with priority scores
  redundancy_map.json              # Techniques with multi-vendor coverage
```

---

## Connecting to ATTACK-Navi

ATTACK-Navi supports custom heatmap layers that can visualize coverage scores directly on the ATT&CK matrix. The output of the gap scoring pipeline can be loaded as a Navigator layer:

```json
{
  "name": "Vendor Stack Coverage",
  "versions": { "attack": "16.1", "navigator": "5.0.0", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1059",
      "score": 1,
      "color": "#4CAF50",
      "comment": "Covered by: CrowdStrike, SentinelOne (via SI-4)"
    },
    {
      "techniqueID": "T1190",
      "score": 0,
      "color": "#F44336",
      "comment": "GAP: No vendor in stack maps to SA-11/RA-5 for this technique"
    }
  ]
}
```

Load this JSON into ATTACK-Navi to see your coverage gaps visualized as a heatmap across the full ATT&CK matrix.

---

## CTID Data Downloads

Download the raw mapping data directly from CTID to build the control_to_technique edge table:

| Framework | CTID Explorer URL | Coverage |
|---|---|---|
| NIST 800-53 v5 | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/) | All 800-53 controls → Enterprise ATT&CK |
| AWS Security Controls | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/aws/) | AWS native controls → ATT&CK |
| Azure Security Controls | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/azure/) | Azure/Entra controls → ATT&CK |
| GCP Security Controls | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/gcp/) | GCP controls → ATT&CK |
| Microsoft 365 | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/m365/) | M365 controls → ATT&CK |
| CSA CCM | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/csa/) | Cloud security controls → ATT&CK |
| CISA KEV | [View](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/) | Known exploited CVEs → ATT&CK techniques |


### Coverage Gap Analysis Methodology

**Step 1: Asset Inventory**
Before measuring coverage, establish what you're protecting:
```json
{
  "asset_types": ["workstation", "server", "cloud_vm", "saas_app", "network_device"],
  "data_classifications": ["public", "internal", "confidential", "restricted"],
  "business_criticality": ["critical", "high", "medium", "low"]
}
```

**Step 2: Control Mapping**
Map each deployed control to NIST 800-53 families and ATT&CK techniques it addresses:
```python
# Example control mapping entry
control = {
    "vendor": "CrowdStrike Falcon",
    "deployment_coverage": 0.94,  # 94% of endpoints have agent
    "nist_controls": ["SI-3", "SI-7", "AU-12", "IR-4"],
    "attack_techniques": ["T1059.001", "T1055", "T1003", "T1548"],
    "gap_notes": "6% coverage gap — Linux servers in DMZ zone"
}
```

**Step 3: Gap Scoring**
```python
def calculate_technique_coverage(technique_id: str, controls: list[dict]) -> float:
    """
    Returns 0.0 (no coverage) to 1.0 (fully covered)
    """
    covering_controls = [c for c in controls if technique_id in c.get("attack_techniques", [])]
    if not covering_controls:
        return 0.0
    # Weight by deployment coverage
    avg_deployment = sum(c["deployment_coverage"] for c in covering_controls) / len(covering_controls)
    # Bonus for multiple independent controls (defense in depth)
    depth_multiplier = min(1.0, 0.7 + (len(covering_controls) * 0.1))
    return min(1.0, avg_deployment * depth_multiplier)
```

**Step 4: ATT&CK Navigator Layer Generation**
```python
import json

def generate_navigator_layer(technique_scores: dict[str, float]) -> dict:
    """Generate ATT&CK Navigator layer from technique coverage scores."""
    techniques = []
    for technique_id, score in technique_scores.items():
        # Color: red (0) → yellow (0.5) → green (1.0)
        color = score_to_color(score)
        techniques.append({
            "techniqueID": technique_id,
            "score": round(score * 100),
            "color": color,
            "comment": f"Coverage score: {score:.0%}",
            "enabled": True
        })

    return {
        "name": "Coverage Heatmap",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Control coverage mapped to ATT&CK techniques",
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100
        },
        "techniques": techniques
    }

def score_to_color(score: float) -> str:
    if score < 0.25: return "#ff6666"   # Red
    if score < 0.5:  return "#ffa500"   # Orange
    if score < 0.75: return "#ffe766"   # Yellow
    return "#8ec843"                     # Green
```

### Gap Priority Matrix

| Technique Coverage | Business Impact | Priority | Action |
|---|---|---|---|
| 0% | Critical | P1 | Immediate — acquire or deploy control within 30 days |
| 0% | High | P2 | Near-term — deploy within 90 days |
| 0-25% | Critical | P1 | Immediate — expand deployment coverage |
| 25-50% | High | P2 | Near-term — expand deployment and add compensating control |
| 50-75% | Medium | P3 | Planned — include in next budget cycle |
| 75-100% | Any | P4 | Monitoring — optimize existing controls |

### ROSI Calculation Model

**Return on Security Investment**

```python
def calculate_rosi(
    asset_value: float,          # Total value of assets at risk ($)
    threat_frequency: float,     # Estimated annual events (ARO)
    exposure_factor: float,      # % of asset value lost per event (0-1)
    control_effectiveness: float, # % risk reduction from control (0-1)
    control_cost: float          # Annual cost of control ($)
) -> dict:
    """
    ROSI = (Risk Reduced * Control Effectiveness) - Control Cost
    """
    ale_before = asset_value * threat_frequency * exposure_factor  # Annual Loss Expectancy
    ale_after = ale_before * (1 - control_effectiveness)
    risk_reduced = ale_before - ale_after
    rosi = risk_reduced - control_cost
    rosi_percent = (rosi / control_cost) * 100 if control_cost > 0 else 0

    return {
        "ale_before": ale_before,
        "ale_after": ale_after,
        "annual_risk_reduction": risk_reduced,
        "control_cost": control_cost,
        "net_rosi": rosi,
        "rosi_percentage": rosi_percent,
        "recommendation": "Deploy" if rosi > 0 else "Do not deploy based on ROSI alone"
    }

# Example: EDR deployment
result = calculate_rosi(
    asset_value=50_000_000,    # $50M in sensitive systems
    threat_frequency=0.3,      # 0.3 ransomware events per year (industry average)
    exposure_factor=0.2,       # 20% average loss per event
    control_effectiveness=0.85, # EDR reduces ransomware success by 85%
    control_cost=200_000       # $200K/year EDR license
)
# Result: $2.55M risk reduction, $2.35M ROSI, 1175% ROI
```

---
