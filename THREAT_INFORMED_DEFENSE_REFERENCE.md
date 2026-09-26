# Threat-Informed Defense Reference

> **What this is.** A field guide to running defense with MITRE ATT&CK at the center — connecting the
> knowledge systems that answer *what behavior is happening*, *what weakness enables it*, *what products
> are affected*, and *what we should do about it*. It is the conceptual backbone behind this repository's
> [ATT&CK Navigator layers](navigator/), [control/technique edge tables](data/), and the
> [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) workbench.

| | |
|---|---|
| **Read this when** | turning a long CVE list into root-cause weakness groupings, deciding which detection or mitigation to build next for a technique, wiring ATT&CK to CWE/CAPEC/D3FEND/NIST controls |
| **Start at** | [The ATT&CK-centric knowledge graph](#_1-the-attampck-centric-knowledge-graph), [The canonical chain](#the-canonical-chain), [Getting started](#_6-getting-started-recommended-order) |
| **Pairs with** | [ATT&CK Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md), [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), [Controls Mapping](CONTROLS_MAPPING.md), [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) |

Threat-informed defense is the discipline of prioritizing security work by what adversaries actually do,
using a shared model of adversary behavior (ATT&CK) as the organizing spine and enriching it with the
other public knowledge bases that describe vulnerabilities, weaknesses, affected products, and defensive
countermeasures. The goal is a clean chain of reasoning from an observed or anticipated behavior all the
way to a concrete defensive action.

---

## 1. The ATT&CK-centric knowledge graph

Keep ATT&CK as the base graph and normalize every other source into one of six node roles. This avoids
treating each knowledge base as a disconnected panel and instead builds a single graph you can traverse.

| Role | System | What it answers | In this library |
|---|---|---|---|
| **behavior** | **MITRE ATT&CK** | What is the adversary *doing*? (tactics, techniques, groups, software, campaigns) | [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) · [Detail Pages](techniques/README.md) · [Groups](THREAT_GROUP_PROFILES.md) |
| **attack_pattern** | **CAPEC** | Through what *pattern* is a weakness exploited? | [CAPEC Attack Pattern Reference](CAPEC_REFERENCE.md) |
| **weakness** | **CWE** | What *class of flaw* makes it possible? | [CWE Weakness Reference](CWE_REFERENCE.md) |
| **exposure** | **CVE** | Which *specific vulnerabilities* exist? | [CVE Reference](CVE_REFERENCE.md) |
| **product** | **CPE** | Which *products/versions* are affected? | [NVD CPE](https://nvd.nist.gov/products/cpe/search) |
| **defense** | **MITRE D3FEND** | What *countermeasure* opposes the behavior? | [D3FEND Countermeasure Reference](D3FEND_REFERENCE.md) |

Add a small set of relationship types between these nodes, and the graph becomes traversable in any
direction:

`enables` · `affects` · `caused_by` · `maps_to` · `countered_by` · `observed_in`

### The canonical chain

```
CPE  ── affects ──►  CVE  ── caused_by ──►  CWE  ── maps_to ──►  CAPEC  ── maps_to ──►  ATT&CK  ── countered_by ──►  D3FEND
(product)          (exposure)           (weakness)          (attack pattern)         (behavior)                 (defense)
                                                                                        │
                                                                          maps_to (via CTID)
                                                                                        ▼
                                                                       NIST 800-53 / CIS / cloud controls
```

Reading it in both directions is the point:

- **Forward (exposure → action):** a product you run (CPE) has a vulnerability (CVE), caused by a weakness
  class (CWE), exploited through an attack pattern (CAPEC), realized as an ATT&CK technique, which is
  opposed by specific D3FEND countermeasures and framework controls.
- **Backward (behavior → root cause):** an ATT&CK technique you observed maps back to the attack patterns,
  weakness classes, and concrete vulnerabilities that make it possible in your environment — turning a long
  CVE list into a handful of root-cause weakness groupings.

### The most important individual mappings

| Mapping | Meaning | Why it matters |
|---|---|---|
| **CVE → CWE** | This vulnerability is an instance of this weakness type | Collapses a long CVE list into root-cause groupings for remediation strategy |
| **CVE → CPE** | This vulnerability affects these products/versions | Tells you whether a vulnerability is *relevant to your environment* |
| **CWE → CAPEC** | This weakness is exploited through these attack patterns | Bridges implementation flaws to attacker tradecraft |
| **CAPEC → ATT&CK** | This attack pattern aligns with these techniques | Bridges abstract patterns to operational adversary behavior |
| **ATT&CK → D3FEND** | These defensive techniques counter this behavior | Turns ATT&CK into an actionable defensive plan |
| **ATT&CK ↔ NIST 800-53** | These controls mitigate this technique (via CTID) | Connects behavior to your compliance/control framework — see [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) |

---

## 2. The threat-informed data-source stack

A mature program layers several open knowledge bases and detection sources on top of ATT&CK. Organize
them by the **coverage type** they provide — *mitigation, detection, validation, intel,* or *exposure* —
so every technique can carry a consistent "coverage stack."

### Behavior & attribution

| Source | Role | Where to get it |
|---|---|---|
| **MITRE ATT&CK** | The behavior spine — techniques, groups, software, campaigns | [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) |
| **MITRE ATT&CK Groups & Software** | Which adversaries/tools use a technique (exposure & frequency) | Bundled in ATT&CK STIX |
| **VERIS** | Incident action taxonomy for breach-pattern context | [veriscommunity.net](https://veriscommunity.net/) |

### Exposure & prioritization (what to fix first)

| Source | Role | Where to get it |
|---|---|---|
| **CVE / NVD** | Specific vulnerabilities + severity/metadata | [nvd.nist.gov](https://nvd.nist.gov/) · [CVE List V5](https://github.com/CVEProject/cvelistV5) |
| **CISA KEV** | Known-exploited vulnerabilities — *urgency, not just relevance* | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| **EPSS** | Probability a CVE will be exploited in the wild (0–1) | [first.org/epss](https://www.first.org/epss/) |
| **CWE / CAPEC** | Root-cause weakness families and their exploit patterns | [cwe.mitre.org](https://cwe.mitre.org/) · [capec.mitre.org](https://capec.mitre.org/) |

> KEV should be treated as a *priority multiplier* on technique risk, not just another badge. A technique
> with KEV-backed exposure and thin control coverage is a top-of-queue gap.

### Detection coverage (can we see it?)

| Source | Role | Where to get it |
|---|---|---|
| **Sigma** | Portable detection rules mapped to ATT&CK — "do we have detection logic for this technique?" | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| **Elastic Detection Rules** | Maintained EQL/KQL detections | [elastic/detection-rules](https://github.com/elastic/detection-rules) |
| **Splunk Security Content (ESCU)** | Maintained Splunk detections + analytic stories | [splunk/security_content](https://github.com/splunk/security_content) |
| **MITRE CAR** | Cyber Analytics Repository — vendor-neutral analytics with data-model context | [car.mitre.org](https://car.mitre.org/) |
| **Zeek** | Network telemetry for data-source-backed detection | [zeek.org](https://zeek.org/) |
| **Suricata** | IDS/NSM signatures complementing Sigma at the network layer | [suricata.io](https://suricata.io/) |
| **YARA / YARA-X** | File- and payload-oriented detection | [VirusTotal/yara](https://github.com/VirusTotal/yara) |
| **Security Onion** | A bundled open detection stack (Zeek + Suricata + Elastic) | [securityonion.net](https://securityonion.net/) |

See this repo's [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) for ready-to-adapt,
multi-platform analytics keyed to ATT&CK techniques.

### Validation (does our detection actually fire?)

| Source | Role | Where to get it |
|---|---|---|
| **Atomic Red Team** | Small, portable tests per technique — "can we exercise this in our environment?" | [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| **CALDERA** | Automated adversary emulation | [mitre/caldera](https://github.com/mitre/caldera) |
| **Adversary Emulation Library** | Full CTID emulation plans for named actors | [CTID library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) |

### Live threat intel (why does this matter right now?)

| Source | Role | Where to get it |
|---|---|---|
| **MISP** | Event-driven CTI with ATT&CK tagging, IOCs, correlation | [misp-project.org](https://www.misp-project.org/) |
| **OpenCTI** | Graph-native CTI with STIX relationships, provenance, confidence | [opencti.io](https://www.opencti.io/) |

> MISP and OpenCTI overlap. Choose **MISP** for event-driven operational CTI; choose **OpenCTI** for
> richer actor/malware/campaign relationship graphing.

### Defensive action & controls (what do we do next?)

| Source | Role | Where to get it |
|---|---|---|
| **MITRE D3FEND** | Countermeasure techniques per ATT&CK behavior | [d3fend.mitre.org](https://d3fend.mitre.org/) |
| **MITRE Engage** | Denial, deception, and adversary-engagement activities | [engage.mitre.org](https://engage.mitre.org/) |
| **NIST 800-53 R5** | Control framework, mapped to ATT&CK via CTID | [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/) |
| **CIS Controls / Safeguards** | Prioritized control set with ATT&CK mappings | [CIS Controls](https://www.cisecurity.org/controls) |
| **Cloud controls (AWS/Azure/GCP/M365/CSA CCM)** | Cloud-native control → ATT&CK mappings | [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) |

---

## 3. Coverage types — the per-technique "coverage stack"

For any technique, ask five questions. Together they form its coverage stack:

| Coverage type | Question | Backed by |
|---|---|---|
| **mitigation** | Do controls reduce the technique's viability? | NIST 800-53, CIS, ATT&CK mitigations, D3FEND |
| **detection** | Would we see it if it happened? | Sigma, Elastic, Splunk, CAR, Zeek, Suricata, YARA |
| **validation** | Have we *proven* detection works? | Atomic Red Team, CALDERA, purple-team exercises |
| **intel** | Is it seen in intel relevant to us? | MISP, OpenCTI, ATT&CK groups/campaigns |
| **exposure** | How exploitable/urgent is it in our stack? | CVE, CPE, KEV, EPSS |

A technique that is mitigated *and* detected *and* validated *and* intel-relevant *and* low-exposure is
well-covered. Any missing layer is a prioritized gap.

---

## 4. Operationalizing it in this repository

This library implements the control-to-behavior half of the graph as machine-readable data you can query
and visualize:

| Artifact | What it gives you |
|---|---|
| [`data/control_to_technique.jsonl`](data/control_to_technique.jsonl) | NIST 800-53 R5 → ATT&CK technique edges (authoritative, CTID-sourced) |
| [`data/vendor_to_control.jsonl`](data/vendor_to_control.jsonl) | Which NIST controls each security vendor satisfies |
| [`data/vendor_to_technique.jsonl`](data/vendor_to_technique.jsonl) | Derived vendor → ATT&CK coverage via the control join |
| [`navigator/teamstarwolf_vendor_coverage.json`](navigator/teamstarwolf_vendor_coverage.json) | Master ATT&CK Navigator heatmap: technique control-depth |
| [`CONTROLS_MAPPING.md`](CONTROLS_MAPPING.md) | Human-readable vendor → NIST → ATT&CK cross-reference |
| [`COVERAGE_SCHEMA.md`](COVERAGE_SCHEMA.md) | Data model + gap-scoring functions |
| [`scores/coverage_gaps.md`](scores/coverage_gaps.md) | Where the modeled stack leaves ATT&CK gaps |

### Building a coverage gap score

The gap-scoring recipe (see [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md) for the data model):

1. Take the NIST 800-53 R5 → ATT&CK mapping from CTID (`control_to_technique`).
2. For each vendor in your stack, list the NIST controls it satisfies (`vendor_to_control`).
3. Join `vendor_controls ∩ control_to_technique` → techniques each vendor covers.
4. Union across your stack → total covered techniques.
5. Complement against the full ATT&CK matrix → **gap list**.
6. Rank gaps by tactic, technique criticality (KEV/EPSS), and pipeline stage.

### Visualizing it

Load any layer in the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), or use
the [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) workbench, which adds coverage, detection,
exposure, compliance, and risk heatmaps over these mappings. See the
[ATT&CK Matrix Analysis Reference](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) for the full set of analytic lenses.

---

## 5. Worked example — T1059.001 (PowerShell)

Following one technique across the whole graph:

| Layer | For T1059.001 PowerShell |
|---|---|
| **behavior** | Execution via the PowerShell interpreter (ATT&CK T1059.001) |
| **attack_pattern → weakness** | Command/script execution abuse; related weaknesses include improper neutralization of commands (CWE-77/CWE-78 families) when reached via an app |
| **exposure** | Any CVE that yields code execution feeding a PowerShell cradle; prioritize by KEV/EPSS |
| **detection** | Encoded-command and script-block analytics — see the [Detection Library entry](detections/TECHNIQUE_DETECTION_LIBRARY.md#t1059001) for Splunk/Elastic/KQL/Chronicle/CrowdStrike queries |
| **validation** | [Atomic Red Team T1059.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.001) tests |
| **mitigation (controls)** | NIST 800-53 controls mapped to T1059.001 (CM-7 least functionality, SI-3/SI-4, AC-6) — see [`control_to_technique.jsonl`](data/control_to_technique.jsonl) |
| **defense (D3FEND)** | Script execution analysis, process spawn analysis countermeasures |

The same traversal works for any technique and is exactly what the coverage layers and detection library
in this repo are built to support.

---

## 6. Getting started (recommended order)

1. **Anchor on ATT&CK.** Load the [master coverage layer](navigator/) and skim your top-frequency techniques.
2. **Add exposure urgency.** Overlay KEV/EPSS to separate "covered in theory" from "under active pressure."
3. **Check detection.** Map Sigma/CAR/vendor detections to your top techniques (start with the
   [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md)).
4. **Validate.** Run the matching Atomic Red Team tests and confirm alerts fire.
5. **Add intel context.** Wire in MISP or OpenCTI so technique priority reflects what you're actually seeing.
6. **Plan defense.** Use D3FEND + your control framework to choose the next mitigation for each open gap.

---

## Related references

- [ATT&CK Matrix Analysis Reference](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) — 24 analytic lenses for reading an ATT&CK matrix
- [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) — multi-platform detections per technique
- [Controls Mapping](CONTROLS_MAPPING.md) · [Coverage Schema](COVERAGE_SCHEMA.md) · [Coverage gaps](scores/coverage_gaps.md)
- [Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [Purple Team](PURPLE_TEAM_REFERENCE.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md)
- [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Threat Modeling](THREAT_MODELING_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md)
- [ATTACK-Navi workbench](https://github.com/TeamStarWolf/ATTACK-Navi) — the interactive implementation of this model

*All systems referenced here are public, authoritative knowledge bases (MITRE, NIST, CISA, FIRST, CTID) or
open-source projects. Mappings between NIST 800-53 and ATT&CK are sourced from the
[CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/).*
