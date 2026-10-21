<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Threat-informed defense and ATT&CK

> Using MITRE ATT&CK and the related MITRE frameworks to decide what to defend, detect, and test first.

Part of the [domain hubs](/hubs/README.md). 16 reference documents in this domain; reading time is the page's words at 230 words a minute.

## ATT&CK and threat-informed defense

| Reference | What it covers | Reading time |
|---|---|---|
| [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md) | ATT&CK-centric knowledge graph (CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND), open-source data-source stack, and per-technique coverage-stack model | 7 min |
| [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md) | All 714 ATT&CK techniques by tactic (697 active per MITRE v19.2; a few superseded records retained), cross-referenced to threat groups, software, mitigations, NIST controls, and detection | 51 min |
| [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md) | 24 analytic lenses for reading an ATT&CK matrix: mitigation, threat activity, exposure, detection, compliance, and composite risk | 5 min |
| [ATT&CK Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md) | 106 telemetry categories mapped to the techniques they detect, with concrete log sources and channels | 134 min |
| [ATT&CK Software Reference](/ATTACK_SOFTWARE_REFERENCE.md) | 825 MITRE ATT&CK malware families and tools with the techniques they implement and the groups that use them | 46 min |
| [ATT&CK Campaigns Reference](/ATTACK_CAMPAIGNS_REFERENCE.md) | 56 MITRE ATT&CK intrusion campaigns with active windows, techniques, software, and group attribution | 29 min |
| [ATT&CK Mitigations Reference](/ATTACK_MITIGATIONS_REFERENCE.md) | All 44 ATT&CK Enterprise mitigations (M-codes) and the techniques each one addresses | 22 min |
| [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md) | MITRE ATT&CK for Mobile techniques and sub-techniques by tactic (page snapshot: ATT&CK v18.1), cross-referenced to groups, software, and mitigations | 7 min |

## Related MITRE frameworks

| Reference | What it covers | Reading time |
|---|---|---|
| [D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md) | 156 MITRE D3FEND defensive techniques (7 tactics) mapped to the 426 ATT&CK techniques they counter | 14 min |
| [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md) | 615 common attack patterns, 177 bridging to ATT&CK techniques, linked to their CWE weaknesses | 17 min |
| [CWE Weakness Reference](/CWE_REFERENCE.md) | Software and hardware weakness types, organized by pillar and class, with consequences, mitigations, and a most-attacked ranking | 14 min |
| [Engage Reference (deception)](/ENGAGE_REFERENCE.md) | MITRE Engage: denial, deception and adversary engagement: 5 goals, 9 approaches, 31 activities, with 175 mappings to ATT&CK techniques | 9 min |
| [Fight Fraud Framework (MITRE F3)](/FRAUD_FRAMEWORK_REFERENCE.md) | 123 cyber-enabled financial fraud techniques across 8 tactics (reconnaissance through monetization) from MITRE's Center for Threat-Informed Defense | 33 min |

## Mapping and measuring coverage

| Reference | What it covers | Reading time |
|---|---|---|
| [Enterprise Security Pipeline](/SECURITY_PIPELINE.md) | End-to-end security lifecycle with vendor mapping across all 6 stages | 6 min |
| [Controls Mapping](/CONTROLS_MAPPING.md) | The cross-reference chain from security vendors to the NIST 800-53 controls they implement and on to the ATT&CK techniques those controls mitigate | 8 min |
| [Coverage Schema](/COVERAGE_SCHEMA.md) | Data model for scoring vendor coverage gaps against ATT&CK techniques through NIST 800-53 controls | 2 min |

## Learning paths

- [Detection Engineering](/disciplines/detection-engineering.md)
- [Purple Teaming & Adversary Simulation](/disciplines/purple-teaming.md)
- [Threat Intelligence](/disciplines/threat-intelligence.md)

## How-to guides

Time and difficulty are quoted in full from each guide's header table.

| Guide | Time | Difficulty |
|---|---|---|
| [Run an ATT&CK Coverage Gap Assessment](/guides/RUN_A_COVERAGE_GAP_ASSESSMENT.md) | 2-4 hours (first run) | Intermediate |
| [Run Your First Purple-Team Exercise](/guides/RUN_A_PURPLE_TEAM_EXERCISE.md) | Half a day to plan, 2-3 hours to run | Intermediate |
| [How to Use This Library](/guides/HOW_TO_USE_THIS_LIBRARY.md) | 30-45 min | Beginner |

## See also

- [Explore: framework objects in one table](/explore.md)
- [ATT&CK priority gaps](/scores/attack_priority_gaps.md)
- [Navigator layers](/navigator/)
- [Cross-framework crosswalk](/mitre/crosswalk.md)

<!-- hub:end -->
