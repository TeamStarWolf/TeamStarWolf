# MITRE Frameworks — Enriched Knowledge Base

ATT&CK-Navigator-style browsable pages: **one page per MITRE object**, cross-linked across frameworks (ATT&CK, Mitigation, D3FEND, CAPEC, NIST 800-53) and enriched with detection analytics, data sources, named adversary usage, and Team Star Wolf corpus telemetry. ATT&CK v19.2.

## Browse by object

| Section | Pages | What each page carries |
|---|---|---|
| [Techniques](/mitre/techniques/README.md) | 714 | tactics, platforms, mitigations, **linked D3FEND**, **detection analytics + log sources**, **data sources**, **CAR analytics**, **MITRE Engage**, **named threat-group & tool usage**, sub-techniques, NIST 800-53 (named), CAPEC, corpus prevalence |
| [Mitigations](/mitre/mitigations/README.md) | 44 | how-to-implement, NIST mapping, techniques countered, corpus relevance |
| [Tactics](/mitre/tactics/README.md) | 16 | the "why" of each stage, its techniques, top corpus-observed techniques |
| [D3FEND](/mitre/d3fend/README.md) | 156 | defensive technique, D3FEND tactic, digital artifacts, ATT&CK techniques countered |
| [CAPEC](/mitre/capec/README.md) | 615 | abstraction, severity, likelihood, mapped ATT&CK, related CWE, prerequisites, mitigations |
| [ATLAS (AI/ML)](/mitre/atlas/README.md) | 205 | adversarial-AI techniques + mitigations |
| [F3 (Fight Fraud)](/mitre/f3/README.md) | 123 | CTID fraud-lifecycle techniques; ATT&CK-derived ones cross-link to their technique pages |
| [Threat Groups](/mitre/groups/README.md) | 176 | ATT&CK adversary groups (intrusion sets) — aliases, techniques used (linked), and software wielded |
| [Software & Tools](/mitre/software/README.md) | 825 | ATT&CK malware & tools — type, platforms, aliases, techniques implemented (linked), and the groups that wield them |
| [Campaigns](/mitre/campaigns/README.md) | 56 | ATT&CK intrusion campaigns — active window, attributed groups, techniques used (linked), and software deployed |
| [Cross-Framework Crosswalk](/mitre/crosswalk.md) | — | technique, mitigation, NIST, D3FEND, CAPEC in one table |

## Start here

- **Investigating a technique?** open its Technique page — mitigations, detection analytics (with the exact log sources), and which groups/tools use it are all on one page.
- **Building a control set?** open a Mitigation page for how-to-implement + NIST mapping, or the Crosswalk for the full join.
- **Engineering detections?** the Detection + Data-sources sections on each technique name the analytics and telemetry to collect.
- **Prioritising?** ⭐ marks the 21 techniques observed in the Team Star Wolf 529-machine training corpus — real-world lower-bound prevalence.

**Coverage:** every ATT&CK object cross-links to its related mitigations, D3FEND countermeasures, CAPEC patterns, and NIST 800-53 controls — the cross-framework relationships in one browsable place.

---

*Source: MITRE ATT&CK® (v19.2) — ATT&CK®, D3FEND™, and CAPEC™ are trademarks of The MITRE Corporation. This is an independent reference summary enriched with Team Star Wolf corpus telemetry; consult the upstream projects for authoritative content. Corpus figures are keyword-derived from a 529-machine training walkthrough corpus (lower-bound evidence), not an official MITRE mapping.*
