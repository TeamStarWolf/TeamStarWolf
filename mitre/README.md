# Framework Knowledge Base: ATT&CK, D3FEND, CAPEC, ATLAS and F3

Start from a technique, a mitigation, a threat group or a tool and follow it across the frameworks defenders use: what the behaviour is, who uses it, how to mitigate and detect it, and which NIST 800-53 controls apply. There is one page per framework object, cross-linked across MITRE ATT&CK® v20.0, its mitigations, D3FEND™, CAPEC™ and NIST 800-53, and enriched with detection analytics, data sources, named adversary usage, and TeamStarWolf corpus telemetry.

## Browse by object

| Section | Pages | What each page carries |
|---|---|---|
| [Techniques](/mitre/techniques/README.md) | 723 | tactics, platforms, mitigations, linked D3FEND, detection analytics + log sources, data sources, CAR analytics, MITRE Engage, named threat-group & tool usage, sub-techniques, NIST 800-53 (named), CAPEC, corpus prevalence |
| [Mitigations](/mitre/mitigations/README.md) | 44 | how-to-implement, NIST mapping, techniques countered, corpus relevance |
| [Tactics](/mitre/tactics/README.md) | 15 | the "why" of each stage, its techniques, top corpus-observed techniques |
| [D3FEND](/mitre/d3fend/README.md) | 156 | defensive technique, D3FEND tactic, digital artifacts, ATT&CK techniques countered |
| [CAPEC](/mitre/capec/README.md) | 615 | abstraction, severity, likelihood, mapped ATT&CK, related CWE, prerequisites, mitigations |
| [ATLAS (AI/ML)](/mitre/atlas/README.md) | 205 | adversarial-AI techniques + mitigations |
| [F3 (Fight Fraud)](/mitre/f3/README.md) | 123 | CTID fraud-lifecycle techniques; ATT&CK-derived ones cross-link to their technique pages |
| [Threat Groups](/mitre/groups/README.md) | 178 | ATT&CK adversary groups (intrusion sets): aliases, techniques used (linked), and software wielded |
| [Software & Tools](/mitre/software/README.md) | 842 | ATT&CK malware & tools: type, platforms, aliases, techniques implemented (linked), and the groups that wield them |
| [Campaigns](/mitre/campaigns/README.md) | 57 | ATT&CK intrusion campaigns: active window, attributed groups, techniques used (linked), and software deployed |
| [Cross-Framework Crosswalk](/mitre/crosswalk.md) | N/A | technique, mitigation, NIST, D3FEND, CAPEC in one table |

## Start here

- Investigating a technique? Open its Technique page. Mitigations, detection analytics (with the exact log sources), and the groups and tools that use it are all on one page.
- Building a control set? Open a Mitigation page for implementation guidance and the NIST mapping, or the Crosswalk for the full join.
- Engineering detections? The Detection and Data sources sections on each technique name the analytics and telemetry to collect.
- Prioritising? Techniques marked (observed) are the 21 seen in the TeamStarWolf 529-machine training corpus, a real-world lower bound on prevalence.

Coverage: every ATT&CK object cross-links to its related mitigations, D3FEND countermeasures, CAPEC patterns, and NIST 800-53 controls, so the cross-framework relationships can be browsed in one place.

---

*Source: MITRE ATT&CK® (v20.0). ATT&CK®, D3FEND™, and CAPEC™ are trademarks of The MITRE Corporation. This is an independent reference summary enriched with TeamStarWolf corpus telemetry; consult the upstream projects for authoritative content. Corpus figures are keyword-derived from a 529-machine training walkthrough corpus (lower-bound evidence), not an official MITRE mapping.*
